"""
MODULE 1 - LOG INGESTION
------------------------
Reads an uploaded CSV / TXT / JSON file (as bytes, never executed, never saved)
and returns a raw pandas DataFrame whose columns have been auto-detected and
renamed to our standard names:

    timestamp, source_ip, user, event, action, destination, status, bytes
"""
import io
import json
import re

import pandas as pd

ALLOWED_EXTENSIONS = {"csv", "txt", "json"}
MAX_ROWS = 5000  # safety limit so a huge file cannot freeze the app

# standard name -> possible column names (compared after removing symbols, lower-case)
FIELD_ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "date", "eventtime", "ts", "logtime"],
    "source_ip": ["sourceip", "srcip", "src", "ip", "ipaddress", "clientip", "remoteip", "source"],
    "user": ["user", "username", "account", "userid", "accountname", "uid"],
    "event": ["event", "eventtype", "type", "message", "msg", "description", "activity", "category"],
    "action": ["action", "operation", "method", "request", "resource", "path", "file", "object"],
    "destination": ["destination", "dst", "dstip", "destinationip", "dest", "destip", "target", "host", "server"],
    "status": ["status", "result", "outcome", "statuscode", "state"],
    "bytes": ["bytes", "bytessent", "bytesout", "size", "datasize", "length", "transferbytes"],
}


def _clean_name(name):
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def detect_columns(df):
    """Rename whatever column names the file uses to our standard names."""
    cleaned = {col: _clean_name(col) for col in df.columns}
    rename, used = {}, set()
    for standard, aliases in FIELD_ALIASES.items():
        for alias in aliases:  # earlier alias = higher priority
            hit = next((c for c, cl in cleaned.items() if cl == alias and c not in used), None)
            if hit is not None:
                rename[hit] = standard
                used.add(hit)
                break
    df = df.rename(columns=rename)
    for standard in FIELD_ALIASES:  # make sure every standard column exists
        if standard not in df.columns:
            df[standard] = ""
    return df[list(FIELD_ALIASES)], rename


# ---------------------------------------------------------------- TXT parsing
_DASHED = re.compile(
    r"^\s*(?P<timestamp>\d[\d\-/:T\. ]*?)\s+-\s+(?P<event>.+?)\s+-\s+IP\s+(?P<source_ip>\S+)"
    r"(?:\s+-\s+user\s+(?P<user>\S+))?", re.I)
_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?|\b\d{1,2}:\d{2}(?::\d{2})?\b")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER = re.compile(r"(?:user|usr|account)[=: ]+([\w.\-@]+)", re.I)


def _parse_txt(text):
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pairs = _KV.findall(line)
        if len(pairs) >= 2:  # key=value style
            records.append({k: v.strip('"') for k, v in pairs})
            continue
        m = _DASHED.match(line)  # "09:41 - Failed login - IP 10.0.0.5 - user admin"
        if m:
            records.append({k: (v or "") for k, v in m.groupdict().items()})
            continue
        # last resort: pull out whatever we can recognise
        t, ip, u = _TIME.search(line), _IP.search(line), _USER.search(line)
        rest = line
        for found in (t, ip, u):
            if found:
                rest = rest.replace(found.group(0), " ")
        records.append({"timestamp": t.group(0) if t else "", "source_ip": ip.group(0) if ip else "",
                        "user": u.group(1) if u else "", "event": re.sub(r"\s+", " ", rest).strip(" -:|")})
    return pd.DataFrame(records)


def _parse_json(text):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:  # maybe one JSON object per line
        data = [json.loads(l) for l in text.splitlines() if l.strip()]
    if isinstance(data, dict):
        for key in ("events", "logs", "records", "data"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data]
    return pd.json_normalize(data)


def parse_log(file_bytes, filename):
    """Return (raw_dataframe, notes). Raises ValueError with a friendly message on problems."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .csv, .txt and .json files are allowed.")
    if not file_bytes.strip():
        raise ValueError("The file is empty.")

    text = file_bytes.decode("utf-8-sig", errors="replace")  # text only - nothing is ever executed
    try:
        if ext == "csv":
            df = pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False,
                             sep=None, engine="python", on_bad_lines="skip")
        elif ext == "json":
            df = _parse_json(text).astype(str)
        else:
            df = _parse_txt(text)
    except Exception as exc:  # malformed file
        raise ValueError(f"Could not read the file: {type(exc).__name__}") from None

    if df.empty:
        raise ValueError("No log rows were found in the file.")
    df, mapping = detect_columns(df.fillna("").astype(str))
    if (df["timestamp"].str.strip() == "").all() or (df["event"].str.strip() == "").all():
        raise ValueError("Could not find a timestamp column and an event column in this file.")

    notes = [f"Detected columns: {', '.join(f'{k} -> {v}' for k, v in mapping.items()) or 'TXT patterns'}"]
    if len(df) > MAX_ROWS:
        df = df.head(MAX_ROWS)
        notes.append(f"File was limited to the first {MAX_ROWS} rows.")
    return df.reset_index(drop=True), notes
