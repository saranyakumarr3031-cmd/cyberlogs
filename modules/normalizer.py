"""
MODULE 2 - EVENT NORMALIZATION  (Data preprocessing)
----------------------------------------------------
Turns the raw table into one clean, common structure:

    id | order | timestamp | source_ip | user | event | etype | severity | ...

* sorts by time, but keeps `order` = the original line position in the file
* handles missing values, invalid timestamps, duplicates and unknown event types
"""
import ipaddress
import re

import pandas as pd

# base severity (0-5) for every known event type
BASE_SEVERITY = {
    "failed_login": 2, "successful_login": 1, "privilege_change": 4, "discovery": 3,
    "file_access": 1, "file_download": 2, "outbound_transfer": 3,
    "logout": 0, "normal_activity": 0, "unknown": 1,
}
SEVERITY_LABEL = {0: "info", 1: "low", 2: "low", 3: "medium", 4: "high", 5: "critical"}

# (event type, regex) - checked in this order
_RULES = [
    ("failed_login", r"(fail|denied|invalid|wrong|bad|unsuccess).*(log ?in|log ?on|auth|ssh|password|credential)|(log ?in|log ?on|auth|ssh).*(fail|denied|invalid)"),
    ("logout", r"log ?out|log ?off|sign ?out|session closed"),
    ("successful_login", r"log ?in|log ?on|authenticat|ssh accept"),
    ("privilege_change", r"privilege|sudo|escalat|admin(istrators)? group|role change|permission change|runas"),
    ("discovery", r"director(y|ies) listing|dir listing|enumerat|scan|discover|list files|network share"),
    ("outbound_transfer", r"outbound|upload|exfil|egress|transfer"),
    ("file_download", r"download|export|archive|compress|zip"),
    ("file_access", r"file access|open file|read|view|accessed|smb"),
    ("normal_activity", r"web|brows|e-?mail|mail|dns|http|sync"),
]
_SENSITIVE = re.compile(r"payroll|salary|confidential|secret|password|credential|customer|finance|/hr/|employee|backup|database|\.pem|\.key|ssn", re.I)


def classify_event(text):
    text = str(text).lower()
    for etype, pattern in _RULES:
        if re.search(pattern, text):
            return etype
    return "unknown"


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7")]


def is_private_ip(value):
    """True for internal addresses (RFC 1918 etc.) and for names that are not IPs (e.g. 'fileserver01')."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    return any(ip in net for net in _INTERNAL_NETS if net.version == ip.version)


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return "unknown"


def normalize(raw):
    """raw DataFrame -> (clean DataFrame, quality-report dict)."""
    df = raw.copy()
    df["order"] = range(1, len(df) + 1)  # original position in the file
    for col in ("source_ip", "user", "event", "action", "destination", "status"):
        df[col] = df[col].astype(str).str.strip()
    quality = {"rows_read": len(df)}

    # --- invalid timestamps (time-only values like "09:41" are accepted, today's date is used)
    
df["timestamp"] = pd.to_datetime(
    df["timestamp"].astype(str).str.strip(),
    errors="coerce",
    utc=True
).dt.tz_localize(None)
   ```python
    df["timestamp"] = pd.to_datetime(
        df["timestamp"].astype(str).str.strip(),
        errors="coerce",
        utc=True
    ).dt.tz_localize(None)

    bad = df["timestamp"].isna()
    quality["invalid_timestamps"] = int(bad.sum())
    df = df[~bad].copy()
```

    # --- missing values
    quality["missing_values_filled"] = int(((df["user"] == "") | (df["source_ip"] == "") | (df["event"] == "")).sum())
    df["user"] = df["user"].replace("", "unknown")
    df["source_ip"] = df["source_ip"].replace("", "unknown").map(_valid_ip)
    df["event"] = df["event"].replace("", "unknown event")
    df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(0).clip(lower=0)

    # --- duplicates
    key = ["timestamp", "source_ip", "user", "event", "action", "destination", "status"]
    before = len(df)
    df = df.drop_duplicates(subset=key, keep="first")
    quality["duplicates_removed"] = before - len(df)

    # --- sort by time (stable: ties keep original order) and give each event an id
    df = df.sort_values(["timestamp", "order"], kind="stable").reset_index(drop=True)
    df["id"] = df.index

    # --- event type (look at the event name first, then at the action text)
    df["etype"] = df["event"].map(classify_event)
    unknown_mask = df["etype"] == "unknown"
    df.loc[unknown_mask, "etype"] = df.loc[unknown_mask, "action"].map(classify_event)
    # a status of failure turns a login into a failed login
    fail = df["status"].str.lower().str.contains("fail|denied|error", regex=True)
    df.loc[(df["etype"] == "successful_login") & fail, "etype"] = "failed_login"
    quality["unknown_event_types"] = int((df["etype"] == "unknown").sum())

    # --- helper flags + severity
    text = df["event"] + " " + df["action"] + " " + df["destination"]
    df["sensitive"] = text.str.contains(_SENSITIVE)
    df["large"] = df["event"].str.contains(r"large|huge|massive|unusual|bulk", case=False, regex=True)
    df["external_dest"] = ~df["destination"].map(is_private_ip) & df["destination"].ne("")
    sev = df["etype"].map(BASE_SEVERITY).astype(int)
    sev += ((df["etype"].isin(["file_access", "file_download", "outbound_transfer"])) & df["sensitive"]).astype(int)
    sev += ((df["etype"] == "outbound_transfer") & df["external_dest"]).astype(int)
    sev += ((df["etype"] == "outbound_transfer") & ((df["bytes"] >= 500_000_000) | df["large"])).astype(int)
    df["severity"] = sev.clip(0, 5)
    df["severity_label"] = df["severity"].map(SEVERITY_LABEL)
    return df, quality
