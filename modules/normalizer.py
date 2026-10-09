
"""
IncidentLensAI - Log Normalizer
Normalizes uploaded security CSV logs into a consistent schema.
"""

import pandas as pd
import numpy as np


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _find_column(df, candidates):
    """Find a column without depending on capitalization or spaces."""
    normalized = {
        str(col).strip().lower().replace(" ", "_").replace("-", "_"): col
        for col in df.columns
    }

    for candidate in candidates:
        key = candidate.strip().lower().replace(" ", "_").replace("-", "_")
        if key in normalized:
            return normalized[key]

    return None


def _clean_text(value, default="unknown"):
    if pd.isna(value):
        return default

    value = str(value).strip()
    return value if value else default


def detect_event_type(value):
    """Map common security event names into normalized event types."""
    text = _clean_text(value, "").lower()
    text = text.replace("-", "_").replace(" ", "_")

    patterns = {
        "failed_login": [
            "failed_login", "login_failed", "authentication_failure",
            "auth_failure", "invalid_password", "failed_authentication",
            "login_failure", "logon_failure"
        ],
        "successful_login": [
            "successful_login", "login_success", "authentication_success",
            "user_login", "logged_in", "logon_success"
        ],
        "port_scan": [
            "port_scan", "portscan", "network_scan", "nmap"
        ],
        "malware": [
            "malware", "virus_detected", "trojan", "ransomware"
        ],
        "outbound_transfer": [
            "outbound_transfer", "data_exfiltration", "large_upload",
            "data_transfer", "file_upload"
        ],
        "privilege_escalation": [
            "privilege_escalation", "admin_privilege",
            "privilege_grant", "sudo"
        ],
        "suspicious_process": [
            "suspicious_process", "process_injection",
            "powershell", "suspicious_execution"
        ],
        "firewall_block": [
            "firewall_block", "connection_blocked", "blocked_connection"
        ],
        "file_access": [
            "file_access", "file_modified", "file_deleted"
        ],
        "dns_query": [
            "dns_query", "dns_request", "domain_lookup"
        ],
    }

    # Exact/substring matching against known event patterns.
    for event_type, keywords in patterns.items():
        if any(keyword in text for keyword in keywords):
            return event_type

    # Keep a meaningful unknown event name instead of inventing a type.
    return text if text and text != "unknown" else "unknown"


# ---------------------------------------------------------
# Main normalizer
# ---------------------------------------------------------

def normalize(df):
    """
    Input:
        pandas DataFrame containing uploaded log records.

    Output:
        (normalized_dataframe, quality_dictionary)

    The output includes columns expected by the pipeline:
        id, timestamp, source_ip, user, destination, external_dest,
        etype, severity, is_candidate
    """

    if df is None:
        raise ValueError("No CSV data was supplied.")

    if not isinstance(df, pd.DataFrame):
        df = pd.DataFrame(df)

    if df.empty:
        raise ValueError("The uploaded CSV file contains no data rows.")

    df = df.copy()

    # Normalize header names.
    df.columns = [
        str(col).strip().lower().replace(" ", "_").replace("-", "_")
        for col in df.columns
    ]

    # Remove duplicate column names, keeping the first occurrence.
    df = df.loc[:, ~df.columns.duplicated()].copy()

    quality = {
        "rows_read": int(len(df)),
        "invalid_timestamps": 0,
        "duplicates_removed": 0,
        "valid_events": 0,
        "unknown_event_types": 0,
    }

    # Find common timestamp column names.
    timestamp_col = _find_column(
        df,
        [
            "timestamp", "@timestamp", "time", "datetime",
            "date_time", "event_time", "created_at", "date"
        ],
    )

    if timestamp_col is None:
        raise ValueError(
            "Could not find a timestamp column. "
            "Expected a column such as timestamp, time, or datetime. "
            f"Found columns: {list(df.columns)}"
        )

    # Find common event-type column names.
    event_col = _find_column(
        df,
        [
            "etype", "event", "event_type", "eventtype",
            "event_name", "activity", "action", "description",
            "message", "log_type", "signature"
        ],
    )

    if event_col is None:
        raise ValueError(
            "Could not find an event column. "
            "Expected event, event_type, event_name, action, or message. "
            f"Found columns: {list(df.columns)}"
        )

    # Standardize timestamps.
    df["timestamp"] = pd.to_datetime(
        df[timestamp_col].astype(str).str.strip(),
        errors="coerce",
        utc=True,
    ).dt.tz_localize(None)

    bad_timestamps = df["timestamp"].isna()
    quality["invalid_timestamps"] = int(bad_timestamps.sum())

    df = df.loc[~bad_timestamps].copy()

    if df.empty:
        raise ValueError(
            "No valid timestamps were found. "
            "Please check the timestamp values in the CSV."
        )

    # Generate stable IDs for the remaining rows.
    id_col = _find_column(
        df,
        ["id", "event_id", "log_id", "record_id", "row_id"],
    )

    if id_col is not None:
        df["id"] = df[id_col].astype(str)
    else:
        df["id"] = [f"event_{i + 1}" for i in range(len(df))]

    # Normalize event types.
    df["etype"] = df[event_col].apply(detect_event_type)

    quality["unknown_event_types"] = int(
        (df["etype"] == "unknown").sum()
    )

    # Source IP.
    source_col = _find_column(
        df,
        [
            "source_ip", "src_ip", "src", "srcip",
            "client_ip", "ip_address", "ip", "remote_ip"
        ],
    )

    if source_col is not None:
        df["source_ip"] = df[source_col].apply(_clean_text)
    else:
        df["source_ip"] = "unknown"

    # Username.
    user_col = _find_column(
        df,
        [
            "user", "username", "user_name", "account",
            "account_name", "principal", "subject"
        ],
    )

    if user_col is not None:
        df["user"] = df[user_col].apply(_clean_text)
    else:
        df["user"] = "unknown"

    # Destination.
    destination_col = _find_column(
        df,
        [
            "destination", "destination_ip", "dest_ip",
            "dst_ip", "dst", "dest", "target_ip",
            "remote_host", "destination_host"
        ],
    )

    if destination_col is not None:
        df["destination"] = df[destination_col].apply(_clean_text)
        df.loc[df["destination"] == "unknown", "destination"] = ""
    else:
        df["destination"] = ""

    # External destination indicator.
    external_col = _find_column(
        df,
        [
            "external_dest", "is_external", "external_destination",
            "destination_external"
        ],
    )

    if external_col is not None:
        df["external_dest"] = (
            df[external_col]
            .astype(str)
            .str.strip()
            .str.lower()
            .isin(["true", "1", "yes", "y", "external"])
        )
    else:
        df["external_dest"] = False

    # Severity: preserve numeric values where possible.
    severity_col = _find_column(
        df,
        [
            "severity", "severity_score", "risk_score",
            "priority_score", "level"
        ],
    )

    if severity_col is not None:
        severity = pd.to_numeric(df[severity_col], errors="coerce")
    else:
        severity = pd.Series(np.nan, index=df.index)

    # Convert common textual severity levels to a 1-5 scale.
    if severity_col is not None:
        text_severity = (
            df[severity_col].astype(str).str.strip().str.lower()
        )

        severity_map = {
            "info": 1,
            "informational": 1,
            "low": 2,
            "medium": 3,
            "moderate": 3,
            "high": 4,
            "critical": 5,
            "urgent": 5,
        }

        mapped = text_severity.map(severity_map)
        severity = severity.fillna(mapped)

    df["severity"] = severity.fillna(1).clip(lower=1, upper=5).astype(int)

    severity_labels = {
        1: "Low",
        2: "Low",
        3: "Medium",
        4: "High",
        5: "Critical",
    }

    df["severity_label"] = df["severity"].map(severity_labels)

    # Anomaly score: use an existing score if present; otherwise
    # initialize it to zero. Detection happens in the pipeline.
    anomaly_col = _find_column(
        df,
        ["anomaly_score", "anomaly", "anomaly_probability"],
    )

    if anomaly_col is not None:
        df["anomaly_score"] = pd.to_numeric(
            df[anomaly_col], errors="coerce"
        ).fillna(0).clip(lower=0, upper=1)
    else:
        df["anomaly_score"] = 0.0

    # Preserve existing order if supplied, otherwise generate one.
    order_col = _find_column(
        df,
        ["order", "event_order", "sequence", "sequence_number"],
    )

    if order_col is not None:
        df["order"] = df[order_col]
    else:
        df["order"] = range(1, len(df) + 1)

    # Mark potential candidates for downstream anomaly detection.
    # Unknown events are not automatically considered malicious.
    df["is_candidate"] = df["etype"] != "unknown"

    # Remove exact duplicate rows.
    before = len(df)
    df = df.drop_duplicates().copy()
    quality["duplicates_removed"] = int(before - len(df))

    # Ensure chronological order.
    df = df.sort_values("timestamp").reset_index(drop=True)

    quality["valid_events"] = int(len(df))

    return df, quality
