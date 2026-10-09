
import pandas as pd


def normalize(raw):
    """
    Normalize parsed security logs into a consistent format.
    Returns:
        df      : cleaned DataFrame
        quality : data-quality statistics
    """

    df = raw.copy()

    quality = {
        "rows_read": len(df),
        "invalid_timestamps": 0,
        "duplicates_removed": 0,
        "unknown_event_types": 0,
    }

    if df.empty:
        return df, quality

    # Ensure expected columns exist
    expected_columns = [
        "timestamp",
        "source_ip",
        "user",
        "event",
        "action",
        "destination",
        "status",
        "bytes",
    ]

    for column in expected_columns:
        if column not in df.columns:
            df[column] = ""

    # Normalize timestamp values
    df["timestamp"] = pd.to_datetime(
        df["timestamp"].astype(str).str.strip(),
        errors="coerce",
        utc=True,
    ).dt.tz_localize(None)

    # Remove invalid timestamps
    bad = df["timestamp"].isna()
    quality["invalid_timestamps"] = int(bad.sum())
    df = df[~bad].copy()

    if df.empty:
        quality["duplicates_removed"] = 0
        quality["unknown_event_types"] = 0
        return df, quality

    # Clean text fields
    text_columns = [
        "source_ip",
        "user",
        "event",
        "action",
        "destination",
        "status",
    ]

    for column in text_columns:
        df[column] = (
            df[column]
            .fillna("")
            .astype(str)
            .str.strip()
        )

    # Replace missing values
    df["source_ip"] = df["source_ip"].replace("", "unknown")
    df["user"] = df["user"].replace("", "unknown")
    df["event"] = df["event"].replace("", "unknown")
    df["action"] = df["action"].replace("", "unknown")
    df["destination"] = df["destination"].replace("", "unknown")
    df["status"] = df["status"].replace("", "unknown")

    # Convert bytes to numeric values
    df["bytes"] = pd.to_numeric(
        df["bytes"], errors="coerce"
    ).fillna(0)

    # Remove duplicate rows
    before = len(df)
    df = df.drop_duplicates().copy()
    quality["duplicates_removed"] = before - len(df)

    # Sort by time
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Assign unique event IDs
    df["id"] = [
        f"E{i + 1:04d}" for i in range(len(df))
    ]

    # Normalize event names
    event_text = (
        df["event"].astype(str).str.lower()
        + " "
        + df["action"].astype(str).str.lower()
    )

    def classify_event(value):
        value = str(value).lower()

        if any(word in value for word in [
            "failed login", "login failed", "authentication failure",
            "auth failure", "invalid password",
        ]):
            return "failed_login"

        if any(word in value for word in [
            "successful login", "login success", "user login",
        ]):
            return "successful_login"

        if any(word in value for word in [
            "port scan", "portscan", "network scan",
        ]):
            return "port_scan"

        if any(word in value for word in [
            "privilege escalation", "sudo", "admin privilege",
        ]):
            return "privilege_escalation"

        if any(word in value for word in [
            "malware", "ransomware", "virus detected",
        ]):
            return "malware_detected"

        if any(word in value for word in [
            "outbound transfer", "data exfiltration",
            "large upload", "data transfer",
        ]):
            return "outbound_transfer"

        if any(word in value for word in [
            "file access", "file modified", "file deleted",
        ]):
            return "file_activity"

        if any(word in value for word in [
            "firewall", "blocked connection", "connection blocked",
        ]):
            return "firewall_event"

        if any(word in value for word in [
            "dns query", "dns request",
        ]):
            return "dns_query"

        if any(word in value for word in [
            "process started", "process execution",
        ]):
            return "process_execution"

        return "unknown"

    df["etype"] = event_text.apply(classify_event)

    # Severity score from 1 (low) to 5 (critical)
    severity_map = {
        "failed_login": 2,
        "successful_login": 1,
        "port_scan": 3,
        "privilege_escalation": 5,
        "malware_detected": 5,
        "outbound_transfer": 4,
        "file_activity": 2,
        "firewall_event": 2,
        "dns_query": 1,
        "process_execution": 2,
        "unknown": 1,
    }

    df["severity"] = df["etype"].map(severity_map).fillna(1).astype(int)

    # Mark potentially sensitive events
    df["sensitive"] = df["etype"].isin([
        "failed_login",
        "privilege_escalation",
        "malware_detected",
        "outbound_transfer",
    ])

    # Identify external destination hints
    def is_external_destination(value):
        value = str(value).strip().lower()

        if not value or value in {
            "unknown", "localhost", "127.0.0.1", "::1"
        }:
            return False

        # This is a simple heuristic, not a complete IP/domain validator.
        if value.startswith((
            "10.", "192.168.", "172.16.", "172.17.",
            "172.18.", "172.19.", "172.20.", "172.21.",
            "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.",
        )):
            return False

        return True

    df["external_dest"] = df["destination"].apply(
        is_external_destination
    )

    # Count unrecognized event types
    quality["unknown_event_types"] = int(
        (df["etype"] == "unknown").sum()
    )

    return df, quality
