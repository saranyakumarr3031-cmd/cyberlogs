"""
MODULE 4 - ATTACK STAGE IDENTIFICATION
--------------------------------------
Maps each event type to a *possible* attack stage. These are hints, not facts.

MITRE ATT&CK IDs are only attached as "candidate techniques" and only when the
evidence supports them (e.g. T1110 needs at least 3 failed logins).
"""

STAGE_ORDER = ["Initial Access", "Authentication", "Privilege Activity", "Discovery",
               "Resource Access", "Data Collection", "Data Transfer", "Possible Exfiltration"]
STAGE_INDEX = {s: i for i, s in enumerate(STAGE_ORDER)}

STAGE_BY_TYPE = {
    "failed_login": "Initial Access",
    "successful_login": "Authentication",
    "privilege_change": "Privilege Activity",
    "discovery": "Discovery",
    "file_access": "Resource Access",
    "file_download": "Data Collection",
    "outbound_transfer": "Data Transfer",
}

# friendly wording used in the "Possible Incident" sequence
STAGE_PHRASE = {
    "Initial Access": "Unauthorized Access Attempts", "Authentication": "Account Access",
    "Privilege Activity": "Privilege Activity", "Discovery": "Resource Discovery",
    "Resource Access": "Sensitive Resource Access", "Data Collection": "Data Collection",
    "Data Transfer": "Data Transfer", "Possible Exfiltration": "Possible Data Exfiltration",
}

# (event type, minimum number of such events needed, technique id, name)
MITRE_RULES = [
    ("failed_login", 3, "T1110", "Brute Force"),
    ("successful_login", 1, "T1078", "Valid Accounts"),
    ("privilege_change", 1, "T1098", "Account Manipulation"),
    ("discovery", 1, "T1083", "File and Directory Discovery"),
    ("file_download", 1, "T1005", "Data from Local System"),
    ("outbound_transfer", 1, "T1041", "Exfiltration Over C2 Channel"),
]


def assign_stages(df):
    """Basic stage per event (only for event types that belong to the kill chain)."""
    df = df.copy()
    df["stage"] = df["etype"].map(STAGE_BY_TYPE).fillna("")
    return df


def refine_stage(event_type, bytes_out, external, earlier_stage_names):
    """An outbound transfer becomes 'Possible Exfiltration' only when it looks big/external
    AND data was collected earlier in the same incident."""
    if event_type != "outbound_transfer":
        return STAGE_BY_TYPE.get(event_type, "")
    collected = {"Data Collection", "Resource Access"} & set(earlier_stage_names)
    if collected and (external or bytes_out >= 100_000_000):
        return "Possible Exfiltration"
    return "Data Transfer"


def mitre_candidates(event_types):
    """List of candidate (not confirmed) ATT&CK techniques, only if the evidence count is met."""
    out = []
    for etype, minimum, tid, name in MITRE_RULES:
        n = sum(1 for e in event_types if e == etype)
        if n >= minimum:
            out.append({"id": tid, "name": name, "based_on": f"{n} x {etype.replace('_', ' ')}"})
    return out


ETYPE_LABEL = {
    "failed_login": "Failed Login", "successful_login": "Successful Login",
    "privilege_change": "Privilege Change", "discovery": "Discovery",
    "file_access": "File Access", "file_download": "File Download",
    "outbound_transfer": "Outbound Transfer", "logout": "Logout",
    "normal_activity": "Normal Activity", "unknown": "Unknown",
}
