"""
MODULE 12 - REPORT GENERATION
-----------------------------
Collects everything the report page needs. The HTML itself is produced by the
Flask template `templates/report.html` (Jinja escapes all log text automatically).
PDF = open the report and use the browser's "Save as PDF" (Print) button - no extra library needed.
"""

RECOMMENDATIONS = {
    "Initial Access": "Enable account lockout / rate limiting and multi-factor authentication; block or monitor the source IP.",
    "Authentication": "Reset the password of the affected account and review all of its recent sessions.",
    "Privilege Activity": "Review and revert any unexpected privilege or group-membership change; apply least privilege.",
    "Discovery": "Check which directories were listed and restrict broad read access on file servers.",
    "Resource Access": "Audit access to the sensitive files involved and confirm with the data owner whether it was expected.",
    "Data Collection": "Review download volume for the account; enable data-loss-prevention (DLP) alerts on bulk downloads.",
    "Data Transfer": "Inspect the outbound connection and destination; consider blocking it at the firewall until verified.",
    "Possible Exfiltration": "Treat as a potential data leak: preserve logs, block the external destination, and involve the incident-response / data-protection team.",
}
GENERAL = [
    "Preserve the original logs and take a copy before making any changes (evidence integrity).",
    "Verify this suspected incident manually - confirm with the account owner before drawing conclusions.",
    "Document findings and escalate to the incident-response team if the activity cannot be explained.",
]


def build_report(result, incident):
    events = {e["id"]: e for e in result["events"]}
    timeline = [events[i] for i in incident["event_ids"]]
    suspicious = [events[i] for i in incident["key_event_ids"]]
    actions = [RECOMMENDATIONS[s["stage"]] for s in incident["stages"] if s["stage"] in RECOMMENDATIONS] + GENERAL
    return {"incident": incident, "timeline": timeline, "suspicious": suspicious,
            "actions": actions, "filename": result["meta"]["filename"],
            "generated_at": result.get("created_at", "")}
