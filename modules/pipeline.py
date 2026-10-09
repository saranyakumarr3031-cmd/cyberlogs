"""
The full pipeline, one clearly separated step after another:

  1 Data preprocessing      -> log_parser.py + normalizer.py
  2 Anomaly detection (ML)  -> anomaly_detector.py
  3 Event correlation       -> event_correlator.py
  4 Incident reconstruction -> incident_reconstructor.py
  5 Attack-stage classif.   -> attack_stage.py (used inside step 4)
  6 Explanation (story)     -> story_generator.py (used inside step 4)
"""
from .anomaly_detector import CANDIDATE_THRESHOLD, detect_anomalies
from .event_correlator import correlate
from .incident_reconstructor import reconstruct
from .log_parser import parse_log
from .normalizer import normalize


def _short(value, limit=200):
    value = str(value)
    return value if len(value) <= limit else value[:limit] + "..."


def run_pipeline(file_bytes, filename):
    raw, notes = parse_log(file_bytes, filename)           # 1 ingestion
    df, quality = normalize(raw)                           # 1 normalization
    if df.empty:
        raise ValueError("No valid events remained after cleaning (check the timestamp column).")
    df = detect_anomalies(df)                              # 2 anomaly detection
    edges, labels = correlate(df)                          # 3 correlation + clustering
    incidents, notes_by_id = reconstruct(df, labels)       # 4 + 5 + 6 reconstruction

    events = []
    for r in df.to_dict("records"):
        a = notes_by_id.get(r["id"], {})
        events.append({
            "id": r["id"], "order": r.get("order", r["id"]), "date": r["timestamp"].strftime("%Y-%m-%d"),
            "time": r["timestamp"].strftime("%H:%M:%S"), "ip": _short(r["source_ip"]), "user": _short(r["user"]),
            "event": _short(r["event"]), "etype": r["etype"], "action": _short(r["action"]),
            "destination": _short(r["destination"]), "status": _short(r["status"]), "bytes": int(r["bytes"]),
            "severity": int(r.get("severity", 0)),
            "severity_label": r.get("severity_label", "Unknown"),
            "anomaly": float(r["anomaly"]), "ml_score": round(float(r["ml_score"]), 3), "reasons": r["reasons"],
            "sensitive": bool(r["sensitive"]), "external_dest": bool(r["external_dest"]),
            "stage": a.get("stage", ""), "incident": a.get("incident", ""),
            "corr_prev": a.get("corr_prev"), "corr_prev_id": a.get("corr_prev_id"),
            "flagged": bool(r["is_candidate"]),
        })

    in_incident = {x for i in incidents for x in i["event_ids"]}
    isolated = [e["id"] for e in events if e["flagged"] and e["id"] not in in_incident]
    meta = {"filename": filename, "notes": notes, **quality, "valid_events": len(df),
            "flagged_events": int(df["is_candidate"].sum()), "relationships": len(edges),
            "candidate_threshold": CANDIDATE_THRESHOLD}
    return {"meta": meta, "events": events, "incidents": incidents, "isolated_ids": isolated,
            "edges": [e for i in incidents for e in i["edges"]]}
