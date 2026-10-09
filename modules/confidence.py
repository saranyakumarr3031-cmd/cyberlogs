"""
MODULE 8 - CONFIDENCE SCORE
---------------------------
Three explainable sub-scores (0-100) combined into one overall number:

    Evidence Strength     how strong/unusual the events are and how many stages were seen
    Event Correlation     average relationship score between consecutive incident events
    Sequence Consistency  do the events follow a logical attack order in time?

    Overall = 40% evidence + 30% correlation + 30% sequence   (never shown above 95%)

The number is an ANALYTICAL ESTIMATE. It is not proof that an attack happened.
"""
from .attack_stage import STAGE_INDEX

DISCLAIMER = ("Confidence is an analytical estimate calculated from the evidence in the uploaded logs. "
              "It is NOT proof of an attack. The result is a suspected / potential incident that a human "
              "analyst must verify before any conclusion is made.")
MAX_CONFIDENCE = 0.95


def confidence_scores(events, chain_scores):
    """events: list of dicts (time-sorted, each with anomaly, severity, stage)."""
    top = sorted((e["anomaly"] for e in events), reverse=True)[:5]
    mean_top = sum(top) / len(top)
    n_stages = len({e["stage"] for e in events})
    strong = any(e["severity"] >= 4 for e in events)
    evidence = 0.45 * min(1.0, mean_top / 0.7) + 0.35 * min(1.0, n_stages / 5) + 0.20 * (1.0 if strong else 0.0)

    correlation = sum(chain_scores) / len(chain_scores) if chain_scores else 0.0

    order = [STAGE_INDEX[e["stage"]] for e in events]
    steps = list(zip(order, order[1:]))
    sequence = sum(1 for a, b in steps if b >= a) / len(steps) if steps else 0.0

    overall = min(MAX_CONFIDENCE, 0.4 * evidence + 0.3 * correlation + 0.3 * sequence)
    pct = lambda x: int(round(100 * x))
    return {"evidence_strength": pct(evidence), "event_correlation": pct(correlation),
            "sequence_consistency": pct(sequence), "overall": pct(overall), "disclaimer": DISCLAIMER}


def conclusion_confidence(satisfied, total, overall_pct):
    """Confidence for one conclusion = half 'how many of its checks passed', half overall confidence."""
    ratio = satisfied / total if total else 0
    return int(round(100 * min(MAX_CONFIDENCE, 0.5 * ratio + 0.5 * overall_pct / 100)))


def risk_score(events, n_stages):
    """0-100 'how serious would this be IF it is real' (separate from confidence)."""
    max_sev = max(e["severity"] for e in events)
    mean_anom = sum(e["anomaly"] for e in events) / len(events)
    stages = {e["stage"] for e in events}
    score = (max_sev / 5) * 35 + min(1, n_stages / 7) * 25 + mean_anom * 15
    score += 15 if stages & {"Data Transfer", "Possible Exfiltration"} else 0
    score += 10 if "Privilege Activity" in stages else 0
    return int(min(100, round(score)))
