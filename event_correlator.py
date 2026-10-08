"""
MODULE 3b - AI-ASSISTED EVENT CORRELATION   (the heart of the project)
----------------------------------------------------------------------
For every pair of suspicious events that happened close in time we calculate a
relationship score between 0 and 1 from SEVEN factors (not only the IP):

    same IP 22% | same user 18% | time closeness 20% | related event types 20%
    event severity 8% | repeated behaviour 6% | source/destination relation 6%

Then DBSCAN clustering (scikit-learn) groups events that are strongly related.
Each cluster is a *candidate incident*. Events that are not strongly related to
anything (like a lone backup job) stay out of the cluster.
"""
import math

import numpy as np
from sklearn.cluster import DBSCAN

from .attack_stage import STAGE_BY_TYPE, STAGE_INDEX

WEIGHTS = {"same_ip": 0.22, "same_user": 0.18, "time": 0.20, "type_relation": 0.20,
           "severity": 0.08, "repetition": 0.06, "src_dst": 0.06}
WINDOW_MINUTES = 60        # events further apart than this are never correlated
TIME_DECAY_MINUTES = 15    # how fast "time closeness" fades
EDGE_THRESHOLD = 0.55      # pairs scoring at least this are kept as relationships
DBSCAN_EPS = 0.35          # cluster distance = 1 - score  (so score >= 0.65 is "close")
DBSCAN_MIN_SAMPLES = 3

# how much event B "follows" event A in a normal attack progression (by stage distance)
_FORWARD = {0: 0.80, 1: 1.00, 2: 0.90, 3: 0.80, 4: 0.65, 5: 0.50, 6: 0.40}


def type_relation(type_a, type_b):
    """1.0 = natural next step of an attack, low = unrelated / going backwards."""
    sa, sb = STAGE_BY_TYPE.get(type_a), STAGE_BY_TYPE.get(type_b)
    if not sa or not sb:
        return 0.10
    delta = STAGE_INDEX[sb] - STAGE_INDEX[sa]
    return _FORWARD.get(delta, 0.40) if delta >= 0 else 0.20


def pair_score(a, b, type_counts):
    """a happened before b (both are dict-like rows). Returns (score, parts)."""
    minutes = abs((b["timestamp"] - a["timestamp"]).total_seconds()) / 60
    parts = {
        "same_ip": 1.0 if a["source_ip"] == b["source_ip"] and a["source_ip"] != "unknown" else 0.0,
        "same_user": 1.0 if a["user"] == b["user"] and a["user"] != "unknown" else 0.0,
        "time": math.exp(-minutes / TIME_DECAY_MINUTES),
        "type_relation": type_relation(a["etype"], b["etype"]),
        "severity": (a["severity"] + b["severity"]) / 10.0,
        "repetition": 1.0 if a["etype"] == b["etype"] else min(1.0, type_counts.get((b["source_ip"], b["etype"]), 1) / 3),
        "src_dst": 1.0 if a["destination"] and a["destination"] == b["destination"]
                   else 0.8 if (b["etype"] == "outbound_transfer" and not a["external_dest"]) else 0.4,
    }
    score = sum(WEIGHTS[k] * v for k, v in parts.items())
    return round(float(score), 3), {k: round(float(v), 2) for k, v in parts.items()}


def correlate(df):
    """Returns (edges, labels).
    edges  : list of {a, b, score, parts}  for pairs scoring >= EDGE_THRESHOLD
    labels : {event_id: cluster_number}    (-1 = not part of any cluster)"""
    cand = df[df["is_candidate"]].sort_values("timestamp")
    ids = cand["id"].tolist()
    rows = cand.to_dict("records")
    n = len(rows)
    type_counts = cand.groupby(["source_ip", "etype"]).size().to_dict()

    dist = np.ones((n, n))
    np.fill_diagonal(dist, 0)
    edges = []
    for i in range(n):
        for j in range(i + 1, n):
            if (rows[j]["timestamp"] - rows[i]["timestamp"]).total_seconds() > WINDOW_MINUTES * 60:
                break  # rows are sorted by time, so later ones are even further away
            score, parts = pair_score(rows[i], rows[j], type_counts)
            dist[i, j] = dist[j, i] = 1 - score
            if score >= EDGE_THRESHOLD:
                edges.append({"a": ids[i], "b": ids[j], "score": score, "parts": parts})

    labels = {}
    if n >= DBSCAN_MIN_SAMPLES:
        found = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES, metric="precomputed").fit_predict(dist)
        labels = {ids[k]: int(found[k]) for k in range(n)}
    return edges, labels
