```python
"""
MODULE 3b - AI-ASSISTED EVENT CORRELATION
-----------------------------------------
Calculates relationship scores between suspicious events using seven factors,
then uses DBSCAN clustering to group related events into candidate incidents.
"""

import math

import numpy as np
from sklearn.cluster import DBSCAN

from .attack_stage import STAGE_BY_TYPE, STAGE_INDEX


# Relationship weights
WEIGHTS = {
    "same_ip": 0.22,
    "same_user": 0.18,
    "time": 0.20,
    "type_relation": 0.20,
    "severity": 0.08,
    "repetition": 0.06,
    "src_dst": 0.06,
}

WINDOW_MINUTES = 60
TIME_DECAY_MINUTES = 15

# Minimum score needed to create a relationship edge
EDGE_THRESHOLD = 0.55

# DBSCAN clustering settings
DBSCAN_EPS = 0.35

# Changed from 3 to 2 so two strongly related events
# can form a candidate cluster.
DBSCAN_MIN_SAMPLES = 2


_FORWARD = {
    0: 0.80,
    1: 1.00,
    2: 0.90,
    3: 0.80,
    4: 0.65,
    5: 0.50,
    6: 0.40,
}


def type_relation(type_a, type_b):
    """Estimate how naturally one event type follows another."""

    stage_a = STAGE_BY_TYPE.get(type_a)
    stage_b = STAGE_BY_TYPE.get(type_b)

    if stage_a is None or stage_b is None:
        return 0.10

    delta = STAGE_INDEX[stage_b] - STAGE_INDEX[stage_a]

    if delta >= 0:
        return _FORWARD.get(delta, 0.40)

    return 0.20


def pair_score(a, b, type_counts):
    """Calculate relationship score and individual factor contributions."""

    minutes = abs(
        (b["timestamp"] - a["timestamp"]).total_seconds()
    ) / 60

    parts = {
        "same_ip": (
            1.0
            if a["source_ip"] == b["source_ip"]
            and a["source_ip"] != "unknown"
            else 0.0
        ),

        "same_user": (
            1.0
            if a["user"] == b["user"]
            and a["user"] != "unknown"
            else 0.0
        ),

        "time": math.exp(-minutes / TIME_DECAY_MINUTES),

        "type_relation": type_relation(
            a["etype"], b["etype"]
        ),

        "severity": (
            a["severity"] + b["severity"]
        ) / 10.0,

        "repetition": (
            1.0
            if a["etype"] == b["etype"]
            else min(
                1.0,
                type_counts.get(
                    (b["source_ip"], b["etype"]), 1
                ) / 3,
            )
        ),

        "src_dst": (
            1.0
            if a["destination"]
            and a["destination"] == b["destination"]
            else (
                0.8
                if (
                    b["etype"] == "outbound_transfer"
                    and not a["external_dest"]
                )
                else 0.4
            )
        ),
    }

    score = sum(
        WEIGHTS[key] * value
        for key, value in parts.items()
    )

    rounded_parts = {
        key: round(float(value), 2)
        for key, value in parts.items()
    }

    return round(float(score), 3), rounded_parts


def correlate(df):
    """
    Return:
      edges: event relationships above EDGE_THRESHOLD
      labels: event ID to cluster number; -1 means noise
    """

    cand = (
        df[df["is_candidate"]]
        .sort_values("timestamp")
    )

    ids = cand["id"].tolist()
    rows = cand.to_dict("records")
    n = len(rows)

    type_counts = (
        cand.groupby(["source_ip", "etype"])
        .size()
        .to_dict()
    )

    # No suspicious candidate events means no relationships.
    if n == 0:
        return [], {}

    # Initialize distance matrix.
    # DBSCAN uses distance = 1 - relationship score.
    dist = np.ones((n, n), dtype=float)
    np.fill_diagonal(dist, 0.0)

    edges = []

    for i in range(n):
        for j in range(i + 1, n):

            minutes = (
                rows[j]["timestamp"] - rows[i]["timestamp"]
            ).total_seconds() / 60

            if minutes > WINDOW_MINUTES:
                break

            score, parts = pair_score(
                rows[i], rows[j], type_counts
            )

            distance = 1.0 - score
            dist[i, j] = distance
            dist[j, i] = distance

            if score >= EDGE_THRESHOLD:
                edges.append({
                    "a": ids[i],
                    "b": ids[j],
                    "score": score,
                    "parts": parts,
                })

    # Cluster candidate events.
    if n >= DBSCAN_MIN_SAMPLES:
        found = DBSCAN(
            eps=DBSCAN_EPS,
            min_samples=DBSCAN_MIN_SAMPLES,
            metric="precomputed",
        ).fit_predict(dist)

        labels = {
            ids[index]: int(found[index])
            for index in range(n)
        }
    else:
        labels = {
            ids[index]: -1
            for index in range(n)
        }

    return edges, labels
```
