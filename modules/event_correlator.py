
"""
MODULE 3b - AI-ASSISTED EVENT CORRELATION
Calculates relationships between suspicious events and groups
strongly related events into candidate incidents.
"""

import math

import numpy as np
from sklearn.cluster import DBSCAN

from .attack_stage import STAGE_BY_TYPE, STAGE_INDEX


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
EDGE_THRESHOLD = 0.55

DBSCAN_EPS = 0.35
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
    """Estimate the relationship between two event types."""

    stage_a = STAGE_BY_TYPE.get(type_a)
    stage_b = STAGE_BY_TYPE.get(type_b)

    if stage_a is None or stage_b is None:
        return 0.10

    delta = STAGE_INDEX[stage_b] - STAGE_INDEX[stage_a]

    if delta >= 0:
        return _FORWARD.get(delta, 0.40)

    return 0.20


def pair_score(a, b, type_counts):
    """Calculate a relationship score between two events."""

    minutes = abs(
        (b["timestamp"] - a["timestamp"]).total_seconds()
    ) / 60.0

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
        "type_relation": type_relation(a["etype"], b["etype"]),
        "severity": (
            float(a["severity"]) + float(b["severity"])
        ) / 10.0,
        "repetition": (
            1.0
            if a["etype"] == b["etype"]
            else min(
                1.0,
                type_counts.get(
                    (b["source_ip"], b["etype"]), 1
                ) / 3.0,
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

    parts = {
        key: round(float(value), 2)
        for key, value in parts.items()
    }

    return round(float(score), 3), parts


def correlate(df):
    """
    Returns:
      edges: relationships with score >= EDGE_THRESHOLD
      labels: event ID -> cluster ID; -1 means not clustered
    """

    candidates = (
        df[df["is_candidate"]]
        .sort_values("timestamp")
    )

    ids = candidates["id"].tolist()
    rows = candidates.to_dict("records")
    n = len(rows)

    if n == 0:
        return [], {}

    type_counts = (
        candidates.groupby(["source_ip", "etype"])
        .size()
        .to_dict()
    )

    distances = np.ones((n, n), dtype=float)
    np.fill_diagonal(distances, 0.0)

    edges = []

    for i in range(n):
        for j in range(i + 1, n):
            minutes = (
                rows[j]["timestamp"] - rows[i]["timestamp"]
            ).total_seconds() / 60.0

            if minutes > WINDOW_MINUTES:
                break

            score, parts = pair_score(
                rows[i], rows[j], type_counts
            )

            distance = 1.0 - score
            distances[i, j] = distance
            distances[j, i] = distance

            if score >= EDGE_THRESHOLD:
                edges.append({
                    "a": ids[i],
                    "b": ids[j],
                    "score": score,
                    "parts": parts,
                })

    # Allow a cluster containing two strongly related events.
    if n >= DBSCAN_MIN_SAMPLES:
        cluster_ids = DBSCAN(
            eps=DBSCAN_EPS,
            min_samples=DBSCAN_MIN_SAMPLES,
            metric="precomputed",
        ).fit_predict(distances)

        labels = {
            ids[index]: int(cluster_ids[index])
            for index in range(n)
        }
    else:
        labels = {
            event_id: -1
            for event_id in ids
        }

    return edges, labels

