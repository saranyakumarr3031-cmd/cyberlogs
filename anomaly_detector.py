"""
MODULE 3a - ANOMALY DETECTION  (Machine Learning: Isolation Forest)
-------------------------------------------------------------------
Every event gets an `anomaly` score from 0 to 1:

    anomaly = 0.6 * rule_score  +  0.4 * ml_score

* rule_score : explainable, based on severity + behaviour (e.g. "success after 5 failures")
* ml_score   : IsolationForest (scikit-learn) - "how unusual is this event compared with
               all the other events in this file?"

IMPORTANT: an anomaly is only "unusual". It is NOT proof of malicious activity.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

CANDIDATE_THRESHOLD = 0.40  # events at/above this are passed on to the correlator


def _window_counts(times, ip_values, mask, seconds=600):
    """For each event: how many `mask` events came from the same IP in the previous `seconds`."""
    out = np.zeros(len(times))
    for ip in np.unique(ip_values):
        idx = np.where(ip_values == ip)[0]
        t_all = times[idx]
        t_flag = np.sort(times[idx][mask[idx]])
        out[idx] = (np.searchsorted(t_flag, t_all, side="right")
                    - np.searchsorted(t_flag, t_all - seconds, side="left"))
    return out


def detect_anomalies(df):
    df = df.copy()
    t = df["timestamp"].astype("int64").to_numpy() / 1e9
    ips = df["source_ip"].to_numpy()
    failed = (df["etype"] == "failed_login").to_numpy()

    df["failed_10m"] = _window_counts(t, ips, failed)                    # failures from this IP in last 10 min
    df["burst_10m"] = _window_counts(t, ips, np.ones(len(df), bool))     # all events from this IP in last 10 min
    hour = df["timestamp"].dt.hour
    df["night"] = ((hour < 6) | (hour >= 22)).astype(int)
    ip_count = df.groupby("source_ip")["id"].transform("count")
    pair_count = df.groupby(["source_ip", "user"])["id"].transform("count")

    # ---------------- ML part: Isolation Forest ----------------
    features = pd.DataFrame({
        "severity": df["severity"], "log_bytes": np.log1p(df["bytes"]),
        "failed_10m": df["failed_10m"], "burst_10m": df["burst_10m"],
        "night": df["night"], "sensitive": df["sensitive"].astype(int),
        "external": df["external_dest"].astype(int),
        "ip_rarity": 1 / ip_count, "pair_rarity": 1 / pair_count,
    })
    if len(df) >= 10:
        model = IsolationForest(n_estimators=200, random_state=42)
        raw = -model.fit(features).score_samples(features)          # bigger = more unusual
        span = raw.max() - raw.min()
        df["ml_score"] = (raw - raw.min()) / span if span > 0 else 0.0
    else:
        df["ml_score"] = 0.5  # too little data for ML, stay neutral

    # ---------------- rule part: explainable behaviour ----------------
    rule = df["severity"] / 5.0
    rule += ((df["etype"] == "successful_login") & (df["failed_10m"] >= 3)) * 0.4
    rule += ((df["etype"] == "failed_login") & (df["failed_10m"] >= 3)) * 0.2
    rule += (df["night"] == 1) * 0.1
    df["rule_score"] = rule.clip(0, 1)
    df["anomaly"] = (0.6 * df["rule_score"] + 0.4 * df["ml_score"]).clip(0, 1).round(3)

    # human-readable reasons ("why was this flagged?")
    def reasons(row):
        r = []
        if row.etype == "failed_login" and row.failed_10m >= 3:
            r.append(f"{int(row.failed_10m)} failed logins from this IP within 10 minutes (possible password guessing)")
        if row.etype == "successful_login" and row.failed_10m >= 3:
            r.append(f"successful login right after {int(row.failed_10m)} failed attempts from the same IP")
        if row.etype == "privilege_change":
            r.append("privilege-related change")
        if row.etype == "discovery":
            r.append("directory / resource discovery activity")
        if row.sensitive and row.etype in ("file_access", "file_download", "outbound_transfer"):
            r.append("touches a sensitive-looking resource (finance / HR / customer data)")
        if row.etype == "file_download" and row.bytes >= 100_000_000:
            r.append(f"large download ({row.bytes / 1e6:.0f} MB)")
        if row.etype == "outbound_transfer":
            size = f" of {row.bytes / 1e6:.0f} MB" if row.bytes else (" described as large" if row.large else "")
            r.append(f"outbound transfer{size}" + (" to an external address" if row.external_dest else ""))
        if row.night:
            r.append("outside normal working hours")
        if row.ml_score >= 0.7:
            r.append("statistically unusual compared with the rest of the log (Isolation Forest)")
        if row.etype == "unknown":
            r.append("unknown event type")
        return r

    df["reasons"] = df.apply(reasons, axis=1)
    df["is_candidate"] = df["anomaly"] >= CANDIDATE_THRESHOLD
    return df
