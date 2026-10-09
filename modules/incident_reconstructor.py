"""
MODULES 5 + 7 - INCIDENT RECONSTRUCTION and EVIDENCE
----------------------------------------------------
Input : the clusters found by the correlator
Output: a list of "possible incidents". For each one we work out:
        start/end, duration, main IP and user, attack stages (in order), the
        most important events, relationship scores, risk score, confidence,
        the attack story and the evidence behind every conclusion.
"""
import hashlib
from collections import Counter, defaultdict

from .attack_stage import (ETYPE_LABEL, STAGE_BY_TYPE, STAGE_ORDER, STAGE_PHRASE,
                           mitre_candidates, refine_stage)
from .confidence import conclusion_confidence, confidence_scores, risk_score
from .event_correlator import EDGE_THRESHOLD, pair_score
from .story_generator import build_story

ATTACH_MINUTES = 10   # look this far before/after the cluster for more related events
ATTACH_SCORE = 0.70   # ... and attach them if they correlate this strongly with a cluster member
MIN_STAGES = 2        # a possible incident must show at least 2 different stages


def duration_text(seconds):
    seconds = int(seconds)
    m, s = divmod(seconds, 60)
    return f"{m} min {s} s" if m else f"{s} s"


def _pair(a, b, counts):
    first, second = (a, b) if a["timestamp"] <= b["timestamp"] else (b, a)
    return pair_score(first, second, counts)


def reconstruct(df, labels):
    """Returns (incidents, annotations). annotations = {event_id: {stage, incident, corr_prev, corr_prev_id}}"""
    rows = df.to_dict("records")
    for r in rows:
        r["time"] = r["timestamp"].strftime("%H:%M:%S")
    by_id = {r["id"]: r for r in rows}
    counts = Counter((r["source_ip"], r["etype"]) for r in rows)

    clusters = defaultdict(list)
    for eid, lab in labels.items():
        if lab >= 0:
            clusters[lab].append(eid)

    incidents, annotations = [], {}
    for lab in sorted(clusters):
        members = set(clusters[lab])
        # ---- attach weaker events that still correlate strongly with the cluster
        t0 = min(by_id[m]["timestamp"] for m in members)
        t1 = max(by_id[m]["timestamp"] for m in members)
        for r in rows:
            if r["id"] in members or r["etype"] not in STAGE_BY_TYPE:
                continue
            if (t0 - r["timestamp"]).total_seconds() > ATTACH_MINUTES * 60 or (r["timestamp"] - t1).total_seconds() > ATTACH_MINUTES * 60:
                continue
            if max(_pair(r, by_id[m], counts)[0] for m in members) >= ATTACH_SCORE:
                members.add(r["id"])
        evs = sorted((by_id[m] for m in members), key=lambda e: (e["timestamp"], e["id"]))

        # ---- attack stage for every event (in time order)
        seen = []
        for e in evs:
            e["stage"] = refine_stage(e["etype"], e["bytes"], e["external_dest"] or e["large"], seen)
            seen.append(e["stage"])
        evs = [e for e in evs if e["stage"]]  # drop events that are not part of the kill chain (e.g. logout)
        stage_names = {e["stage"] for e in evs}
        if len(stage_names) < MIN_STAGES or len(evs) < 3:
            continue

        # ---- chain: relationship score between consecutive events
        chain, chain_scores = [], []
        for a, b in zip(evs, evs[1:]):
            score, parts = _pair(a, b, counts)
            chain.append({"a": a["id"], "b": b["id"], "score": score, "parts": parts})
            chain_scores.append(score)
        # all strong pairs (used by the investigation view)
        edges = []
        for i, a in enumerate(evs):
            for b in evs[i + 1:]:
                score, parts = _pair(a, b, counts)
                if score >= EDGE_THRESHOLD:
                    edges.append({"a": a["id"], "b": b["id"], "score": score, "parts": parts})

        start, end = evs[0]["timestamp"], evs[-1]["timestamp"]
        main_ip = Counter(e["source_ip"] for e in evs).most_common(1)[0][0]
        main_user = Counter(e["user"] for e in evs).most_common(1)[0][0]
        incident_id = "INC-{:%Y%m%d}-{}".format(
            start, hashlib.md5(f"{main_ip}|{main_user}|{start}".encode()).hexdigest()[:4].upper())
        dur = duration_text((end - start).total_seconds())

        conf = confidence_scores(evs, chain_scores)
        stages = []
        for name in STAGE_ORDER:
            ids = [e["id"] for e in evs if e["stage"] == name]
            if ids:
                stages.append({"stage": name, "count": len(ids), "event_ids": ids,
                               "first_time": by_id[ids[0]]["time"][:5]})
        mitre = []
        for tech in mitre_candidates([e["etype"] for e in evs]):
            et = tech["based_on"].split(" x ")[1].replace(" ", "_")
            tech["stage"] = Counter(e["stage"] for e in evs if e["etype"] == et).most_common(1)[0][0]
            mitre.append(tech)

        meta = {"main_ip": main_ip, "main_user": main_user, "duration_text": dur}
        sequence = [STAGE_PHRASE[s["stage"]] for s in stages]
        if "Unauthorized Access Attempts" in sequence and "Account Access" in sequence:
            sequence.remove("Account Access")  # keep the sequence short: attempts + success = unauthorized access
            sequence[sequence.index("Unauthorized Access Attempts")] = "Possible Unauthorized Access"
        key = sorted(evs, key=lambda e: (-e["anomaly"], e["id"]))[:6]
        incident = {
            "incident_id": incident_id, "main_ip": main_ip, "main_user": main_user,
            "start": start.isoformat(), "end": end.isoformat(),
            "start_time": evs[0]["time"], "end_time": evs[-1]["time"], "date": f"{start:%Y-%m-%d}",
            "duration_seconds": int((end - start).total_seconds()), "duration_text": dur,
            "event_ids": [e["id"] for e in evs],
            "key_event_ids": sorted(e["id"] for e in key),
            "stages": stages, "stage_count": len(stages), "sequence": sequence,
            "risk": risk_score(evs, len(stages)), "confidence": conf,
            "mitre": mitre, "chain": chain, "edges": edges,
            "conclusions": build_conclusions(evs, conf["overall"]),
            "story": build_story(evs, meta),
            "graph": build_graph(evs, chain, main_ip, main_user),
        }
        incident["risk_label"] = "High" if incident["risk"] >= 75 else "Medium" if incident["risk"] >= 50 else "Low"
        incidents.append(incident)

        prev = None
        for e in evs:
            annotations[e["id"]] = {"stage": e["stage"], "incident": incident_id,
                                    "corr_prev": None, "corr_prev_id": None}
            if prev is not None:
                c = next(c for c in chain if c["a"] == prev["id"] and c["b"] == e["id"])
                annotations[e["id"]].update(corr_prev=c["score"], corr_prev_id=prev["id"])
            prev = e

    incidents.sort(key=lambda i: -i["risk"])
    return incidents, annotations


# ------------------------------------------------------------------ evidence
def _span_min(events):
    return (events[-1]["timestamp"] - events[0]["timestamp"]).total_seconds() / 60 if events else 0


def build_conclusions(evs, overall):
    """MODULE 7 - every conclusion is listed with the checks (evidence) that support it."""
    by = lambda t: [e for e in evs if e["etype"] == t]
    ids = lambda lst: [e["id"] for e in lst]
    fails, logins, privs = by("failed_login"), by("successful_login"), by("privilege_change")
    acc, dls, outs = by("file_access"), by("file_download"), by("outbound_transfer")
    same_ip = len({e["source_ip"] for e in evs}) == 1
    out = []

    def add(title, checks):
        ok = sum(1 for _, passed, _ in checks if passed)
        out.append({"title": title, "confidence": conclusion_confidence(ok, len(checks), overall),
                    "evidence": [{"text": t, "ok": bool(p), "event_ids": i} for t, p, i in checks]})

    if logins and fails:
        after = [l for l in logins if l["timestamp"] >= fails[0]["timestamp"]]
        add("Possible Unauthorized Access", [
            (f"{len(fails)} failed login attempt(s) from {fails[0]['source_ip']}", len(fails) >= 3, ids(fails)),
            ("Successful login followed the failed attempts", bool(after), ids(after[:1])),
            ("Failures and success target the same account", len({e["user"] for e in fails + logins}) == 1, ids(fails + logins[:1])),
            (f"Failed attempts happened within {max(1, round(_span_min(fails)))} minute(s)", _span_min(fails) <= 10, ids(fails)),
        ])
    if privs:
        after = [p for p in privs if logins and p["timestamp"] >= logins[0]["timestamp"]]
        add("Possible Privilege Activity", [
            (f"Privilege-related event: {privs[0]['event']}", True, ids(privs)),
            ("It happened after a successful login", bool(after), ids(after)),
            ("Same source IP as the login", same_ip, ids(privs + logins[:1])),
        ])
    if acc or dls:
        sens = [e for e in acc + dls if e["sensitive"]]
        mb = sum(e["bytes"] for e in dls) / 1e6
        add("Possible Sensitive Resource Access and Data Collection", [
            (f"{len(acc)} file-access event(s)", len(acc) >= 2, ids(acc)),
            ("Sensitive-looking resources touched (finance / HR / customer data)", bool(sens), ids(sens)),
            (f"{len(dls)} file download(s)" + (f", about {mb:.0f} MB" if mb else ""), len(dls) >= 2, ids(dls)),
            ("Same source IP for all of these events", same_ip, ids(acc + dls)),
        ])
    if outs:
        o = outs[-1]
        add("Possible Data Exfiltration", [
            (f"Large outbound transfer ({o['bytes'] / 1e6:.0f} MB)" if o["bytes"] else "Outbound transfer described as large in the log",
             o["bytes"] >= 100_000_000 or bool(o["large"]), ids(outs)),
            ("Destination is an external address", bool(o["external_dest"]), ids(outs)),
            ("Preceded by file downloads / collection", any(d["timestamp"] <= o["timestamp"] for d in dls), ids(dls)),
            ("Same source IP as the earlier activity", same_ip, ids(outs)),
            (f"All events occurred within {max(1, round(_span_min(evs)))} minute(s)", _span_min(evs) <= 30, ids(evs)),
        ])
    return out


# --------------------------------------------------------------------- graph
def build_graph(evs, chain, main_ip, main_user):
    """MODULE 10 - nodes and links for the relationship graph (IP -> user -> event types)."""
    nodes = [{"id": "ip", "kind": "ip", "label": main_ip, "event_ids": [e["id"] for e in evs]},
             {"id": "user", "kind": "user", "label": main_user, "event_ids": [e["id"] for e in evs]}]
    order = []
    for e in evs:
        if e["etype"] not in order:
            order.append(e["etype"])
    for et in order:
        ids = [e["id"] for e in evs if e["etype"] == et]
        stage = Counter(e["stage"] for e in evs if e["etype"] == et).most_common(1)[0][0]
        nodes.append({"id": et, "kind": "event", "label": ETYPE_LABEL[et], "stage": stage, "event_ids": ids})
    links = [{"source": "ip", "target": "user", "kind": "identity"}]
    for et in order:
        links.append({"source": "ip", "target": et, "kind": "origin"})
        links.append({"source": "user", "target": et, "kind": "origin"})
    by_id = {e["id"]: e for e in evs}
    flows = defaultdict(list)
    for c in chain:
        ta, tb = by_id[c["a"]]["etype"], by_id[c["b"]]["etype"]
        if ta != tb:
            flows[(ta, tb)].append(c["score"])
    for (ta, tb), scores in flows.items():
        links.append({"source": ta, "target": tb, "kind": "flow", "score": round(sum(scores) / len(scores), 2)})
    outs = [e for e in evs if e["etype"] == "outbound_transfer" and e["destination"]]
    if outs:
        nodes.append({"id": "dest", "kind": "dest", "label": outs[-1]["destination"], "event_ids": [e["id"] for e in outs]})
        links.append({"source": "outbound_transfer", "target": "dest", "kind": "flow"})
    return {"nodes": nodes, "links": links}
