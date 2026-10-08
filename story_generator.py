"""
MODULE 6 - ATTACK STORY GENERATOR  (works fully offline, no LLM needed)
-----------------------------------------------------------------------
Builds the story from templates that are filled ONLY with values taken from the
detected events (times, counts, IPs, file names). Nothing is invented.

Each sentence is returned together with the ids of the events that prove it,
so the user interface can show "evidence: events #12, #13 ...".
"""


def _hm(e):
    return e["time"][:5]


def _res(e):
    """last word of the action, e.g. 'READ /finance/payroll.xlsx' -> '/finance/payroll.xlsx'"""
    parts = (e["action"] or e["event"]).split()
    return parts[-1] if parts else e["event"]


def _ids(events):
    return [e["id"] for e in events]


def _pattern_name(stages):
    parts = []
    if "Initial Access" in stages or "Authentication" in stages:
        parts.append("unauthorized access")
    if "Privilege Activity" in stages:
        parts.append("privilege misuse")
    if "Resource Access" in stages or "Data Collection" in stages:
        parts.append("sensitive data collection")
    if "Possible Exfiltration" in stages:
        parts.append("data exfiltration")
    elif "Data Transfer" in stages:
        parts.append("data transfer")
    if not parts:
        return "suspicious activity"
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def build_story(events, meta):
    """events: incident events (time-sorted dicts with stage). meta: main_ip, main_user, duration_text."""
    by = lambda t: [e for e in events if e["etype"] == t]
    fails, logins, privs = by("failed_login"), by("successful_login"), by("privilege_change")
    disc, acc, dls, outs = by("discovery"), by("file_access"), by("file_download"), by("outbound_transfer")
    s = []

    s.append((f"Between {_hm(events[0])} and {_hm(events[-1])} ({meta['duration_text']}), {len(events)} related events "
              f"were observed from source {meta['main_ip']} involving account '{meta['main_user']}'.", _ids(events)))
    if fails:
        text = f"{len(fails)} failed login attempt(s) were recorded between {_hm(fails[0])} and {_hm(fails[-1])}"
        later = [l for l in logins if l["timestamp"] >= fails[0]["timestamp"]]
        if later:
            text += f", followed by a successful login from the same source at {_hm(later[0])}."
            s.append((text, _ids(fails) + [later[0]["id"]]))
        else:
            s.append((text + ".", _ids(fails)))
    elif logins:
        s.append((f"A successful login was recorded at {_hm(logins[0])}.", _ids(logins[:1])))
    if privs:
        s.append((f"Privilege-related activity ('{privs[0]['action'] or privs[0]['event']}') was recorded at {_hm(privs[0])}.", _ids(privs)))
    if disc:
        s.append((f"Resource discovery activity ('{disc[0]['action'] or disc[0]['event']}') was seen at {_hm(disc[0])}.", _ids(disc)))
    if acc:
        sens = [e for e in acc if e["sensitive"]]
        text = f"{len(acc)} file-access event(s) followed between {_hm(acc[0])} and {_hm(acc[-1])}"
        if sens:
            text += ", including sensitive-looking resources such as " + ", ".join(sorted({_res(e) for e in sens})[:3])
        s.append((text + ".", _ids(acc)))
    if dls:
        total = sum(e["bytes"] for e in dls) / 1e6
        text = f"{len(dls)} file download(s) were recorded between {_hm(dls[0])} and {_hm(dls[-1])}"
        text += f", about {total:.0f} MB in total." if total > 0 else "."
        s.append((text, _ids(dls)))
    if outs:
        o = outs[-1]
        where = f" to {o['destination']}" if o["destination"] else ""
        ext = " (an external address)" if o["external_dest"] else ""
        size = f" of about {o['bytes'] / 1e6:.0f} MB" if o["bytes"] else ""
        s.append((f"An unusual outbound transfer{size}{where}{ext} was recorded at {_hm(o)}.", _ids(outs)))

    stages = {e["stage"] for e in events}
    s.append((f"Together, these correlated events show a pattern consistent with a potential {_pattern_name(stages)} incident. "
              "This is a SUSPECTED incident produced by automated analysis; it is not a confirmed attack and must be "
              "verified by a security analyst.", []))
    return [{"text": t, "event_ids": i} for t, i in s]
