/* IncidentLens front-end
   Every page loads the latest analysis from /api/result and draws it.
   SECURITY: log text is only ever put on the page with textContent / createTextNode
   (never innerHTML), so a malicious log line cannot inject HTML or scripts. */
(() => {
  "use strict";

  const STAGES = ["Initial Access", "Authentication", "Privilege Activity", "Discovery",
                  "Resource Access", "Data Collection", "Data Transfer", "Possible Exfiltration"];
  const STAGE_HELP = {
    "Initial Access": "Repeated failed logins can indicate password guessing.",
    "Authentication": "A successful login, especially right after failures, may mean valid credentials were obtained.",
    "Privilege Activity": "Changing privileges can give an account more power than it should have.",
    "Discovery": "Listing directories is a common way to find valuable data.",
    "Resource Access": "Reading sensitive files after gaining access may indicate data gathering.",
    "Data Collection": "Bulk downloads can indicate data being staged for removal.",
    "Data Transfer": "Data leaving the network that was not expected.",
    "Possible Exfiltration": "A large outbound transfer to an external address after data collection is consistent with data leaving the organisation.",
  };

  // ------------------------------------------------------------ tiny helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const pct = x => Math.round(x * 100);
  const stageIdx = s => STAGES.indexOf(s);

  function h(tag, attrs, ...kids) {              // build an HTML element safely
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    }
    for (const kid of kids.flat()) if (kid != null && kid !== false) e.append(kid);
    return e;
  }
  const NS = "http://www.w3.org/2000/svg";
  function sv(tag, attrs, ...kids) {              // build an SVG element
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "text") e.textContent = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    }
    kids.flat().forEach(kid => kid && e.append(kid));
    return e;
  }

  const kpi = (label, value, sub, cls) =>
    h("div", { class: "kpi " + (cls || "") }, h("small", { text: label }), h("b", { text: String(value) }), sub ? h("span", { text: sub }) : null);
  const sevBadge = label => h("span", { class: "badge sev-" + label, text: label });
  const stageBadge = st => st ? h("span", { class: `badge stg stg-${stageIdx(st)}`, text: st }) : h("span", { class: "muted small", text: "not in an incident" });
  const bar = (frac, warn) => h("div", { class: "bar" + (warn ? " warn" : "") }, h("i", { style: `width:${Math.max(0, Math.min(1, frac)) * 100}%` }));
  const evLink = id => h("a", { class: "chip", href: `/investigation?event=${id}`, text: `#${id}` });
  const mb = b => b >= 1e6 ? (b / 1e6).toFixed(b >= 1e8 ? 0 : 1) + " MB" : b >= 1e3 ? (b / 1e3).toFixed(0) + " KB" : b + " B";
  const dotColor = ev => ev.stage ? `var(--s${stageIdx(ev.stage)})` : ev.flagged ? "var(--amber)" : "#46556f";

  let R = null, EV = {};
  const primary = () => (R && R.incidents[0]) || null;

  async function load() {
    const res = await fetch("/api/result");
    if (!res.ok) return false;
    R = await res.json();
    R.events.forEach(e => (EV[e.id] = e));
    return true;
  }

  function showEmpty(msg) {
    const app = $("#app");
    if (!app) return;
    app.replaceChildren(h("div", { class: "panel empty" },
      h("p", { text: msg }),
      h("a", { class: "btn primary", href: "/#upload", text: "Upload logs or use the sample dataset" })));
  }

  // relationships (edges) between events of the reconstructed incidents
  function relatedOf(id) {
    return R.edges.filter(e => e.a === id || e.b === id)
      .map(e => ({ other: e.a === id ? e.b : e.a, score: e.score, parts: e.parts }))
      .sort((x, y) => y.score - x.score);
  }
  const partsText = p => `ip ${p.same_ip} · user ${p.same_user} · time ${p.time} · type ${p.type_relation} · severity ${p.severity} · repeat ${p.repetition} · src/dst ${p.src_dst}`;

  // ------------------------------------------------------- event detail card
  function eventDetail(ev, box, opts = {}) {
    const onSelect = opts.onSelect || (() => {});
    const d = h("div", { class: "detail" });
    d.append(h("h4", { text: `#${ev.id}  ${ev.event}` }),
             h("div", { class: "muted small", text: `${ev.date} ${ev.time} · original line ${ev.order}` }),
             h("div", { style: "margin:8px 0;display:flex;gap:6px;flex-wrap:wrap" }, sevBadge(ev.severity_label), stageBadge(ev.stage)));
    const dl = h("dl", { class: "dl" });
    const row = (k, v) => { if (v !== "" && v != null) dl.append(h("dt", { text: k }), h("dd", { text: String(v) })); };
    row("Source IP", ev.ip); row("User", ev.user); row("Action", ev.action); row("Destination", ev.destination);
    row("Status", ev.status); row("Data size", ev.bytes ? mb(ev.bytes) : ""); row("Incident", ev.incident || "none");
    d.append(dl);
    d.append(h("div", { class: "small muted", text: `Anomaly score ${ev.anomaly.toFixed(2)} (unusual, not proof of malice)` }), bar(ev.anomaly, true));
    if (ev.corr_prev != null)
      d.append(h("div", { class: "small muted", style: "margin-top:8px" }, `Correlation with previous incident event `, evLink(ev.corr_prev_id), ` : ${ev.corr_prev.toFixed(2)}`));

    // Why is this event important?
    d.append(h("h3", { text: "Why is this event important?" }));
    const why = [];
    if (ev.stage) why.push(`Possible stage "${ev.stage}": ${STAGE_HELP[ev.stage]}`);
    ev.reasons.forEach(r => why.push(r[0].toUpperCase() + r.slice(1)));
    if (ev.incident) why.push(`Part of suspected incident ${ev.incident}.`);
    else if (ev.flagged) why.push("Unusual on its own, but not strongly related to other events, so no incident was formed around it.");
    if (!why.length) why.push("No suspicious indicators. This looks like routine activity.");
    d.append(h("ul", {}, why.map(w => h("li", { text: w }))));

    // Which other events are related to it?
    d.append(h("h3", { text: "Which other events are related to it?" }));
    const rel = relatedOf(ev.id).slice(0, opts.extended ? 8 : 5);
    if (!rel.length) d.append(h("p", { class: "muted small", text: "No strong relationships found." }));
    rel.forEach(r => {
      const o = EV[r.other];
      d.append(h("div", { class: "rel", onclick: () => onSelect(o.id) },
        h("span", { class: "sc", text: r.score.toFixed(2) }), h("span", { class: "mono", text: o.time }),
        h("span", { text: `#${o.id} ${o.event}` })));
      if (opts.extended) d.append(h("div", { class: "parts", style: "margin:-2px 0 6px 6px", text: partsText(r.parts) }));
    });

    if (opts.extended) {
      const near = R.events.filter(e => e.id !== ev.id && (e.ip === ev.ip || e.user === ev.user));
      const list = (title, items) => {
        d.append(h("h3", { text: title }));
        if (!items.length) d.append(h("p", { class: "muted small", text: "None." }));
        items.forEach(o => d.append(h("div", { class: "rel", onclick: () => onSelect(o.id) },
          h("span", { class: "mono", text: o.time }), h("span", { text: `#${o.id} ${o.event}` }),
          h("span", { class: "muted small", text: o.ip }))));
      };
      list("Previous events (same IP or user)", near.filter(e => e.id < ev.id).slice(-4));
      list("Next events (same IP or user)", near.filter(e => e.id > ev.id).slice(0, 4));
      d.append(h("h3", { text: "Scores" }),
        h("dl", { class: "dl" }, h("dt", { text: "Anomaly" }), h("dd", { text: ev.anomaly.toFixed(3) }),
          h("dt", { text: "ML (Isolation Forest)" }), h("dd", { text: ev.ml_score.toFixed(3) }),
          h("dt", { text: "Severity" }), h("dd", { text: `${ev.severity}/5 (${ev.severity_label})` }),
          h("dt", { text: "Sensitive path" }), h("dd", { text: ev.sensitive ? "yes" : "no" }),
          h("dt", { text: "External destination" }), h("dd", { text: ev.external_dest ? "yes" : "no" })));
    }
    box.replaceChildren(d);
  }

  // ------------------------------------------------------------ ANALYSIS page
  function pageAnalysis() {
    const m = R.meta, inc = primary();
    const steps = [
      ["Preprocessing", `${m.valid_events} valid of ${m.rows_read} rows. ${m.duplicates_removed} duplicate(s), ${m.invalid_timestamps} bad timestamp(s) removed.`],
      ["Anomaly detection", `Isolation Forest + rules flagged ${m.flagged_events} unusual events.`],
      ["Event correlation", `${m.relationships} relationships scored (7 factors), DBSCAN clustering.`],
      ["Incident reconstruction", `${R.incidents.length} possible incident(s) found.`],
      ["Stage classification", inc ? `${inc.stage_count} possible stages in the main incident.` : "No stages (no incident)."],
      ["Explanation", "Story generated only from detected events."],
    ];
    $("#pipeline").replaceChildren(...steps.map(([t, s]) => h("div", { class: "pstep" }, h("b", { text: t }), h("span", { text: s }))));
    $("#kpis").replaceChildren(
      kpi("Rows read", m.rows_read), kpi("Valid events", m.valid_events, "after cleaning", "good"),
      kpi("Duplicates removed", m.duplicates_removed), kpi("Invalid timestamps", m.invalid_timestamps),
      kpi("Unknown event types", m.unknown_event_types), kpi("Unusual events", m.flagged_events, "anomaly >= " + m.candidate_threshold, "cy"),
      kpi("Incidents", R.incidents.length, "suspected", R.incidents.length ? "hot" : ""));

    const top = [...R.events].sort((a, b) => b.anomaly - a.anomaly).slice(0, 12);
    const tbl = h("table", { class: "table" }, h("thead", {}, h("tr", {}, ...["Time", "Event", "IP", "User", "Severity", "Anomaly", "Why flagged", "Status"].map(t => h("th", { text: t })))));
    const body = h("tbody");
    top.forEach(e => body.append(h("tr", { class: "click", onclick: () => (location.href = `/investigation?event=${e.id}`) },
      h("td", { class: "mono", text: e.time }), h("td", { text: e.event }), h("td", { class: "mono", text: e.ip }), h("td", { text: e.user }),
      h("td", {}, sevBadge(e.severity_label)), h("td", {}, bar(e.anomaly, true), h("span", { class: "small mono", text: e.anomaly.toFixed(2) })),
      h("td", { class: "small", text: e.reasons.join("; ") || "-" }),
      h("td", { class: "small", text: e.incident ? "In incident " + e.incident : e.flagged ? "Unusual, not correlated" : "Normal" }))));
    tbl.append(body);
    $("#top-events").replaceChildren(tbl);

    $("#notes-panel").replaceChildren(h("h2", { text: "Notes" }),
      h("p", { class: "muted", text: m.notes[0] || "-" }),
      h("p", { class: "muted", text: "An anomaly score only says an event is unusual compared with the rest of this file. It does not prove malicious activity; correlation with other events is what turns anomalies into a suspected incident." }));

    const canvas = $("#chart");
    const draw = () => drawChart(canvas, R.events, m.candidate_threshold);
    draw();
    window.addEventListener("resize", draw);
  }

  function drawChart(canvas, events, thr) {
    const dpr = window.devicePixelRatio || 1, W = canvas.clientWidth, H = 260;
    canvas.width = W * dpr; canvas.height = H * dpr;
    const c = canvas.getContext("2d"); c.scale(dpr, dpr); c.clearRect(0, 0, W, H);
    const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
    const L = 40, Rr = 14, T = 12, B = 28;
    const tms = e => Date.parse(`${e.date}T${e.time}`);
    const t0 = Math.min(...events.map(tms)), t1 = Math.max(...events.map(tms)) || t0 + 1;
    const X = t => L + ((t - t0) / Math.max(1, t1 - t0)) * (W - L - Rr), Y = v => T + (1 - v) * (H - T - B);
    c.font = "11px Consolas, monospace"; c.fillStyle = css("--muted"); c.strokeStyle = css("--line");
    for (let v = 0; v <= 1.001; v += 0.25) { c.beginPath(); c.moveTo(L, Y(v)); c.lineTo(W - Rr, Y(v)); c.stroke(); c.fillText(v.toFixed(2), 4, Y(v) + 4); }
    for (let i = 0; i <= 5; i++) {
      const t = t0 + (i / 5) * (t1 - t0), d = new Date(t);
      c.fillText(d.toTimeString().slice(0, 5), Math.min(X(t) - 14, W - 44), H - 8);
    }
    c.setLineDash([5, 4]); c.strokeStyle = css("--amber"); c.beginPath(); c.moveTo(L, Y(thr)); c.lineTo(W - Rr, Y(thr)); c.stroke(); c.setLineDash([]);
    c.fillStyle = css("--amber"); c.fillText("flag threshold", W - 100, Y(thr) - 4);
    const pts = events.map(e => ({ e, x: X(tms(e)), y: Y(e.anomaly) }));
    [["normal", "#4a5a78"], ["flag", css("--amber")], ["inc", css("--red")]].forEach(([kind, col]) => {
      pts.filter(p => (p.e.incident ? "inc" : p.e.flagged ? "flag" : "normal") === kind).forEach(p => {
        c.beginPath(); c.arc(p.x, p.y, kind === "inc" ? 5 : 4, 0, 6.3); c.fillStyle = col; c.globalAlpha = kind === "normal" ? 0.7 : 1; c.fill(); c.globalAlpha = 1;
      });
    });
    const info = $("#chart-info");
    canvas.onmousemove = ev => {
      const r = canvas.getBoundingClientRect(), mx = ev.clientX - r.left, my = ev.clientY - r.top;
      const hit = pts.find(p => Math.hypot(p.x - mx, p.y - my) < 8);
      canvas.style.cursor = hit ? "pointer" : "default";
      info.textContent = hit ? `#${hit.e.id} ${hit.e.time} ${hit.e.event} | ${hit.e.ip} | ${hit.e.user} | anomaly ${hit.e.anomaly.toFixed(2)}` : " ";
    };
    canvas.onclick = ev => {
      const r = canvas.getBoundingClientRect(), mx = ev.clientX - r.left, my = ev.clientY - r.top;
      const hit = pts.find(p => Math.hypot(p.x - mx, p.y - my) < 8);
      if (hit) location.href = `/investigation?event=${hit.e.id}`;
    };
  }

  // ------------------------------------------------------------ INCIDENT page
  function pageIncident() {
    const inc = primary();
    if (!inc) {
      $("#banner").replaceChildren(h("div", { class: "banner", text: "No correlated incident was found. The unusual events (if any) were not strongly related to each other." }));
      $("#others").replaceChildren(isolatedTable());
      return;
    }
    $("#banner").replaceChildren(h("div", { class: "banner", text: "SUSPECTED incident, reconstructed automatically from log correlation. It is a potential incident and is NOT a confirmed attack." }));
    $("#kpis").replaceChildren(
      kpi("Incident ID", inc.incident_id, `${inc.date}`, "cy"), kpi("Duration", inc.duration_text, `${inc.start_time} - ${inc.end_time}`),
      kpi("Risk score", inc.risk + "/100", inc.risk_label, "hot"), kpi("Confidence", inc.confidence.overall + "%", "analytical estimate", "good"),
      kpi("Attack stages", inc.stage_count), kpi("Main IP", inc.main_ip), kpi("Main user", inc.main_user), kpi("Events", inc.event_ids.length));

    const seq = [];
    inc.sequence.forEach((s, i) => { if (i) seq.push(h("i", { text: "→" })); seq.push(h("span", { text: s })); });
    $("#sequence").replaceChildren(...seq);

    $("#story").replaceChildren(...inc.story.map((s, i) => {
      const p = h("p", { class: i === inc.story.length - 1 ? "story-last" : "" }, s.text);
      s.event_ids.slice(0, 4).forEach(id => p.append(evLink(id)));
      if (s.event_ids.length > 4) p.append(h("span", { class: "muted small", text: ` +${s.event_ids.length - 4} more` }));
      return p;
    }), h("p", { class: "muted small", text: "Every sentence is built only from detected events. The #numbers open the supporting events." }));

    $("#stages").replaceChildren(...inc.stages.map(s => {
      const techs = inc.mitre.filter(m => m.stage === s.stage);
      return h("div", { class: "stage", style: `border-left-color:var(--s${stageIdx(s.stage)})` },
        h("b", { class: "stg-" + stageIdx(s.stage), text: s.stage }), h("small", { text: `${s.count} event(s) · first at ${s.first_time}` }),
        ...techs.map(t => h("div", { class: "small", title: "Candidate technique, verify manually", text: `${t.id} ${t.name}` })));
    }));
    renderGraph(inc);

    const others = h("div");
    R.incidents.slice(1).forEach(o => others.append(h("p", { text: `Another possible incident ${o.incident_id}: ${o.sequence.join(" → ")} (risk ${o.risk}, confidence ${o.confidence.overall}%).` })));
    others.append(isolatedTable());
    $("#others").replaceChildren(others);
  }

  function isolatedTable() {
    const ids = R.isolated_ids;
    if (!ids.length) return h("p", { class: "muted", text: "No other unusual events needing review." });
    const body = h("tbody");
    ids.forEach(id => { const e = EV[id]; body.append(h("tr", { class: "click", onclick: () => (location.href = `/investigation?event=${id}`) },
      h("td", { class: "mono", text: e.time }), h("td", { text: e.event }), h("td", { class: "mono", text: e.ip }), h("td", { text: e.user }),
      h("td", { class: "small", text: e.reasons.join("; ") }))); });
    return h("div", {}, h("p", { class: "muted small", text: "Unusual events that did NOT correlate with an attack sequence (shown for review; anomaly is not the same as malicious):" }),
      h("table", { class: "table" }, h("thead", {}, h("tr", {}, ...["Time", "Event", "IP", "User", "Why flagged"].map(t => h("th", { text: t })))), body));
  }

  function renderGraph(inc) {
    const svgEl = $("#graph"), g = inc.graph, W = 1000;
    svgEl.replaceChildren();
    const evNodes = g.nodes.filter(n => n.kind === "event"), k = evNodes.length, pad = 80;
    const step = k > 1 ? (W - 2 * pad) / (k - 1) : 0, bw = Math.min(150, step * 1.9 || 150), bh = 46;
    const pos = {};
    evNodes.forEach((n, i) => (pos[n.id] = { x: k > 1 ? pad + i * step : W / 2, y: i % 2 === 0 ? 230 : 316 }));
    pos.ip = { x: 130, y: 62 }; pos.user = { x: 370, y: 62 }; pos.dest = { x: 880, y: 62 };
    const nodeById = Object.fromEntries(g.nodes.map(n => [n.id, n]));
    const color = n => n.kind === "ip" ? "var(--cyan)" : n.kind === "user" ? "var(--purple)" : n.kind === "dest" ? "var(--red)" : `var(--s${stageIdx(n.stage)})`;
    const linkEls = [];
    const order = { origin: 0, identity: 1, flow: 2 };
    [...g.links].sort((a, b) => order[a.kind] - order[b.kind]).forEach(l => {
      const a = pos[l.source], b = pos[l.target];
      const line = sv("line", { class: "link " + l.kind, x1: a.x, y1: a.y, x2: b.x, y2: b.y });
      svgEl.append(line); linkEls.push({ l, line });
    });
    g.links.filter(l => l.kind === "flow" && l.score != null).forEach(l => {
      const a = pos[l.source], b = pos[l.target], mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      svgEl.append(sv("g", { class: "score" }, sv("rect", { x: mx - 20, y: my - 9, width: 40, height: 18, rx: 4 }), sv("text", { x: mx, y: my + 4, text: l.score.toFixed(2) })));
    });
    const detail = $("#graph-detail");
    g.nodes.forEach(n => {
      const p = pos[n.id], w = n.kind === "event" ? bw : 150;
      const sub = n.kind === "event" ? `${n.stage.length > 17 ? n.stage.slice(0, 16) + "\u2026" : n.stage} · ${n.event_ids.length}x` : n.kind === "ip" ? "source IP" : n.kind === "user" ? "account" : "destination";
      const node = sv("g", { class: "node", tabindex: "0",
        onmouseenter: () => linkEls.forEach(({ l, line }) => line.classList.toggle("hl", l.source === n.id || l.target === n.id)),
        onmouseleave: () => linkEls.forEach(({ line }) => line.classList.remove("hl")),
        onclick: () => {
          detail.replaceChildren(h("b", { text: `${n.label}: ` }), ...n.event_ids.map(id => h("a", { class: "chip", href: `/investigation?event=${id}`, title: EV[id].event, text: `#${id} ${EV[id].time.slice(0, 5)} ${EV[id].event}` })));
        } },
        sv("rect", { x: p.x - w / 2, y: p.y - bh / 2, width: w, height: bh, rx: 9, stroke: color(n) }),
        sv("text", { x: p.x, y: p.y - 3, text: n.label.length > 20 ? n.label.slice(0, 19) + "…" : n.label }),
        sv("text", { class: "sub", x: p.x, y: p.y + 13, text: sub }));
      svgEl.append(node);
    });
  }

  // ------------------------------------------------------------ TIMELINE page
  function pageTimeline() {
    const list = $("#timeline"), box = $("#detail");
    let selected = null;
    const select = id => {
      selected = id;
      document.querySelectorAll(".tl").forEach(n => n.classList.toggle("sel", Number(n.dataset.id) === id));
      eventDetail(EV[id], box, { onSelect: select });
    };
    const draw = () => {
      const scope = $('input[name="scope"]:checked').value;
      const evs = R.events.filter(e => scope === "all" || (scope === "flagged" ? e.flagged || e.incident : e.incident));
      list.replaceChildren(...evs.map(e => h("div", { class: "tl" + (e.incident ? "" : " dim"), "data-id": e.id, style: `--dot:${dotColor(e)}`, onclick: () => select(e.id) },
        h("div", { class: "t" }, h("b", { text: e.time }), `#${e.id}`),
        h("div", {}, h("b", { text: e.event }), h("span", { class: "muted small", text: e.action ? "  " + e.action : "" }),
          h("div", { class: "meta" }, h("span", { class: "mono", text: e.ip }), h("span", { text: e.user }), sevBadge(e.severity_label), stageBadge(e.stage),
            e.corr_prev != null ? h("span", { class: "mono", style: "color:var(--cyan)", text: `corr ${e.corr_prev.toFixed(2)}` }) : null)))));
      if (!evs.length) list.append(h("p", { class: "muted", text: "No events in this view." }));
      else if (selected == null || !evs.some(e => e.id === selected)) select(evs[0].id);
      else select(selected);
    };
    document.querySelectorAll('input[name="scope"]').forEach(r => r.addEventListener("change", draw));
    draw();
  }

  // ------------------------------------------------------------ EVIDENCE page
  function pageEvidence() {
    const inc = primary();
    if (!inc) return showEmpty("No incident was reconstructed, so there is no evidence to explain.");
    $("#conclusions").replaceChildren(...inc.conclusions.map(c => h("section", { class: "concl" },
      h("div", { class: "concl-head" }, h("div", {}, h("small", { class: "muted", text: "CONCLUSION" }), h("h3", { text: c.title })),
        h("div", {}, h("small", { class: "muted", text: "CONFIDENCE " }), h("span", { class: "cf", text: c.confidence + "%" }))),
      h("small", { class: "muted", text: "SUPPORTING EVIDENCE" }),
      h("ul", { class: "ev-ok" }, c.evidence.map(e => h("li", { class: e.ok ? "ok" : "no" },
        h("span", { class: "tick", text: e.ok ? "✓" : "✗" }), e.text, ...e.event_ids.slice(0, 5).map(evLink),
        e.event_ids.length > 5 ? h("span", { class: "muted small", text: ` +${e.event_ids.length - 5}` }) : null))))));
    const cf = inc.confidence, row = (label, v) => h("div", { class: "cbar" }, h("span", { text: label }), bar(v / 100), h("b", { text: v + "%" }));
    $("#confidence").replaceChildren(h("h2", { text: "Confidence score" }),
      row("Evidence strength", cf.evidence_strength), row("Event correlation", cf.event_correlation), row("Sequence consistency", cf.sequence_consistency),
      h("div", { style: "margin-top:10px" }, h("small", { class: "muted", text: "OVERALL CONFIDENCE" }), h("div", { class: "overall", text: cf.overall + "%" })),
      h("p", { class: "muted small", text: "Overall = 40% evidence + 30% correlation + 30% sequence, capped at 95%." }),
      h("div", { class: "banner", text: cf.disclaimer }));
  }

  // ---------------------------------------------------------- INVESTIGATION page
  function pageInvestigation() {
    const listBox = $("#list"), detail = $("#detail"), search = $("#search"), filter = $("#filter");
    const wanted = Number(new URLSearchParams(location.search).get("event"));
    let selected = null;
    const select = id => {
      selected = id;
      document.querySelectorAll(".evrow").forEach(n => n.classList.toggle("sel", Number(n.dataset.id) === id));
      eventDetail(EV[id], detail, { onSelect: select, extended: true });
      const n = $(`.evrow[data-id="${id}"]`); if (n) n.scrollIntoView({ block: "nearest" });
    };
    const draw = () => {
      const q = search.value.trim().toLowerCase(), f = filter.value;
      let evs = R.events.filter(e => f === "all" || (f === "flagged" ? e.flagged || e.incident : e.incident));
      if (f === "all") evs = [...evs].sort((a, b) => a.order - b.order);   // original file order
      if (q) evs = evs.filter(e => `${e.ip} ${e.user} ${e.event} ${e.action}`.toLowerCase().includes(q));
      listBox.replaceChildren(...evs.map(e => h("div", { class: "evrow", "data-id": e.id, onclick: () => select(e.id) },
        h("span", { class: "mono", text: e.time }), h("span", {}, `#${e.id} ${e.event} `, h("span", { class: "muted small", text: `${e.ip} ${e.user}` })), sevBadge(e.severity_label))));
      if (!evs.length) listBox.append(h("p", { class: "muted", text: "No matching events." }));
      if (selected != null) select(selected);
    };
    search.addEventListener("input", draw); filter.addEventListener("change", draw);
    if (EV[wanted] && !EV[wanted].incident) filter.value = "all";
    draw();
    const inc = primary();
    select(EV[wanted] ? wanted : inc ? inc.event_ids[0] : (R.events[0] || {}).id);
  }

  // ------------------------------------------------------------------- start
  async function start() {
    const page = document.body.dataset.page;
    const printBtn = $("#print-btn");
    if (printBtn) printBtn.addEventListener("click", () => window.print());
    const pages = { analysis: pageAnalysis, incident: pageIncident, timeline: pageTimeline, evidence: pageEvidence, investigation: pageInvestigation };
    if (!pages[page]) return;
    let ok = false;
    try { ok = await load(); } catch (e) { ok = false; }
    if (!ok) return showEmpty("No analysis yet. Upload a log file or try the sample dataset first.");
    pages[page]();
  }
  start();
})();
