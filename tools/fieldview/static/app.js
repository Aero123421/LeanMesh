"use strict";
// LeanMesh field view: polls /api/state once a second and draws it. No external resources; text goes in as text.
const $ = (id) => document.getElementById(id);
const NS = "http://www.w3.org/2000/svg";

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") e.className = v; else if (k === "title") e.title = v; else e.setAttribute(k, v);
  }
  for (const k of kids.flat()) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}
function s(tag, attrs, ...kids) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) e.setAttribute(k, v);
  for (const k of kids) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}
const fmt = (v, d = "-") => (v === null || v === undefined ? d : v);
const pct = (v) => (v === null || v === undefined ? "-" : v.toFixed(v < 10 ? 1 : 0) + " %");
const age = (v) => (v === null || v === undefined ? "-" : v < 120 ? v.toFixed(0) + " s" : (v / 60).toFixed(1) + " min");
const utcShort = (t) => (t ? t.slice(11, 19) : "-");

async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json", "X-Fieldview": "1" }, body: JSON.stringify(body) };
  const r = await fetch(path, opt);
  let doc = {};
  try { doc = await r.json(); } catch (e) { /* no body */ }
  if (!r.ok) throw new Error(doc.error || ("HTTP " + r.status));
  return doc;
}

let last = null;
let displaySelected = null;

// ---- topology -----------------------------------------------------------------------------------------------------
const X = 118, Y = 96, BW = 104, BH = 38;

function layout(root) {
  let slot = 0;
  (function place(n, level) {
    n.level = level;
    if (!n.children.length) { n.x = slot++; return; }
    n.children.forEach((c) => place(c, level + 1));
    n.x = (n.children[0].x + n.children[n.children.length - 1].x) / 2;
  })(root, 0);
  return slot;
}
function nodesOf(n, out = []) { out.push(n); n.children.forEach((c) => nodesOf(c, out)); return out; }

function drawTopology(tree) {
  const root = tree.root;
  const slots = Math.max(1, layout(root));
  const all = nodesOf(root);
  const levels = Math.max(...all.map((n) => n.level)) + 1;
  const W = Math.max(360, slots * X + 20), H = levels * Y + 10;
  const svg = s("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: "img" });
  const px = (n) => 10 + n.x * X + X / 2 - 10, py = (n) => 10 + n.level * Y;
  const linkLayer = s("g"), nodeLayer = s("g");
  svg.append(linkLayer, nodeLayer);
  for (const n of all) {
    for (const c of n.children) {
      const x1 = px(n), y1 = py(n) + BH, x2 = px(c), y2 = py(c), my = (y1 + y2) / 2;
      const q = n.group || n.root && c.group ? "unknown" : c.quality;
      linkLayer.append(s("path", { class: "link " + q, d: `M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}` }));
      if (!c.group && !n.group) {
        const label = [c.rssi !== null && c.rssi !== undefined ? c.rssi + " dBm" : null,
                       c.loss_pct !== null && c.loss_pct !== undefined ? "loss " + c.loss_pct.toFixed(0) + "%" : null]
          .filter(Boolean).join("  ");
        if (label) linkLayer.append(s("text", { class: "sub link-label", x: x2, y: y2 - 6, "text-anchor": "middle" }, label));
      }
    }
  }
  for (const n of all) {
    const cls = ["node", n.root ? "root" : "", n.group ? "group" : "", n.placeholder ? "placeholder" : "",
                 n.lost ? "lost" : "", n.silent && !n.lost && !n.root && !n.group ? "silent" : "",
                 n.membership && n.membership !== "ACTIVE" ? "left" : ""].join(" ");
    const g = s("g", { class: cls, transform: `translate(${px(n) - BW / 2},${py(n)})` });
    const tip = [n.name, n.short, n.role && "role " + n.role, n.depth != null && "depth " + n.depth,
                 n.membership, n.connectivity, n.silent && !n.root && !n.group ? "no live telemetry" : null,
                 n.placeholder ? "parent not listed by the Host" : null].filter(Boolean).join("\n");
    g.append(s("title", {}, tip), s("rect", { width: BW, height: BH, rx: 7 }));
    g.append(s("text", { x: BW / 2, y: 16, "text-anchor": "middle" }, n.name.length > 15 ? n.name.slice(0, 14) + "…" : n.name));
    const sub = n.root ? "root" : n.group ? "" : [n.role, n.depth != null ? "d" + n.depth : null].filter(Boolean).join(" ");
    g.append(s("text", { class: "sub", x: BW / 2, y: 30, "text-anchor": "middle" }, sub));
    nodeLayer.append(g);
  }
  $("topo").replaceChildren(svg);
  $("topo-note").textContent = tree.has_parent_info
    ? "Parent links come from the Host (parent_device_id). Colour: the child's parent RSSI and telemetry loss."
    : "The Host reports no parent_device_id: every node hangs under \"parent unknown\" (an older Host).";
}

// ---- header / warnings --------------------------------------------------------------------------------------------
function drawHeader(st) {
  const hst = st.host;
  const chips = [
    h("span", { class: "chip " + (hst.ok ? "good" : "bad") }, hst.ok ? "Host reachable" : "Host not reachable"),
    h("span", { class: "chip " + (hst.root_connected ? "good" : "bad") }, hst.root_connected ? "root connected" : "root not connected"),
    h("span", { class: "chip" }, `${st.nodes.length} nodes`),
    h("span", { class: "chip", title: "events read: before this session / since" }, `events ${hst.backlog_events} + ${hst.live_events}`),
    h("span", { class: "chip", title: "requests the laptop made / answered 429" }, `requests ${hst.requests} (429: ${hst.rate_limited})`),
    h("span", { class: "chip" }, "UTC " + utcShort(st.now)),
  ];
  $("chips").replaceChildren(...chips);
  const w = $("warnings");
  w.hidden = st.warnings.length === 0;
  w.replaceChildren(...st.warnings.map((t) => h("div", {}, "⚠ " + t)));
  $("foot").textContent = `session started ${st.started} UTC · records: ${st.logs} · domain ${st.domain} · ` +
    `telemetry interval assumed ${st.interval_assumed_s} s · cursor ${fmt(hst.cursor)}`;
}

// ---- table --------------------------------------------------------------------------------------------------------
function td(content, cls, title) { return h("td", { class: cls, title }, content); }

// node log (§3.4) cells: what the node itself recorded about its boot and attach
function bootTitle(n) {
  const parts = [];
  if (n.boot_detail) parts.push(n.boot_detail);
  parts.push(`boots in the node log: ${n.boots_logged}, SDK restarts: ${n.sdk_restarts}`);
  if (n.log_records) parts.push(`records ${n.log_records}, missing ${n.records_lost}, dropped by the node ${n.log_lost}`);
  return parts.join("\n");
}
function attachTitle(n) {
  const t = (v) => (v === null || v === undefined ? "-" : v.toFixed(1) + " s");
  return `after boot: member ${t(n.member_s)}, reachable ${t(n.attach_s)}, root time valid ${t(n.time_valid_s)}` +
    `\nunreachable events: ${n.unreachable}`;
}

function drawNodes(st) {
  const rows = st.nodes.map((n) => {
    const p = n.ping, lastKind = p.last ? p.last.kind : null;
    const answered = p.alive + p.noanswer + p.rejected;
    const rtt = p.rtt_median_ms === null ? "" : ` · ${p.rtt_median_ms.toFixed(0)} ms` +
      (p.last && p.last.rtt_src === "laptop" ? "*" : "");
    const dots = h("span", { class: "dots" }, p.history.map((k) => h("span", { class: k, title: k })));
    const extra = [["not sent", p.notsent], ["unknown", p.unknown], ["skipped", p.skipped], ["late", p.late]]
      .filter(([, n]) => n).map(([k, n]) => ` · ${k} ${n}`).join("");
    const pingCell = p.sent + p.notsent + p.unknown + p.skipped === 0 ? "-" : [
      h("span", { class: lastKind ? "r-" + lastKind : "" }, `${p.alive}/${p.sent}`),
      ` lost ${pct(p.loss_pct)}${rtt}`, extra, " ", dots];
    const dsp = n.display_state === null || n.display_state === undefined ? "-" :
      `${n.display_state} #${fmt(n.display_seq)}${n.render_fault ? " FAULT" : ""}`;
    const q = n.recent_loss_pct;
    return h("tr", { class: "st-" + n.state },
      td(n.name, "", n.device), td(fmt(n.chip)), td(fmt(n.role)),
      td(h("span", { class: "pill " + n.state }, n.state), "", n.state === "silent" ? "listed, no telemetry" : ""),
      td(`${fmt(n.membership)} / ${fmt(n.connectivity)}`), td(fmt(n.depth), "num"), td(fmt(n.parent)),
      td(n.rssi_dbm === null || n.rssi_dbm === undefined ? "-" : n.rssi_dbm + " dBm", "num"),
      td(age(n.age_s), "num"),
      td(n.received + n.lost === 0 ? "-" : `${pct(n.loss_pct)} (${n.lost}/${n.received + n.lost})` +
         (q === null || q === undefined ? "" : ` · recent ${pct(q)}`), "num"),
      td(`${n.reboots}` + (n.boot_count === null ? "" : ` (#${n.boot_count})`), "num"),
      td(fmt(n.boot_cause), n.sdk_restarts ? "warn" : "", bootTitle(n)),
      td(n.attach_s === null || n.attach_s === undefined ? "-" : n.attach_s.toFixed(1) + " s", "num", attachTitle(n)),
      td(n.tx_done_max_ms === null || n.tx_done_max_ms === undefined ? "-" : `${n.tx_done_max_ms} ms` +
         (n.tx_late ? ` (${n.tx_late} late)` : ""), "num" + (n.tx_late ? " warn" : ""),
         n.tx_stall_waits ? `${n.tx_stall_waits} stall wait(s)` : ""),
      td(n.tx_frames === null && n.rx_frames === null ? "-" : `tx ${fmt(n.tx_frames)} rx ${fmt(n.rx_frames)} rf ${fmt(n.rf_failures)} busy ${fmt(n.local_busy)}`, "",
         n.min_heap_bytes ? "min heap " + n.min_heap_bytes + " B" : ""),
      td(pingCell, "", `answered ${answered}, no answer ${p.noanswer} (late answers ${p.late}), rejected ${p.rejected}, ` +
         `not sent ${p.notsent}, unknown ${p.unknown}, skipped (busy) ${p.skipped}` +
         (p.last ? `\nlast: ${p.last.kind} ${p.last.detail}` : "")),
      td(dsp));
  });
  $("nodes").tBodies[0].replaceChildren(...rows);
}

// ---- ping ---------------------------------------------------------------------------------------------------------
function drawPing(st) {
  const p = st.ping;
  $("ping-status").textContent = (p.running ? `Loop running every ${p.interval_s} s. ` : "Loop stopped. ") +
    `${p.nodes} ACTIVE node(s), round ${p.round}, ${p.open} operation(s) open` +
    (p.running ? ` (at most ${p.open_max}; a node with 3 open pings is skipped). ` : ". ") +
    "RTT marked * is measured by the laptop (the Host gave no root time).";
  $("ping-start").disabled = p.running; $("ping-stop").disabled = !p.running;
  const rows = [...p.rounds].reverse().map((r) => h("tr", {},
    td(r.round), td(utcShort(r.t)), td(r.nodes), td(r.alive, "r-alive"), td(r.noanswer, "r-noanswer"),
    td(r.rejected, "r-rejected"), td(r.notsent, "r-notsent"), td(r.unknown, "r-unknown"), td(r.skipped, "r-skipped"),
    td(r.late, "r-late"), td(r.open)));
  $("rounds").tBodies[0].replaceChildren(...rows);
}

// ---- display ------------------------------------------------------------------------------------------------------
function drawDisplay(st) {
  const sel = $("display-node");
  const have = [...sel.options].map((o) => o.value).join(",");
  const want = st.display_nodes.map((d) => d.device).join(",");
  if (have !== want) {
    sel.replaceChildren(...st.display_nodes.map((d) => h("option", { value: d.device }, d.name)));
    if (displaySelected && want.split(",").includes(displaySelected)) sel.value = displaySelected;
  }
  displaySelected = sel.value || null;
  $("display-usable").disabled = $("display-forbid").disabled = !displaySelected;
  const box = $("display-result");
  if (!displaySelected) { box.textContent = "No display node reported yet (telemetry role 3)."; return; }
  const row = st.nodes.find((n) => n.device === displaySelected) || {};
  const cmd = st.display[displaySelected];
  const mark = (ok, ms) => (ok ? "✓" + (ms !== null && ms !== undefined ? ` ${ms} ms` : "") : "…");
  const lines = [];
  lines.push(h("div", {}, "Reported by the display: ", h("b", {}, row.display_state === null || row.display_state === undefined ? "no state" : row.display_state),
    row.display_seq ? ` (command #${row.display_seq})` : "", row.render_fault ? " · RENDER FAULT" : ""));
  if (cmd) {
    const match = cmd.state === row.display_state && cmd.seq === row.display_seq;
    lines.push(h("div", {}, `Last command: ${cmd.state} #${cmd.seq} sent ${utcShort(cmd.posted)} UTC`));
    lines.push(h("div", {}, "arrived (END_RECEIVED) ", mark(cmd.arrived, cmd.arrived_ms), " · drawn (APP_APPLIED) ", mark(cmd.drawn, cmd.drawn_ms),
      " · result ", h("b", { class: cmd.result === "drawn" ? "r-alive" : cmd.result === "pending" ? "" : "r-noanswer" }, cmd.result),
      cmd.detail ? " " + cmd.detail : "", cmd.late_result ? ` · later the Host showed it ${cmd.late_result}` : ""));
    lines.push(h("div", { class: "note" }, match ? "The telemetry flags show this command." : "The telemetry flags do not show this command (yet)."));
  }
  box.replaceChildren(...lines);
}

// ---- log ----------------------------------------------------------------------------------------------------------
function drawLog(st) {
  const box = $("log");
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 30;
  box.replaceChildren(...st.events.map((e) => h("div", {}, utcShort(e.t) + " ", h("span", { class: "k k-" + e.kind }, e.kind), e.text)));
  if (atBottom) box.scrollTop = box.scrollHeight;
}

function draw(st) {
  last = st;
  drawHeader(st); drawTopology(st.tree); drawNodes(st); drawPing(st); drawDisplay(st); drawLog(st);
}

async function tick() {
  try { draw(await api("/api/state")); }
  catch (e) { $("chips").replaceChildren(h("span", { class: "chip bad" }, "fieldview not answering: " + e.message)); }
}

function showError(id, e) { const b = $(id); b.hidden = !e; b.textContent = e ? e.message : ""; }

$("ping-now").onclick = async () => { try { showError("ping-error"); await api("/api/ping/now", {}); } catch (e) { showError("ping-error", e); } tick(); };
$("ping-start").onclick = async () => {
  try { showError("ping-error"); await api("/api/ping/loop", { action: "start", interval_s: parseFloat($("ping-interval").value) }); }
  catch (e) { showError("ping-error", e); } tick();
};
$("ping-stop").onclick = async () => { try { await api("/api/ping/loop", { action: "stop" }); } catch (e) { showError("ping-error", e); } tick(); };
for (const [id, state] of [["display-usable", "USABLE"], ["display-forbid", "FORBID"]]) {
  $(id).onclick = async () => {
    try { showError("display-error"); await api("/api/display", { device: $("display-node").value, state }); }
    catch (e) { showError("display-error", e); } tick();
  };
}
$("display-node").onchange = () => { displaySelected = $("display-node").value; if (last) drawDisplay(last); };

tick();
setInterval(tick, 1000);
