"use strict";
const $ = (s, r = document) => r.querySelector(s);
const el = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat()) e.append(c instanceof Node ? c : document.createTextNode(c ?? ""));
  return e;
};
const NS = "http://www.w3.org/2000/svg";
const sv = (tag, attrs = {}, ...kids) => {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null && v !== false) e.setAttribute(k, v);
  for (const c of kids.flat()) e.append(c instanceof Node ? c : document.createTextNode(c));
  return e;
};
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* private mode */ } },
};
let IDX = null;

async function getJSON(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(path + ": " + r.status);
  return r.json();
}
const badge = (cls) => el("span", { class: "badge " + cls, title: IDX.classes[cls].meaning }, IDX.classes[cls].label);

function copyButton(getText, label = "Copy") {
  const b = el("button", { type: "button" }, label);
  b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(getText()); b.textContent = "Copied"; } catch (e) { b.textContent = "Select and copy"; }
    setTimeout(() => (b.textContent = label), 1600);
  });
  return b;
}

function header() {
  const clone = `git clone ${IDX.repo}.git && cd IETF127-Hackathon-AI2II-WIMSE && ./reproduce.sh`;
  const live = "./reproduce.sh --live";
  const gh = el("details", { class: "gh" },
    el("summary", {}, "GitHub: clone and run ▾"),
    el("div", { class: "pop" },
      el("p", {}, el("b", {}, "One command, all the evidence."), " Clones the repository, then re-checks every committed capture and partner record (hashes, independent packet checkers, negative captures). Needs python3 and tshark."),
      el("div", { class: "cmd" }, el("pre", {}, clone), copyButton(() => clone)),
      el("p", {}, "To run the peers again and record fresh captures (needs AgentMaurice and tshark installed):"),
      el("div", { class: "cmd" }, el("pre", {}, live), copyButton(() => live)),
      el("p", {}, el("a", { href: IDX.repo }, "Repository"), " · ", el("a", { href: IDX.repo + "#readme" }, "README"), " · ",
        el("a", { href: IDX.repo + "/blob/main/CONTRIBUTING.md" }, "Contribute a result (pull request)"))));
  const raw = IDX.repo.replace("github.com", "raw.githubusercontent.com") + "/main/";
  const unix = `mkdir -p ~/.local/lib/wireshark/plugins && curl -fsSL ${raw}dissectors/wimse.lua -o ~/.local/lib/wireshark/plugins/wimse.lua`;
  const win = `New-Item -ItemType Directory -Force "$env:APPDATA\\Wireshark\\plugins" | Out-Null; Invoke-WebRequest ${raw}dissectors/wimse.lua -OutFile "$env:APPDATA\\Wireshark\\plugins\\wimse.lua"`;
  const cmd = (t) => el("div", { class: "cmd" }, el("pre", {}, t), copyButton(() => t));
  const ws = el("details", { class: "gh" },
    el("summary", {}, "Wireshark decoder \u25BE"),
    el("div", { class: "pop" },
      el("p", {}, el("b", {}, "Open the PCAPs with the WIMSE decoder switched on."), " It decodes HTTP on ports 5050\u20135064, tags each packet with its test case, decodes the WIT, WPT and Txn-Token, and adds filters such as ", el("code", {}, "wimse.test_case"), "."),
      el("p", {}, el("b", {}, "Install once"), " (a web page cannot write into Wireshark itself, so this copies one file into your personal plugins folder; Wireshark loads it every time it starts):"),
      el("p", { class: "muted" }, "macOS / Linux, Terminal:"), cmd(unix),
      el("p", { class: "muted" }, "Windows, PowerShell (not tested):"), cmd(win),
      el("p", {}, "Then restart Wireshark (or Analyze \u25B8 Reload Lua Plugins, Ctrl+Shift+L), open a capture downloaded from any scenario, and filter, for example ", el("code", {}, 'wimse.test_case == "B_CHAIN"'), "."),
      el("p", {}, "Check or remove it with ", el("a", { href: raw + "setup/install_wireshark_dissector.sh" }, "the installer script"), " (", el("code", {}, "check"), " / ", el("code", {}, "uninstall"), "), or just download ", el("a", { href: raw + "dissectors/wimse.lua" }, "wimse.lua"), " and put it in the plugins folder shown under Help \u25B8 About Wireshark \u25B8 Folders.")));
  return el("header", { class: "top" }, el("h1", {}, el("a", { href: "index.html" }, "WIMSE interop explorer"), el("span", { class: "muted" }, " \u2014 IETF 127 hackathon")), ws, gh);
}

/* ------------------------------------------------------------------ index */
const TAGCLASS = { accepted: "result-accepted", refused: "result-refused", mixed: "result-mixed" };
function tagInfo(facet, id) {
  const f = IDX.tag_facets.find((x) => x.id === facet), it = f && f.items.find((x) => x.id === id);
  return { label: it ? it.label : id, meaning: it ? it.meaning : "" };
}
function tagChip(facet, id, onclick) {
  const t = tagInfo(facet, id);
  const attrs = { type: "button", class: `tag ${facet} ${facet === "result" ? TAGCLASS[id] : ""}`, title: t.meaning + " (click to filter)" };
  const b = el("button", attrs, t.label);
  if (onclick) b.addEventListener("click", onclick);
  return b;
}

const INDEP_ITEMS = [
  { id: "yes", label: "Yes", meaning: "An implementation we did not write decides: Maurice, or a partner's own software." },
  { id: "no", label: "No", meaning: "Our own peers are on both ends." },
];
function basisInfo(id) { return IDX.basis_facets.find((b) => b.id === id) || { label: id, short: id, meaning: "" }; }

function renderIndex() {
  const FACETS = [
    { id: "cls", name: "Evidence", get: (s) => [s.cls], items: Object.entries(IDX.classes).filter(([k]) => IDX.scenarios.some((s) => s.cls === k)).map(([k, v]) => ({ id: k, label: v.label, meaning: v.meaning })) },
    ...IDX.tag_facets.map((f) => ({ id: f.id, name: f.name, get: (s) => s.tags[f.id], items: f.items })),
    { id: "basis", name: "What it rests on", get: (s) => [s.basis], items: IDX.basis_facets.map((b) => ({ id: b.id, label: b.label, meaning: b.meaning })) },
    { id: "indep", name: "Independent implementation", get: (s) => [s.independent ? "yes" : "no"], items: INDEP_ITEMS },
  ];
  const params = new URLSearchParams(location.search);
  const sel = Object.fromEntries(FACETS.map((f) => [f.id, new Set((params.get(f.id) || "").split(",").filter((v) => f.items.some((i) => i.id === v)))]));
  const state = { q: (params.get("q") || "").toLowerCase() };
  const main = $("main"), chips = {}, status = el("p", { class: "muted", role: "status", "aria-live": "polite" }), list = el("div");
  const matches = (s, skip) => FACETS.every((f) => f.id === skip || !sel[f.id].size || f.get(s).some((x) => sel[f.id].has(x))) && (!state.q || (s.id + " " + s.title + " " + s.short).toLowerCase().includes(state.q));
  const sync = () => {
    const p = new URLSearchParams();
    for (const f of FACETS) if (sel[f.id].size) p.set(f.id, [...sel[f.id]].join(","));
    if (state.q) p.set("q", state.q);
    history.replaceState(null, "", location.pathname + (p.toString() ? "?" + p : ""));
  };
  const toggle = (facet, id) => { sel[facet].has(id) ? sel[facet].delete(id) : sel[facet].add(id); draw(); };
  const draw = () => {
    sync();
    const shown = IDX.scenarios.filter((s) => matches(s, null));
    status.textContent = `${shown.length} of ${IDX.scenarios.length} scenarios shown`;
    for (const f of FACETS) for (const it of f.items) {
      const b = chips[f.id + ":" + it.id], n = IDX.scenarios.filter((s) => matches(s, f.id) && f.get(s).includes(it.id)).length, on = sel[f.id].has(it.id);
      b.textContent = `${it.label} (${n})`; b.setAttribute("aria-pressed", String(on)); b.disabled = !n && !on;
    }
    $("#clear").hidden = !(FACETS.some((f) => sel[f.id].size) || state.q);
    list.replaceChildren();
    for (const g of IDX.groups) {
      const items = shown.filter((s) => s.group === g.id);
      if (!items.length) continue;
      list.append(el("h2", { class: "grp g-" + g.id }, g.name), el("div", { class: "muted" }, g.question),
        el("ul", { class: "list" }, items.map((s) => {
          const t = s.tags, bi = basisInfo(s.basis), chipsRow = el("div", { class: "tags" },
            el("button", { type: "button", class: "tag basis basis-" + s.basis, title: bi.label + " (click to filter)", onclick: () => toggle("basis", s.basis) }, bi.short),
            tagChip("result", t.result[0], () => toggle("result", t.result[0])),
            ...t.checks.slice(0, 2).map((c) => tagChip("checks", c, () => toggle("checks", c))),
            ...t.topic.slice(0, 2).map((c) => tagChip("topic", c, () => toggle("topic", c))));
          return el("li", {}, el("a", { class: "t", href: "scenario.html#" + s.id }, s.title), el("div", { class: "s" }, el("span", { class: "muted" }, s.short), chipsRow), badge(s.cls), el("span", { class: "muted" }, s.messages + (s.messages === 1 ? " message" : " messages")));
        })));
    }
    if (!list.children.length) list.append(el("p", {}, "No scenario matches these filters."));
  };
  const filters = el("div", { class: "filters" });
  for (const f of FACETS) {
    const row = el("div", { class: "frow" }, el("span", { class: "fname" }, f.name + ":"));
    for (const it of f.items) {
      const b = el("button", { type: "button", "aria-pressed": "false", title: it.meaning });
      if (f.id === "result") b.classList.add("rchip", TAGCLASS[it.id]);
      b.addEventListener("click", () => toggle(f.id, it.id));
      chips[f.id + ":" + it.id] = b; row.append(b);
    }
    filters.append(row);
  }
  const search = el("input", { type: "search", placeholder: "Search scenarios", "aria-label": "Search scenarios", value: state.q });
  search.addEventListener("input", () => { state.q = search.value.toLowerCase(); draw(); });
  const clear = el("button", { type: "button", id: "clear", hidden: true }, "Clear filters");
  clear.addEventListener("click", () => { for (const f of FACETS) sel[f.id].clear(); state.q = ""; search.value = ""; draw(); });
  filters.append(el("div", { class: "frow" }, search, clear, status));
  const meaning = el("details", { class: "tagdefs" }, el("summary", {}, "What do the tags mean?"),
    ...[...IDX.tag_facets, ...FACETS.filter((f) => f.id === "basis" || f.id === "indep")].map((f) => el("div", {}, el("h4", {}, f.name), el("ul", { class: "plain" }, f.items.map((i) => el("li", {}, el("b", {}, i.label), " \u2014 ", i.meaning))))),
    el("p", { class: "muted" }, "Result is computed from the replies or recorded decisions; checks and topic are assigned in the build script. Within a row, several choices mean \"any of\"; across rows they all have to match."));
  main.append(
    el("h2", { style: "margin:4px 0" }, `${IDX.scenarios.length} scenarios, replayed step by step`),
    el("p", {}, "Every scenario that was tested at the IETF 127 hackathon, grouped by the question it answers. Open one to watch its messages appear one at a time, with the captured packet contents, the drafts concerned and the checker's verdict. Filter by what a scenario shows: the evidence class, whether it is accepted or refused, the kind of check, and the topic."),
    filters, meaning, limitsBox(), list);
  draw();
}

function limitsBox() {
  const pr = IDX.pending_rerecord || { no_page: [], with_page: [] };
  return el("details", { class: "limits", id: "limits" }, el("summary", {}, "Limits of this test"),
    el("dl", {}, IDX.limits.flatMap((l) => [el("dt", {}, l.name), el("dd", {}, l.text)])),
    ...(pr.no_page.length || pr.with_page.length ? [el("h4", {}, "Coded, not yet recorded: re-recording pending"),
      el("p", { class: "muted" }, "These cases are coded in chain_cases.json but are not in the committed chain capture, so they are not validated against the new behaviour: ",
        el("span", { id: "pending-list" }, pr.no_page.join(", ") || "none"), ".")] : []),
    pr.with_page.length ? el("p", { class: "muted" }, "Cases whose pages show the older recording, also pending: ",
      pr.with_page.flatMap((c, k) => [k ? ", " : "", el("a", { href: "scenario.html#" + c }, c)]), ".") : "");
}

/* ------------------------------------------------------------------ scenario page */
const PANELS = [["entities", "Entities"], ["sequence", "Sequence"], ["message", "Message"], ["packets", "Packets"], ["comment", "Comment"], ["drafts", "Drafts"], ["verdict", "Checker"], ["timeline", "Timeline"]];
const S = { sc: null, step: 0, brk: -1, full: false, timer: null, panels: { packets: false, ...store.get("wimse-panels", {}) } };

function viewSteps() {
  const sc = S.sc;
  let steps = sc.steps.map((x) => ({ ...x }));
  const b = S.brk >= 0 ? sc.breaks[S.brk] : null;
  if (b) {
    if (b.set_status) {
      const st = steps[b.set_status.step];
      st.label = st.label.replace(/->\s+\d{3}/, "-> " + b.set_status.status); st.result = false; st.mutated = true;
      st.comment = `The mutant: this hop's 200 was changed to ${b.set_status.status}. The set of statuses in the case is unchanged, so only a hop-by-hop comparison notices. Switch back to "Real capture" to compare.`;
      st.reply = { status: b.set_status.status, short: `${b.set_status.status}: refused (changed in the mutant)`, long: st.comment };
      st.verdict = { expected: st.verdict ? st.verdict.expected : "", observed: String(b.set_status.status), ok: false, note: "changed in the mutant capture" };
      if (st.http) st.http = { ...st.http, resp: { ...st.http.resp, line: `HTTP/1.1 ${b.set_status.status} Forbidden` } };
    }
    if (b.add_step) steps.push({ ...b.add_step, injected: true });
    if (b.strip_responses) steps = steps.map((x) => ({ ...x, label: x.label.replace(/\s+->\s+.*$/, "  (no response)"), result: false, stripped: true, reply: null, tokens: x.tokens ? { sent: x.tokens.sent, returned: [] } : x.tokens, verdict: { expected: x.verdict ? x.verdict.expected : "", observed: "no response", ok: false, note: "responses removed from the capture" } }));
  }
  return steps;
}

// A message is a request, a reply, or a single step (partner records, mutant additions). Messages are in true
// capture order: a reply comes after the calls its receiver made in the meantime, not right after its request.
function viewEvents(steps) {
  const evs = [];
  steps.forEach((st, i) => {
    if (st.http) {
      evs.push({ kind: "req", st, n: i + 1, frame: st.http.frame, ord: 0, seq: i });
      if (st.reply && !st.stripped) evs.push({ kind: "reply", st, n: i + 1, frame: st.http.resp_frame, ord: 1, seq: i });
    } else evs.push({ kind: "single", st, n: i + 1, frame: Infinity, ord: 0, seq: i });
  });
  const cmp = (a, b) => (a.frame === b.frame ? 0 : a.frame < b.frame ? -1 : 1);
  return evs.sort((a, b) => cmp(a, b) || a.ord - b.ord || a.seq - b.seq);
}
const evFrom = (e) => (e.kind === "reply" ? e.st.to : e.st.from);
const evTo = (e) => (e.kind === "reply" ? e.st.from : e.st.to);
const nEvents = () => viewEvents(viewSteps()).length;
function labelOf(id) { const all = [...(S.sc.entities || []), ...(S.sc.context || [])]; const e = all.find((x) => x.id === id); return e ? e.label : id; }
// the calls that other entities made while this call was open (between its request and its reply)
function nestedCalls(ev) {
  const evs = S.evs, i = evs.findIndex((e) => e.n === ev.n && e.kind === "req"), j = evs.findIndex((e) => e.n === ev.n && e.kind === "reply");
  if (i < 0 || j < 0) return { replyAt: j, calls: [] };
  return { replyAt: j, calls: evs.slice(i + 1, j).filter((e) => e.kind === "req") };
}
function waitText(ev) {
  const { replyAt, calls } = nestedCalls(ev);
  if (replyAt < 0) return "";
  const list = calls.map((e) => `${e.n} (${labelOf(e.st.to)})`).join(", ");
  if (ev.kind === "req") {
    return calls.length ? `This call stays open while ${labelOf(ev.st.to)} does its work: it makes call${calls.length > 1 ? "s" : ""} ${list} before it can answer. The reply comes at message ${replyAt + 1}, after those.` : `The reply follows at message ${replyAt + 1}.`;
  }
  return calls.length ? `It could only answer after the call${calls.length > 1 ? "s" : ""} made in the meantime had returned: ${list}.` : "";
}

function clip(box, tx, ty) { // point on the box edge towards (tx, ty)
  const cx = box.x + box.w / 2, cy = box.y + box.h / 2, dx = tx - cx, dy = ty - cy;
  if (!dx && !dy) return [cx, cy];
  const k = Math.min(dx ? (box.w / 2) / Math.abs(dx) : Infinity, dy ? (box.h / 2) / Math.abs(dy) : Infinity);
  return [cx + dx * k, cy + dy * k];
}

function heads(p) {
  const mk = (id, cls) => sv("marker", { id: `${p}-${id}`, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 8, markerHeight: 8, orient: "auto-start-reverse" }, sv("path", { d: "M0 0L10 5L0 10z", class: cls }));
  return sv("defs", {}, mk("ok", "mh-ok"), mk("bad", "mh-bad"));
}

function drawEntities(evs) {
  const sc = S.sc, all = [...(sc.context || []).map((e) => ({ ...e, off: true })), ...sc.entities];
  const byId = Object.fromEntries(all.map((e) => [e.id, e]));
  const xs = all.flatMap((e) => [e.x, e.x + e.w]).concat((sc.frames || []).flatMap((f) => [f.x, f.x + f.w]));
  const ys = all.flatMap((e) => [e.y, e.y + e.h]).concat((sc.frames || []).flatMap((f) => [f.y, f.y + f.h]));
  const x0 = Math.min(...xs) - 20, y0 = Math.min(...ys) - 20, w = Math.max(...xs) - x0 + 20, h = Math.max(...ys) - y0 + 20;
  const svg = sv("svg", { viewBox: `${x0} ${y0} ${w} ${h}`, width: "100%", role: "img", "aria-label": "Entities and the messages between them", style: "max-height:460px;display:block;margin:0 auto" });
  svg.append(heads("e"));
  for (const f of sc.frames || []) svg.append(sv("rect", { class: "frame fz-" + f.zone, x: f.x, y: f.y, width: f.w, height: f.h }), sv("text", { class: "framelabel fz-" + f.zone, x: f.x + 10, y: f.y + 20, "font-size": 15, "font-weight": "bold" }, f.label));
  const shown = evs.slice(0, S.step + 1), cur = evs[S.step], used = new Set(shown.flatMap((e) => [evFrom(e), evTo(e)]));
  for (const e of all) {
    const on = !e.off && used.has(e.id), isCur = cur && (evFrom(cur) === e.id || evTo(cur) === e.id);
    svg.append(sv("rect", { class: "box z-" + (e.zone || "p") + (e.off || !on ? " off" : "") + (isCur ? " cur" : ""), x: e.x, y: e.y, width: e.w, height: e.h }),
      sv("text", { x: e.x + e.w / 2, y: e.y + e.h / 2 - 3, "text-anchor": "middle", "font-size": 14, "font-weight": "bold", class: e.off || !on ? "off" : "" }, e.label),
      sv("text", { x: e.x + e.w / 2, y: e.y + e.h / 2 + 15, "text-anchor": "middle", "font-size": 12, class: e.off || !on ? "off" : "" }, e.sub || ""));
  }
  const pair = {};
  shown.forEach((e, k) => {
    if (e.kind === "reply" && k !== S.step) return;  // older replies are in the sequence; here only requests and the current reply
    const f = evFrom(e), t = evTo(e), a = byId[f], b = byId[t];
    if (!a || !b) return;
    const key = [f, t].sort().join("|");
    const off = (pair[key] = (pair[key] || 0) + 1) - 1;
    const [ax, ay] = clip(a, b.x + b.w / 2, b.y + b.h / 2), [bx, by] = clip(b, a.x + a.w / 2, a.y + a.h / 2);
    const nx = -(by - ay), ny = bx - ax, len = Math.hypot(nx, ny) || 1, sh = (off % 2 ? -1 : 1) * Math.ceil(off / 2) * 9 + (f > t ? 7 : -7);
    const p = (x, y) => [x + (nx / len) * sh, y + (ny / len) * sh];
    const [sx, sy] = p(ax, ay), [ex, ey] = p(bx, by);
    const bad = e.kind === "reply" ? e.st.reply.status >= 400 : e.kind === "single" ? e.st.result === false || e.st.injected : false;
    svg.append(sv("line", { class: "arr " + (bad ? "bad" : "good") + (k === S.step ? " cur" : " old") + (e.kind === "reply" || e.st.dashed ? " dash" : ""), x1: sx, y1: sy, x2: ex, y2: ey, "marker-end": `url(#e-${bad ? "bad" : "ok"})` }),
      sv("text", { x: (sx + ex) / 2, y: (sy + ey) / 2 - 4, "text-anchor": "middle", "font-size": 13, "font-weight": k === S.step ? "bold" : "normal" }, e.kind === "reply" ? `${e.n}↩` : String(e.n)));
  });
  return svg;
}

function drawSequence(evs) {
  const sc = S.sc, ents = sc.entities, n = ents.length, W = 1100, left = 20, bw = Math.min(190, (W - 40) / n - 8);
  const step = (W - 40 - bw) / Math.max(n - 1, 1), xs = ents.map((_, i) => (n === 1 ? W / 2 : left + bw / 2 + i * step));
  const top = 92, row = 46, H = top + evs.length * row + 14;
  const svg = sv("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", role: "img", "aria-label": "Sequence of messages" });
  svg.append(heads("s"));
  ents.forEach((e, i) => {
    svg.append(sv("rect", { class: "box z-" + (e.zone || "p"), x: xs[i] - bw / 2, y: 6, width: bw, height: 50 }), sv("text", { x: xs[i], y: 28, "text-anchor": "middle", "font-size": 13, "font-weight": "bold" }, e.label), sv("text", { x: xs[i], y: 46, "text-anchor": "middle", "font-size": 11 }, e.sub || ""),
      sv("line", { class: "life", x1: xs[i], y1: 56, x2: xs[i], y2: H - 6 }));
  });
  const idx = Object.fromEntries(ents.map((e, i) => [e.id, i]));
  const shown = evs.slice(0, S.step + 1);
  // a bar on the receiver's lifeline from a request to its reply: the entity is busy, waiting for what it needs
  shown.forEach((e, k) => {
    if (e.kind !== "req" || !e.st.http) return;
    const b = idx[e.st.to];
    if (b == null) return;
    const j = shown.findIndex((x) => x.kind === "reply" && x.n === e.n), y1 = top + k * row - 6, y2 = top + (j >= 0 ? j : S.step) * row + 6;
    svg.append(sv("rect", { class: "act" + (j >= 0 ? "" : " open"), x: xs[b] - 6, y: y1, width: 12, height: Math.max(y2 - y1, 12) }));
  });
  const arrow = (a, b, y, bad, cur, dashed) => sv("line", { class: "arr " + (bad ? "bad" : "good") + (cur ? " cur" : " old") + (dashed ? " dash" : ""), x1: xs[a], y1: y, x2: xs[b] + (xs[b] > xs[a] ? -2 : 2), y2: y, "marker-end": `url(#s-${bad ? "bad" : "ok"})` });
  const label = (text, a, b, y, cur, bad, full, mark = true) => {
    const x = Math.min(xs[a], xs[b]) + 10, max = Math.floor((W - 14 - x) / 6.3);
    const t = sv("text", { class: "lbl", x, y: y - 7, "text-anchor": "start", "font-size": 12.5, "font-weight": cur ? "bold" : "normal" }, text.length > max ? text.slice(0, max - 1) + "…" : text);
    if (mark) t.append(sv("tspan", { class: "mk " + (bad ? "bad" : "ok") }, bad ? " ✗" : " ✓"));
    t.append(sv("title", {}, full || text));
    return t;
  };
  shown.forEach((e, k) => {
    const st = e.st, y = top + k * row, cur = k === S.step, a = idx[evFrom(e)], b = idx[evTo(e)];
    if (a == null || b == null) return;
    if (e.kind === "req") svg.append(arrow(a, b, y, false, cur, false), label(`${e.n}. ${st.label.replace(/\s+->\s+.*$/, "")}`, a, b, y, cur, false, "", false));
    else if (e.kind === "reply") { const rbad = st.reply.status >= 400; svg.append(arrow(a, b, y, rbad, cur, true), label(`${e.n} reply: ${st.reply.short}`, a, b, y, cur, rbad, st.reply.long)); }
    else { const bad = st.injected || st.result === false; svg.append(arrow(a, b, y, bad, cur, st.dashed), label(`${e.n}. ${st.label}`, a, b, y, cur, bad)); }
  });
  return svg;
}

const TOK = /eyJ[\w-]+\.[\w-]+\.[\w-]*/g;
function fmt(text) {
  const frag = document.createDocumentFragment();
  let last = 0;
  for (const m of String(text).matchAll(TOK)) {
    frag.append(text.slice(last, m.index));
    const full = m[0];
    frag.append(S.full ? full : el("span", { class: "tok", title: "Click to show full tokens", onclick: () => { S.full = true; render(); } }, full.slice(0, 22) + "…" + full.slice(-6)));
    last = m.index + full.length;
  }
  frag.append(text.slice(last));
  return frag;
}

function fmtHttp(line, headers, body, resp) {
  const frag = document.createDocumentFragment();
  const m = resp ? /^(HTTP\/\S+ )(\d{3})(.*)$/.exec(line) : null;
  frag.append(m ? el("span", {}, m[1], el("span", { class: m[2][0] === "2" ? "s2" : "s4" }, m[2]), m[3]) : el("span", { class: "req4" }, line), "\n");
  for (const h of headers) {
    const i = h.indexOf(":");
    frag.append(i > 0 ? el("span", { class: "hn" }, h.slice(0, i)) : "", fmt(i > 0 ? h.slice(i) : h), "\n");
  }
  if (body) frag.append("\n", fmt(body));
  return frag;
}

function tokensBox(st, which) {
  const tk = st.tokens, box = el("div", { class: "toks" });
  const list = tk ? tk[which] || [] : [];
  if (!list.length) return box;
  box.append(el("h4", {}, which === "sent" ? "Tokens sent in this request (decoded)" : "Tokens returned in this reply (decoded)"));
  box.append(...list.map((t) => el("details", { class: "tokitem" },
    el("summary", {}, el("span", { class: "tdir " + which }, which), " ", el("b", {}, t.kind), t.what ? ` (${t.what})` : "", t.line ? ": " + t.line : ""),
    el("p", { class: "muted", style: "margin:4px 0" }, t.where + (t.note ? ". " + t.note : "")),
    el("pre", {}, JSON.stringify({ header: t.header, claims: t.claims }, null, 2)))));
  return box;
}

function panelMessage(ev) {
  const st = ev.st, sc = S.sc, box = el("div", { class: "msg" });
  if (st.http) {
    const h = st.http, cap = sc.capture, stripped = st.stripped, isReply = ev.kind === "reply";
    const reqBlock = () => [el("h4", {}, "Request"), el("pre", {}, fmtHttp(h.req.line, h.req.headers, h.req.body, false))];
    const repBlock = () => [el("h4", {}, "Reply"), el("pre", {}, stripped ? "(removed in this mutant capture)" : fmtHttp(h.resp.line, h.resp.headers, h.resp.body, true))];
    const reqFrames = h.req_first && h.req_first !== h.frame ? `frames ${h.req_first}–${h.frame}` : `frame ${h.frame}`;
    box.append(el("div", { class: "meta" }, isReply ? `Reply: frame ${h.resp_frame}, answering the request in ${reqFrames}; TCP stream ${h.stream}` : `Request: ${reqFrames}` + (stripped ? "" : `; its reply is in frame ${h.resp_frame}`) + `; TCP stream ${h.stream}`));
    box.append(...(isReply ? repBlock() : reqBlock()));
    const wt = waitText(ev);
    if (wt) box.append(el("p", { class: "note" }, wt));
    box.append(tokensBox(st, isReply ? "returned" : "sent"));
    if (!stripped) box.append(el("details", { class: "other" }, el("summary", {}, isReply ? "Show the request this reply answers" : "Show the reply (it arrives later)"), ...(isReply ? reqBlock() : repBlock())));
    const fn = isReply ? h.resp_frame : h.frame;
    const cmd = `tshark -r ${cap.file.split("/").pop()} ${sc.capture.file.includes("chain") ? "-d tcp.port==5051,http -d tcp.port==5060,http -d tcp.port==5061,http -d tcp.port==5062,http -d tcp.port==5063,http -d tcp.port==5064,http " : "-d tcp.port==5050,http "}-Y "frame.number==${fn}" -V`;
    box.append(el("div", { class: "row" }, el("pre", {}, cmd), copyButton(() => cmd)),
      el("div", { class: "row" }, el("span", {}, "Wireshark filter: "), el("code", {}, `frame.number == ${fn}`), copyButton(() => `frame.number == ${fn}`), el("a", { href: cap.url }, "Download the capture (.pcap)")));
    const tc = ((h.req.headers.find((x) => /^x-test-case:/i.test(x)) || "").split(":")[1] || "").trim();
    if (tc) {
      const f2 = `wimse.test_case == "${tc}"`, c2 = `tshark -r ${cap.file.split("/").pop()} -Y '${f2}' -O wimse`;
      box.append(el("div", { class: "row" }, el("span", {}, "With the WIMSE decoder installed (header: Wireshark decoder): "), el("code", {}, f2), copyButton(() => f2)),
        el("div", { class: "row" }, el("pre", {}, c2), copyButton(() => c2)));
    }
    if (S.full) box.append(el("div", { class: "row" }, el("button", { type: "button", onclick: () => { S.full = false; render(); } }, "Shorten tokens")));
  } else if (st.record) {
    box.append(el("div", { class: "meta" }, "A decision line from the partner's committed record"), el("pre", {}, JSON.stringify(st.record, null, 2)),
      sc.record ? el("div", { class: "row" }, el("a", { href: sc.record.url }, "Open the record file: " + sc.record.file)) : "");
  } else if (st.injected) {
    box.append(el("p", {}, "This step does not exist in the real capture. It is what the mutant capture adds; see the checker panel."));
  } else {
    box.append(el("p", { class: "muted" }, "No packet or record for this step: it is described by the partner's report (see the checker panel for the evidence class)."));
  }
  return box;
}

function panelComment(ev) {
  const st = ev.st, big = "margin:0;font-size:16px", small = "margin:8px 0 0;font-size:15px";
  if (ev.kind === "reply") {
    const wt = waitText(ev);
    return el("div", {}, el("p", { style: big }, `${labelOf(st.to)} replies to ${labelOf(st.from)}.`), el("p", { style: small }, el("b", {}, "Reply: "), st.reply.long), wt ? el("p", { style: small }, wt) : "");
  }
  const wt = ev.kind === "req" ? waitText(ev) : "";
  return el("div", {}, el("p", { style: big }, st.comment || ""), wt ? el("p", { style: small }, wt) : "");
}

function panelPackets(st) {
  const sc = S.sc, box = el("div", { class: "msg" });
  if (!st.packets) {
    box.append(el("p", { class: "muted" }, sc.capture ? "This step has no packets of its own: it is what the mutant capture adds." : "Not a packet capture: this step comes from the partner's record or report, so there is no TCP conversation to show."));
    return box;
  }
  const pk = st.packets, content = pk.filter((p) => p.kind === "content").length, h = st.http;
  box.append(el("p", { style: "margin:0 0 8px" }, el("b", {}, `${pk.length} packets for this one request.`), ` ${content} carry the message; the other ${pk.length - content} are housekeeping that every TCP connection needs: dial, say it, wait, answer, hang up.`));
  const rows = [];
  for (const p of pk) {
    if (p.gap_ms) rows.push(el("tr", { class: "pause" }, el("td", { colspan: "5" }, `\u23F3 pause of ${p.gap_ms} ms: the server is working on its answer`)));
    rows.push(el("tr", { class: "pk " + p.kind },
      el("td", {}, String(p.n)), el("td", { class: "tm" }, `+${p.t.toFixed(1)} ms`), el("td", { class: "dir " + p.dir, title: p.dir === "c2s" ? "client to server" : "server to client" }, p.dir === "c2s" ? "\u2192" : "\u2190"),
      el("td", {}, el("b", {}, p.label), p.len ? ` (${p.len} bytes)` : ""), el("td", { class: "muted" }, p.text)));
  }
  box.append(el("table", { class: "pk" }, el("thead", {}, el("tr", {}, ["Frame", "Time", "", "What", "In plain words"].map((x) => el("th", {}, x)))), el("tbody", {}, rows)));
  const f = `tcp.stream == ${h.stream}`;
  box.append(el("div", { class: "row" }, el("span", {}, "Wireshark filter for the whole conversation: "), el("code", {}, f), copyButton(() => f)));
  return box;
}

function panelDrafts(st) {
  const sc = S.sc, box = el("div");
  if (st.drafts && st.drafts.length) box.append(el("p", {}, el("b", {}, "This step: "), st.drafts.join("; ")));
  box.append(el("ul", { class: "plain" }, sc.drafts.map((d) => el("li", {}, el("b", {}, d.name), d.what ? " — " + d.what : "", d.section ? el("span", {}, " (", el("b", {}, d.section), ")") : ""))));
  if (!sc.drafts.length) box.append(el("p", { class: "muted" }, "No draft applies: this checks the test harness itself."));
  return box;
}

function panelVerdict(ev, last) {
  const st = ev.st, sc = S.sc, b = S.brk >= 0 ? sc.breaks[S.brk] : null, box = el("div");
  const kv = el("div", { class: "kv" }), pending = ev.kind === "req" && st.http && st.reply;
  if (st.verdict) {
    kv.append(el("b", {}, "Expected"), el("span", {}, st.verdict.expected || "—"));
    if (pending) kv.append(el("b", {}, "Observed"), el("span", { class: "muted" }, "known when the reply arrives"));
    else kv.append(el("b", {}, "Observed"), el("span", {}, st.verdict.observed), el("b", {}, "This call"), el("span", { class: st.verdict.ok ? "ok" : "fail" }, st.verdict.ok ? "✓ matches" : "✗ does NOT match"));
  }
  kv.append(el("b", {}, "Checker"), el("span", {}, sc.checker), el("b", {}, "Evidence"), el("span", {}, badge(sc.cls), " ", IDX.classes[sc.cls].meaning));
  box.append(kv);
  if (st.verdict && st.verdict.note && !pending) box.append(el("p", { class: "muted" }, st.verdict.note));
  if (b) {
    box.append(el("h4", {}, "Mutant capture: " + b.name), el("p", {}, b.description), el("pre", { class: "fail" }, b.checker_output), el("p", { class: "muted" }, "Checker output recorded at build time on ", el("a", { href: IDX.repo + "/blob/main/checkers/negatives/" + b.mutant }, "checkers/negatives/" + b.mutant)));
  } else if (last) {
    box.append(el("p", {}, el("b", {}, "Result: "), el("span", { class: sc.result.verdict === "PASS" ? "ok" : sc.result.verdict === "FAIL" ? "fail" : "" }, sc.result.verdict), ". ", sc.result.text));
  }
  return box;
}

const sec = (x) => { const v = Math.round(x * 1000) / 1000; return (v < 0 ? "\u2212" : "+") + String(Math.abs(v)); };
function panelTimeline(evs) {
  const sc = S.sc, box = el("div");
  const rel = evs.map((e) => (e.st.time ? (e.kind === "reply" ? e.st.time.resp_rel ?? e.st.time.rel : e.st.time.rel) : 0));
  const note = evs[S.step].st.time && evs[S.step].st.time.note;
  if (sc.bound) {
    const max = Math.max(sc.bound, ...rel), bar = el("div", { class: "bar", title: "0 to the promised bound" });
    evs.slice(0, S.step + 1).forEach((e, i) => { if (i) bar.append(el("i", { style: `left:${(rel[i] / max) * 100}%` })); });
    bar.append(el("b", { style: sc.bound >= max ? "right:4px" : `left:${(sc.bound / max) * 100}%` }, `bound ${sc.bound} s`));
    box.append(el("p", {}, `Time since t0 against the promised bound of ${sc.bound} s:`), bar);
  }
  const text = (e) => (e.kind === "reply" ? `${e.n} reply: ${e.st.reply.short}` : e.kind === "req" ? `${e.n}. ${e.st.label.replace(/\s+->\s+.*$/, "")}` : e.st.label);
  box.append(el("table", { class: "tl" }, evs.map((e, i) => el("tr", { class: i === S.step ? "cur" : "", style: i > S.step ? "opacity:.35" : "" },
    el("td", {}, String(i + 1)), el("td", {}, e.st.time ? `${sec(rel[i])} s` : ""), el("td", {}, e.st.time && i ? `(${sec(rel[i] - rel[i - 1])} s)` : ""), el("td", {}, text(e).length > 46 ? text(e).slice(0, 45) + "…" : text(e))))));
  if (note) box.append(el("p", { class: "muted" }, "Clock: " + note + "."));
  return box;
}

function render() {
  const sc = S.sc, steps = viewSteps(), evs = viewEvents(steps), n = evs.length;
  S.evs = evs;
  S.step = Math.max(0, Math.min(S.step, n - 1));
  const ev = evs[S.step], last = S.step === n - 1;
  $("#count").textContent = `Step ${S.step + 1} of ${n}`;
  $("#prev").disabled = S.step === 0; $("#next").disabled = last; $("#play").textContent = S.timer ? "Pause" : "Play";
  history.replaceState(null, "", `#${sc.id}/${S.step + 1}` + (S.brk >= 0 ? `/b${S.brk + 1}` : ""));
  const put = (id, node) => { const p = $("#p-" + id + " .body"); p.replaceChildren(node); };
  put("entities", drawEntities(evs)); put("sequence", drawSequence(evs)); put("message", panelMessage(ev)); put("packets", panelPackets(ev.st));
  put("comment", panelComment(ev));
  put("drafts", panelDrafts(ev.st)); put("verdict", panelVerdict(ev, last)); put("timeline", panelTimeline(evs));
  const bk = $("#brk"); bk.replaceChildren();
  if (sc.breaks.length) {
    bk.append(el("b", {}, "Break it: "));
    const mk = (i, label) => { const b = el("button", { type: "button", "aria-pressed": String(S.brk === i) }, label); b.addEventListener("click", () => { S.brk = i; S.step = Math.min(S.step, nEvents() - 1); render(); }); return b; };
    bk.append(mk(-1, "Real capture"), ...sc.breaks.map((b, i) => mk(i, b.name)));
  }
}

function applyPanels() {
  for (const [id] of PANELS) $("#p-" + id).classList.toggle("hidden", S.panels[id] === false);
}

function stop() { if (S.timer) { clearInterval(S.timer); S.timer = null; } }
function go(d) { S.step += d; render(); }

async function loadScenario(id, step, brk) {
  stop();
  S.sc = await getJSON(`data/${id}.json`); S.brk = brk > 0 && brk <= S.sc.breaks.length ? brk - 1 : -1; S.step = Math.max(0, (step || 1) - 1);
  document.title = S.sc.title + " — WIMSE interop explorer";
  $("#sel").value = id;
  const head = $("#head"); head.replaceChildren(el("h2", { style: "margin:0;font-size:20px" }, S.sc.title), badge(S.sc.cls), el("span", { class: "gchip g-" + S.sc.group }, IDX.groups.find((g) => g.id === S.sc.group).name));
  const tg = S.sc.tags, link = (fac, id) => { const t = tagInfo(fac, id), a = el("a", { class: `tag ${fac} ${fac === "result" ? TAGCLASS[id] : ""}`, href: `index.html?${fac}=${id}`, title: t.meaning + " (list all scenarios with this tag)" }, t.label); return a; };
  $("#tags").replaceChildren(link("result", tg.result[0]), ...tg.checks.map((c) => link("checks", c)), ...tg.topic.map((c) => link("topic", c)));
  $("#desc").textContent = S.sc.description;
  $("#exp").textContent = S.sc.expected ? "Expected: " + S.sc.expected : "";
  const bi = basisInfo(S.sc.basis);
  $("#basis").replaceChildren(el("h3", {}, "What this tests"),
    el("p", { class: "b-basis" }, el("b", {}, bi.label)),
    S.sc.basis_draft ? el("p", { class: "b-draft" }, "Draft and section: ", el("span", {}, S.sc.basis_draft)) : "",
    el("p", { class: "b-note" }, S.sc.basis_note),
    el("p", { class: "b-indep" }, "Independent implementation: ", el("b", {}, S.sc.independent ? "yes" : "no"),
      el("span", { class: "muted" }, S.sc.independent ? " (an implementation we did not write decides)" : " (our own peers on both ends)")));
  $("#prefix").replaceChildren(...(S.sc.prefix_notice ? [el("b", {}, "Recording note: "), S.sc.prefix_notice] : []));
  $("#prefix").hidden = !S.sc.prefix_notice;
  render();
}

function renderScenario() {
  const main = $("main");
  const sel = el("select", { id: "sel", "aria-label": "Scenario" });
  for (const g of IDX.groups) {
    const og = el("optgroup", { label: g.name });
    for (const s of IDX.scenarios.filter((x) => x.group === g.id)) og.append(el("option", { value: s.id }, `${s.title} [${IDX.classes[s.cls].label}]`));
    if (og.children.length) sel.append(og);
  }
  sel.addEventListener("change", () => { location.hash = sel.value; });
  const toggles = el("div", { class: "toggles", role: "group", "aria-label": "Panels" }, PANELS.map(([id, label]) => {
    const cb = el("input", { type: "checkbox", id: "t-" + id, checked: S.panels[id] !== false });
    cb.addEventListener("change", () => { S.panels[id] = cb.checked; store.set("wimse-panels", S.panels); applyPanels(); });
    return el("label", {}, cb, " " + label);
  }));
  const mkPanel = (id, label) => el("section", { class: "panel", id: "p-" + id }, el("h3", {}, label), el("div", { class: "body" }));
  const left = el("div", { class: "col" }, mkPanel("entities", "Entities"), mkPanel("sequence", "Sequence of messages"), mkPanel("packets", "Whole conversation: every packet of this request"));
  const right = el("div", { class: "col" }, mkPanel("comment", "What is happening"), mkPanel("message", "Message contents (from the capture)"), mkPanel("drafts", "Drafts concerned"), mkPanel("verdict", "Checker verdict"), mkPanel("timeline", "Timeline"));
  main.append(
    el("div", { class: "scen-head" }, sel, el("a", { href: "index.html" }, "All scenarios")),
    el("div", { class: "scen-head", id: "head", style: "margin-top:8px" }),
    el("div", { class: "tags", id: "tags", style: "margin:6px 0 2px" }),
    el("p", { class: "desc", id: "desc" }), el("p", { class: "exp muted", id: "exp" }),
    el("div", { class: "basis", id: "basis" }), el("p", { class: "prefix", id: "prefix", role: "note", hidden: true }),
    el("div", { class: "controls" },
      el("button", { id: "prev", type: "button", onclick: () => go(-1) }, "← Previous"), el("button", { id: "next", type: "button", class: "primary", onclick: () => go(1) }, "Next step →"),
      el("button", { id: "play", type: "button", onclick: () => { if (S.timer) { stop(); render(); } else { if (S.step >= nEvents() - 1) S.step = 0; S.timer = setInterval(() => { if (S.step >= nEvents() - 1) { stop(); render(); } else go(1); }, 1600); render(); } } }, "Play"),
      el("button", { type: "button", onclick: () => { stop(); S.step = 0; render(); } }, "Reset"), el("span", { class: "count", id: "count" }), toggles),
    el("div", { class: "brk", id: "brk" }),
    el("div", { class: "grid" }, left, right));
  applyPanels();
  document.addEventListener("keydown", (e) => {
    if ((e.target.matches && e.target.matches("select, input, textarea, button")) || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "ArrowRight") { go(1); e.preventDefault(); } else if (e.key === "ArrowLeft") { go(-1); e.preventDefault(); } else if (e.key === " ") { $("#play").click(); e.preventDefault(); }
  });
  const fromHash = () => { const [id, st, b] = location.hash.slice(1).split("/"); const known = IDX.scenarios.some((s) => s.id === id); return known ? loadScenario(id, parseInt(st, 10), b && b[0] === "b" ? parseInt(b.slice(1), 10) : 0) : loadScenario(IDX.scenarios.find((s) => s.id === "B_CHAIN") ? "B_CHAIN" : IDX.scenarios[0].id, 1); };
  window.addEventListener("hashchange", () => {  // a pasted link or a hand-edited address bar: new scenario, or just a new step
    const [id, st, b] = location.hash.slice(1).split("/");
    if (!S.sc || id !== S.sc.id) { fromHash(); return; }
    stop();
    S.step = Math.max(0, (parseInt(st, 10) || 1) - 1);
    const k = b && b[0] === "b" ? parseInt(b.slice(1), 10) : 0;
    S.brk = k > 0 && k <= S.sc.breaks.length ? k - 1 : -1;
    render();
  });
  fromHash();
}

(async function main() {
  try { IDX = await getJSON("data/index.json"); } catch (e) { document.body.append(el("p", { style: "padding:16px" }, "Could not load data/index.json. Serve this folder over HTTP (python3 -m http.server -d site) or open the published site.")); return; }
  document.body.prepend(header());
  document.body.append(el("footer", { class: "page" }, `Built from commit ${IDX.built_from} of `, el("a", { href: IDX.repo }, "the repository"), ". Every step comes from a committed capture or partner record; nothing here re-runs a peer."));
  document.body.dataset.page === "index" ? renderIndex() : renderScenario();
})();
