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
function renderIndex() {
  const state = { cls: new Set(), q: "" };
  const main = $("main");
  const filters = el("div", { class: "filters" });
  const list = el("div");
  const draw = () => {
    list.replaceChildren();
    for (const g of IDX.groups) {
      const items = IDX.scenarios.filter((s) => s.group === g.id && (!state.cls.size || state.cls.has(s.cls)) && (!state.q || (s.id + " " + s.title + " " + s.short).toLowerCase().includes(state.q)));
      if (!items.length) continue;
      list.append(el("h2", { class: "grp g-" + g.id }, g.name), el("div", { class: "muted" }, g.question),
        el("ul", { class: "list" }, items.map((s) => el("li", {},
          el("a", { class: "t", href: "scenario.html#" + s.id }, s.title), el("span", { class: "s muted" }, s.short), badge(s.cls), el("span", { class: "muted" }, s.steps + (s.steps === 1 ? " step" : " steps"))))));
    }
    if (!list.children.length) list.append(el("p", {}, "No scenario matches."));
  };
  for (const [k, v] of Object.entries(IDX.classes)) {
    const n = IDX.scenarios.filter((s) => s.cls === k).length;
    if (!n) continue;
    const b = el("button", { type: "button", "aria-pressed": "false" }, `${v.label} (${n})`);
    b.addEventListener("click", () => { state.cls.has(k) ? state.cls.delete(k) : state.cls.add(k); b.setAttribute("aria-pressed", state.cls.has(k)); draw(); });
    filters.append(b);
  }
  const search = el("input", { type: "search", placeholder: "Search scenarios", "aria-label": "Search scenarios" });
  search.addEventListener("input", () => { state.q = search.value.toLowerCase(); draw(); });
  filters.append(search);
  main.append(
    el("h2", { style: "margin:4px 0" }, `${IDX.scenarios.length} scenarios, replayed step by step`),
    el("p", {}, "Every scenario that was tested at the IETF 127 hackathon, grouped by the question it answers. Open one to watch its messages appear one at a time, with the captured packet contents, the drafts concerned and the checker's verdict. Each result carries exactly one evidence class; the classes are never added together."),
    el("div", { class: "legend" }, Object.entries(IDX.classes).filter(([k]) => IDX.scenarios.some((s) => s.cls === k)).map(([k, v]) => el("div", {}, badge(k), " ", v.meaning))),
    filters, list);
  draw();
}

/* ------------------------------------------------------------------ scenario page */
const PANELS = [["entities", "Entities"], ["sequence", "Sequence"], ["message", "Message"], ["packets", "Packets"], ["comment", "Comment"], ["drafts", "Drafts"], ["verdict", "Checker"], ["timeline", "Timeline"]];
const S = { sc: null, step: 0, brk: -1, full: false, timer: null, panels: store.get("wimse-panels", {}) };

function viewSteps() {
  const sc = S.sc;
  let steps = sc.steps.map((x) => ({ ...x }));
  const b = S.brk >= 0 ? sc.breaks[S.brk] : null;
  if (b) {
    if (b.set_status) {
      const st = steps[b.set_status.step];
      st.label = st.label.replace(/->\s+\d{3}/, "-> " + b.set_status.status); st.result = false; st.mutated = true;
      st.comment = `The mutant: this hop's 200 was changed to ${b.set_status.status}. The set of statuses in the case is unchanged, so only a hop-by-hop comparison notices. Switch back to "Real capture" to compare.`;
      st.verdict = { expected: st.verdict ? st.verdict.expected : "", observed: String(b.set_status.status), ok: false, note: "changed in the mutant capture" };
      if (st.http) st.http = { ...st.http, resp: { ...st.http.resp, line: `HTTP/1.1 ${b.set_status.status} Forbidden` } };
    }
    if (b.add_step) steps.push({ ...b.add_step, injected: true });
    if (b.strip_responses) steps = steps.map((x) => ({ ...x, label: x.label.replace(/\s+->\s+.*$/, "  (no response)"), result: false, stripped: true, verdict: { expected: x.verdict ? x.verdict.expected : "", observed: "no response", ok: false, note: "responses removed from the capture" } }));
  }
  return steps;
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

function drawEntities(steps) {
  const sc = S.sc, all = [...(sc.context || []).map((e) => ({ ...e, off: true })), ...sc.entities];
  const byId = Object.fromEntries(all.map((e) => [e.id, e]));
  const xs = all.flatMap((e) => [e.x, e.x + e.w]).concat((sc.frames || []).flatMap((f) => [f.x, f.x + f.w]));
  const ys = all.flatMap((e) => [e.y, e.y + e.h]).concat((sc.frames || []).flatMap((f) => [f.y, f.y + f.h]));
  const x0 = Math.min(...xs) - 20, y0 = Math.min(...ys) - 20, w = Math.max(...xs) - x0 + 20, h = Math.max(...ys) - y0 + 20;
  const svg = sv("svg", { viewBox: `${x0} ${y0} ${w} ${h}`, width: "100%", role: "img", "aria-label": "Entities and the messages between them", style: "max-height:460px;display:block;margin:0 auto" });
  svg.append(heads("e"));
  for (const f of sc.frames || []) svg.append(sv("rect", { class: "frame fz-" + f.zone, x: f.x, y: f.y, width: f.w, height: f.h }), sv("text", { class: "framelabel fz-" + f.zone, x: f.x + 10, y: f.y + 20, "font-size": 15, "font-weight": "bold" }, f.label));
  const cur = steps[S.step], used = new Set(steps.slice(0, S.step + 1).flatMap((x) => [x.from, x.to]));
  for (const e of all) {
    const on = !e.off && used.has(e.id), isCur = cur && (cur.from === e.id || cur.to === e.id);
    svg.append(sv("rect", { class: "box z-" + (e.zone || "p") + (e.off || !on ? " off" : "") + (isCur ? " cur" : ""), x: e.x, y: e.y, width: e.w, height: e.h }),
      sv("text", { x: e.x + e.w / 2, y: e.y + e.h / 2 - 3, "text-anchor": "middle", "font-size": 14, "font-weight": "bold", class: e.off || !on ? "off" : "" }, e.label),
      sv("text", { x: e.x + e.w / 2, y: e.y + e.h / 2 + 15, "text-anchor": "middle", "font-size": 12, class: e.off || !on ? "off" : "" }, e.sub || ""));
  }
  const pair = {};
  steps.slice(0, S.step + 1).forEach((st, i) => {
    const a = byId[st.from], b = byId[st.to];
    if (!a || !b) return;
    const key = [st.from, st.to].sort().join("|");
    const off = (pair[key] = (pair[key] || 0) + 1) - 1;
    const [ax, ay] = clip(a, b.x + b.w / 2, b.y + b.h / 2), [bx, by] = clip(b, a.x + a.w / 2, a.y + a.h / 2);
    const nx = -(by - ay), ny = bx - ax, len = Math.hypot(nx, ny) || 1, sh = (off % 2 ? -1 : 1) * Math.ceil(off / 2) * 9 + (st.from > st.to ? 5 : -5);
    const p = (x, y) => [x + (nx / len) * sh, y + (ny / len) * sh];
    const [sx, sy] = p(ax, ay), [ex, ey] = p(bx, by);
    const good = st.result !== false && !st.injected;
    svg.append(sv("line", { class: "arr " + (good ? "good" : "bad") + (i === S.step ? " cur" : " old") + (st.dashed ? " dash" : ""), x1: sx, y1: sy, x2: ex, y2: ey, "marker-end": `url(#e-${good ? "ok" : "bad"})` }),
      sv("text", { x: (sx + ex) / 2, y: (sy + ey) / 2 - 4, "text-anchor": "middle", "font-size": 13, "font-weight": i === S.step ? "bold" : "normal" }, String(i + 1)));
  });
  return svg;
}

function drawSequence(steps) {
  const sc = S.sc, ents = sc.entities, n = ents.length, W = 1100, left = 20, bw = Math.min(190, (W - 40) / n - 8);
  const step = (W - 40 - bw) / Math.max(n - 1, 1), xs = ents.map((_, i) => (n === 1 ? W / 2 : left + bw / 2 + i * step));
  const row = 48, top = 92, H = top + steps.length * row + 20;
  const svg = sv("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", role: "img", "aria-label": "Sequence of messages" });
  svg.append(heads("s"));
  ents.forEach((e, i) => {
    svg.append(sv("rect", { class: "box z-" + (e.zone || "p"), x: xs[i] - bw / 2, y: 6, width: bw, height: 50 }), sv("text", { x: xs[i], y: 28, "text-anchor": "middle", "font-size": 13, "font-weight": "bold" }, e.label), sv("text", { x: xs[i], y: 46, "text-anchor": "middle", "font-size": 11 }, e.sub || ""),
      sv("line", { class: "life", x1: xs[i], y1: 56, x2: xs[i], y2: H - 6 }));
  });
  const idx = Object.fromEntries(ents.map((e, i) => [e.id, i]));
  steps.slice(0, S.step + 1).forEach((st, i) => {
    const a = idx[st.from], b = idx[st.to], y = top + i * row, isCur = i === S.step;
    if (a == null || b == null) return;
    const bad = st.injected || st.result === false;
    const label = `${i + 1}. ${st.label}`;
    svg.append(sv("line", { class: "arr " + (bad ? "bad" : "good") + (isCur ? " cur" : " old") + (st.dashed ? " dash" : ""), x1: xs[a], y1: y, x2: xs[b] + (xs[b] > xs[a] ? -2 : 2), y2: y, "marker-end": `url(#s-${bad ? "bad" : "ok"})` }));
    const mx = (xs[a] + xs[b]) / 2, lw = Math.abs(xs[a] - xs[b]);
    const t = sv("text", { x: mx, y: y - 7, "text-anchor": "middle", "font-size": 12.5, "font-weight": isCur ? "bold" : "normal" }, lw < 260 && label.length * 6.2 > lw + 120 ? label.slice(0, Math.floor((lw + 120) / 6.2) - 1) + "…" : label);
    t.append(sv("tspan", { class: "mk " + (bad ? "bad" : "ok") }, bad ? " ✗" : " ✓"));
    svg.append(t);
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

function panelMessage(st) {
  const sc = S.sc, box = el("div", { class: "msg" });
  if (st.http) {
    const h = st.http, cap = sc.capture, stripped = st.stripped;
    box.append(el("div", { class: "meta" }, (h.req_first && h.req_first !== h.frame ? `Request: frames ${h.req_first}\u2013${h.frame}` : `Request: frame ${h.frame}`) + (stripped ? "" : `; response: frame ${h.resp_frame}`) + `; TCP stream ${h.stream}`),
      el("h4", {}, "Request"), el("pre", {}, fmtHttp(h.req.line, h.req.headers, h.req.body, false)),
      el("h4", {}, "Response"), el("pre", {}, stripped ? "(removed in this mutant capture)" : fmtHttp(h.resp.line, h.resp.headers, h.resp.body, true)));
    const cmd = `tshark -r ${cap.file.split("/").pop()} ${sc.capture.file.includes("chain") ? "-d tcp.port==5051,http -d tcp.port==5060,http -d tcp.port==5061,http -d tcp.port==5062,http -d tcp.port==5063,http -d tcp.port==5064,http " : "-d tcp.port==5050,http "}-Y "frame.number==${h.frame}" -V`;
    box.append(el("div", { class: "row" }, el("pre", {}, cmd), copyButton(() => cmd)),
      el("div", { class: "row" }, el("span", {}, "Wireshark filter: "), el("code", {}, `frame.number == ${h.frame}`), copyButton(() => `frame.number == ${h.frame}`), el("a", { href: cap.url }, "Download the capture (.pcap)")));
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

function panelVerdict(st, last) {
  const sc = S.sc, b = S.brk >= 0 ? sc.breaks[S.brk] : null, box = el("div");
  const kv = el("div", { class: "kv" });
  if (st.verdict) kv.append(el("b", {}, "Expected"), el("span", {}, st.verdict.expected || "—"), el("b", {}, "Observed"), el("span", {}, st.verdict.observed), el("b", {}, "This step"), el("span", { class: st.verdict.ok ? "ok" : "fail" }, st.verdict.ok ? "✓ matches" : "✗ does NOT match"));
  kv.append(el("b", {}, "Checker"), el("span", {}, sc.checker), el("b", {}, "Evidence"), el("span", {}, badge(sc.cls), " ", IDX.classes[sc.cls].meaning));
  box.append(kv);
  if (st.verdict && st.verdict.note) box.append(el("p", { class: "muted" }, st.verdict.note));
  if (b) {
    box.append(el("h4", {}, "Mutant capture: " + b.name), el("p", {}, b.description), el("pre", { class: "fail" }, b.checker_output), el("p", { class: "muted" }, "Checker output recorded at build time on ", el("a", { href: IDX.repo + "/blob/main/checkers/negatives/" + b.mutant }, "checkers/negatives/" + b.mutant)));
  } else if (last) {
    box.append(el("p", {}, el("b", {}, "Result: "), el("span", { class: sc.result.verdict === "PASS" ? "ok" : sc.result.verdict === "FAIL" ? "fail" : "" }, sc.result.verdict), ". ", sc.result.text));
  }
  return box;
}

function panelTimeline(steps) {
  const sc = S.sc, box = el("div");
  const rel = steps.map((s) => (s.time ? s.time.rel : 0)), note = steps[S.step].time && steps[S.step].time.note;
  if (sc.bound) {
    const max = Math.max(sc.bound, ...rel), bar = el("div", { class: "bar", title: "0 to the promised bound" });
    steps.slice(0, S.step + 1).forEach((s, i) => { if (i) bar.append(el("i", { style: `left:${(rel[i] / max) * 100}%` })); });
    bar.append(el("b", { style: sc.bound >= max ? "right:4px" : `left:${(sc.bound / max) * 100}%` }, `bound ${sc.bound} s`));
    box.append(el("p", {}, `Time since t0 against the promised bound of ${sc.bound} s:`), bar);
  }
  box.append(el("table", { class: "tl" }, steps.map((s, i) => el("tr", { class: i === S.step ? "cur" : "", style: i > S.step ? "opacity:.35" : "" },
    el("td", {}, String(i + 1)), el("td", {}, s.time ? `+${s.time.rel} s` : ""), el("td", {}, s.time && i ? `(+${s.time.dt} s)` : ""), el("td", {}, s.label.length > 46 ? s.label.slice(0, 45) + "…" : s.label)))));
  if (note) box.append(el("p", { class: "muted" }, "Clock: " + note + "."));
  return box;
}

function render() {
  const sc = S.sc, steps = viewSteps(), n = steps.length;
  S.step = Math.max(0, Math.min(S.step, n - 1));
  const st = steps[S.step], last = S.step === n - 1;
  $("#count").textContent = `Step ${S.step + 1} of ${n}`;
  $("#prev").disabled = S.step === 0; $("#next").disabled = last; $("#play").textContent = S.timer ? "Pause" : "Play";
  history.replaceState(null, "", `#${sc.id}/${S.step + 1}` + (S.brk >= 0 ? `/b${S.brk + 1}` : ""));
  const put = (id, node) => { const p = $("#p-" + id + " .body"); p.replaceChildren(node); };
  put("entities", drawEntities(steps)); put("sequence", drawSequence(steps)); put("message", panelMessage(st)); put("packets", panelPackets(st));
  put("comment", el("p", { style: "margin:0;font-size:16px" }, st.comment || ""));
  put("drafts", panelDrafts(st)); put("verdict", panelVerdict(st, last)); put("timeline", panelTimeline(steps));
  const bk = $("#brk"); bk.replaceChildren();
  if (sc.breaks.length) {
    bk.append(el("b", {}, "Break it: "));
    const mk = (i, label) => { const b = el("button", { type: "button", "aria-pressed": String(S.brk === i) }, label); b.addEventListener("click", () => { S.brk = i; S.step = Math.min(S.step, viewSteps().length - 1); render(); }); return b; };
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
  $("#desc").textContent = S.sc.description;
  $("#exp").textContent = S.sc.expected ? "Expected: " + S.sc.expected : "";
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
    el("p", { class: "desc", id: "desc" }), el("p", { class: "exp muted", id: "exp" }),
    el("div", { class: "controls" },
      el("button", { id: "prev", type: "button", onclick: () => go(-1) }, "← Previous"), el("button", { id: "next", type: "button", class: "primary", onclick: () => go(1) }, "Next step →"),
      el("button", { id: "play", type: "button", onclick: () => { if (S.timer) { stop(); render(); } else { if (S.step >= viewSteps().length - 1) S.step = 0; S.timer = setInterval(() => { if (S.step >= viewSteps().length - 1) { stop(); render(); } else go(1); }, 1600); render(); } } }, "Play"),
      el("button", { type: "button", onclick: () => { stop(); S.step = 0; render(); } }, "Reset"), el("span", { class: "count", id: "count" }), toggles),
    el("div", { class: "brk", id: "brk" }),
    el("div", { class: "grid" }, left, right));
  applyPanels();
  document.addEventListener("keydown", (e) => {
    if ((e.target.matches && e.target.matches("select, input, textarea, button")) || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "ArrowRight") { go(1); e.preventDefault(); } else if (e.key === "ArrowLeft") { go(-1); e.preventDefault(); } else if (e.key === " ") { $("#play").click(); e.preventDefault(); }
  });
  const fromHash = () => { const [id, st, b] = location.hash.slice(1).split("/"); const known = IDX.scenarios.some((s) => s.id === id); return known ? loadScenario(id, parseInt(st, 10), b && b[0] === "b" ? parseInt(b.slice(1), 10) : 0) : loadScenario(IDX.scenarios.find((s) => s.id === "B_CHAIN") ? "B_CHAIN" : IDX.scenarios[0].id, 1); };
  let cur = null;
  window.addEventListener("hashchange", () => { const id = location.hash.slice(1).split("/")[0]; if (id !== cur) { cur = id; fromHash(); } });
  cur = location.hash.slice(1).split("/")[0]; fromHash();
}

(async function main() {
  try { IDX = await getJSON("data/index.json"); } catch (e) { document.body.append(el("p", { style: "padding:16px" }, "Could not load data/index.json. Serve this folder over HTTP (python3 -m http.server -d site) or open the published site.")); return; }
  document.body.prepend(header());
  document.body.append(el("footer", { class: "page" }, `Built from commit ${IDX.built_from} of `, el("a", { href: IDX.repo }, "the repository"), ". Every step comes from a committed capture or partner record; nothing here re-runs a peer."));
  document.body.dataset.page === "index" ? renderIndex() : renderScenario();
})();
