// Drives the site in headless Chrome over the DevTools protocol and checks the controls.
// Usage: node site/test_site.mjs [base-url]     (serve site/ first: python3 -m http.server -d site 8765)
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = process.argv[2] || "http://localhost:8765";
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const port = 9300 + Math.floor(Math.random() * 500);
const chrome = spawn(CHROME, ["--headless=new", "--disable-gpu", `--remote-debugging-port=${port}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), "wimse-"))}`, "--window-size=1500,1200", "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (name, ok, extra = "") => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : "  " + extra}`); if (!ok) failures++; };

async function connect() {
  for (let i = 0; i < 50; i++) {
    try {
      const tabs = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
      const page = tabs.find((t) => t.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch (e) { /* not up yet */ }
    await sleep(200);
  }
  throw new Error("Chrome did not start");
}

const ws = new WebSocket(await connect());
await new Promise((r) => ws.addEventListener("open", r));
let id = 0; const pending = new Map(); const errors = [];
ws.addEventListener("message", (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
  if (d.method === "Runtime.exceptionThrown") errors.push(d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text);
  if (d.method === "Runtime.consoleAPICalled" && d.params.type === "error") errors.push(d.params.args.map((a) => a.value).join(" "));
});
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => { const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true }); return r.result?.result?.value; };
const go = async (url) => { await send("Page.navigate", { url }); await sleep(900); };

await send("Runtime.enable"); await send("Page.enable");

// index
await go(`${BASE}/index.html`);
check("index lists scenarios", (await ev(`document.querySelectorAll('ul.list li').length`)) >= 99);
check("filter by class works", (await ev(`(()=>{const b=[...document.querySelectorAll('.filters button')].find(x=>x.textContent.startsWith('Mocked'));b.click();return document.querySelectorAll('ul.list li').length})()`)) === 6);
check("GitHub pop-over holds the clone command", (await ev(`document.querySelector('details.gh pre').textContent`)).includes("git clone https://github.com/apelov/IETF127-Hackathon-AI2II-WIMSE.git"));

// scenario: stepping
await go(`${BASE}/scenario.html#B_CHAIN/1`);
check("B_CHAIN has 9 steps", (await ev(`document.getElementById('count').textContent`)) === "Step 1 of 9");
check("previous is disabled on step 1", (await ev(`document.getElementById('prev').disabled`)) === true);
check("only message 1 is drawn at step 1", (await ev(`document.querySelectorAll('#p-sequence svg line.arr').length`)) === 1);
await ev(`document.getElementById('next').click()`); await ev(`document.getElementById('next').click()`);
check("Next adds messages (3 arrows at step 3)", (await ev(`document.querySelectorAll('#p-sequence svg line.arr').length`)) === 3);
check("hash follows the step", (await ev(`location.hash`)) === "#B_CHAIN/3");
check("message panel shows a real frame", /^Frame 268 \(request\), 272/.test(await ev(`document.querySelector('#p-message .meta').textContent`)));
check("comment panel has text", (await ev(`document.querySelector('#p-comment .body').textContent`)).length > 40);
check("drafts panel names a draft", (await ev(`document.querySelector('#p-drafts .body').textContent`)).includes("identity-chaining-17"));
check("verdict panel: step matches", (await ev(`document.querySelector('#p-verdict .body').textContent`)).includes("matches"));

// keyboard
await ev(`document.body.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowRight',bubbles:true}))`);
check("right arrow advances", (await ev(`document.getElementById('count').textContent`)) === "Step 4 of 9");
await ev(`document.body.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowLeft',bubbles:true}))`);
check("left arrow goes back", (await ev(`document.getElementById('count').textContent`)) === "Step 3 of 9");
await ev(`document.body.dispatchEvent(new KeyboardEvent('keydown',{key:' ',bubbles:true}))`); await sleep(1900);
check("space starts Play and it advances", (await ev(`document.getElementById('count').textContent`)) !== "Step 3 of 9");
await ev(`document.body.dispatchEvent(new KeyboardEvent('keydown',{key:' ',bubbles:true}))`);
check("space again pauses", (await ev(`document.getElementById('play').textContent`)) === "Play");

// panel toggles
await ev(`(()=>{const c=document.getElementById('t-entities');c.checked=false;c.dispatchEvent(new Event('change'))})()`);
check("turning Entities off hides the panel", (await ev(`document.getElementById('p-entities').classList.contains('hidden')`)) === true);
check("the other panels stay", (await ev(`document.getElementById('p-sequence').classList.contains('hidden')`)) === false);
await go(`${BASE}/scenario.html#B_CHAIN/1`);
check("the choice is remembered after reload", (await ev(`document.getElementById('p-entities').classList.contains('hidden')`)) === true);
await ev(`(()=>{const c=document.getElementById('t-entities');c.checked=true;c.dispatchEvent(new Event('change'))})()`);

// dropdown
await ev(`(()=>{const s=document.getElementById('sel');s.value='C3';s.dispatchEvent(new Event('change'))})()`);
await sleep(700);
check("dropdown switches scenario", (await ev(`document.getElementById('head').textContent`)).startsWith("C3"));
check("C3 (replay) has 2 steps", (await ev(`document.getElementById('count').textContent`)) === "Step 1 of 2");

// break it
await go(`${BASE}/scenario.html#C7/1`);
await ev(`[...document.querySelectorAll('#brk button')].find(b=>b.textContent==='One hop flipped').click()`);
await ev(`document.getElementById('next').click()`);
check("mutant: step 2 shows 403", (await ev(`document.querySelector('#p-message .body').textContent`)).includes("HTTP/1.1 403 Forbidden"));
check("mutant: checker output is shown", (await ev(`document.querySelector('#p-verdict .body').textContent`)).includes("FAIL C7"));
check("mutant: hash records it", (await ev(`location.hash`)) === "#C7/2/b2");
await go(`${BASE}/scenario.html#B_CHAIN/9/b2`);
check("mutant link reopens the leaked-token view", (await ev(`document.getElementById('count').textContent`)) === "Step 9 of 10");

// partner and report scenarios
await go(`${BASE}/scenario.html#redthread-p2-17nov-killswitch/3`);
check("report scenario is badged Partner report", (await ev(`document.querySelector('#head .badge').textContent`)) === "Partner report");
check("report scenario shows 5.8 s", (await ev(`document.body.textContent`)).includes("5.8 s"));
await go(`${BASE}/scenario.html#mintid-issuer/2`);
check("MintID scenario draws the bound bar", (await ev(`!!document.querySelector('#p-timeline .bar')`)) === true);

// phone width (device emulation): the page must not scroll sideways
await send("Emulation.setDeviceMetricsOverride", { width: 390, height: 800, deviceScaleFactor: 1, mobile: true });
for (const url of ["index.html", "scenario.html#B_CHAIN/5", "scenario.html#C7/2/b2", "scenario.html#mintid-kill_switch/4"]) {
  await go(`${BASE}/${url}`);
  const w = await ev(`document.documentElement.scrollWidth`);
  check(`phone width: no sideways scroll on ${url} (width ${w})`, w <= 391);
}
await send("Emulation.clearDeviceMetricsOverride");

// dark theme follows the system setting
await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
await go(`${BASE}/scenario.html#C7/2/b2`);
check("dark theme: dark background", (await ev(`getComputedStyle(document.body).backgroundColor`)) === "rgb(14, 18, 24)");
check("dark theme: text is light", (await ev(`getComputedStyle(document.body).color`)) === "rgb(232, 236, 242)");
if (process.env.SHOT_DARK) {
  const shot = await send("Page.captureScreenshot", { format: "png" });
  (await import("node:fs")).writeFileSync(process.env.SHOT_DARK, Buffer.from(shot.result.data, "base64"));
}
await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });

check("no console errors or exceptions", errors.length === 0, errors.join(" | "));
ws.close(); chrome.kill();
console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
