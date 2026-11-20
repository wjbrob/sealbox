// Drive the guest viewer in headless Chromium over the DevTools protocol (no dependencies:
// Node 22's built-in WebSocket). Used by the G29 gates to type passphrases, addresses and
// codes into the real page, and to record every request the page makes so a test can prove
// the secret never left it.
//
//   node web/guest/test/drive.mjs --browser /usr/bin/chromium --plan '<json>'
//
// Plan: { "secrets": ["..."], "steps": [ ... ] } with steps
//   { "open": url }                         navigate (the #fragment stays client-side)
//   { "waitText": "...", "timeoutMs": n }   until document.body.innerText contains it
//   { "waitVisible": "#id" }                until the element exists and is not [hidden]
//   { "fill": "#id", "value": "..." }       set an input's value
//   { "fillFromStdin": "#id", "name": "x" } print `NEED x` on stdout, read one stdin line, fill it
//   { "submit": "#form" }                   form.requestSubmit()
//   { "click": "#id" }
//   { "assertNoText": "..." }
//   { "assertUrlNoFragment": true }         the address bar no longer shows the fragment
//   { "sleepMs": n }
// Prints one final JSON line: { ok, error?, text, requests:[{url, method, postData}], leaks:[...] }
// and exits 0 only when every step passed and no request carried a secret.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const browserBin = arg('--browser') || 'chromium';
const plan = JSON.parse(arg('--plan') || fs.readFileSync(arg('--plan-file'), 'utf8'));
const secrets = (plan.secrets || []).filter(Boolean);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const stdinLines = [];
let stdinWaiter = null;
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (l) => {
  if (stdinWaiter) {
    const w = stdinWaiter;
    stdinWaiter = null;
    w(l);
  } else {
    stdinLines.push(l);
  }
});
function readLine() {
  if (stdinLines.length) return Promise.resolve(stdinLines.shift());
  return new Promise((r) => {
    stdinWaiter = r;
  });
}

const profileRoot = process.env.CARGO_TARGET_DIR || os.tmpdir();
fs.mkdirSync(path.join(profileRoot, 'g29-chromium'), { recursive: true });
const profile = fs.mkdtempSync(path.join(profileRoot, 'g29-chromium', 'p-'));
const child = spawn(
  browserBin,
  [
    '--headless=new',
    '--disable-gpu',
    // CI runners have a small /dev/shm; Chromium otherwise stalls or crashes on start-up there.
    '--disable-dev-shm-usage',
    '--no-sandbox',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--remote-debugging-port=0',
    `--user-data-dir=${profile}`,
    'about:blank',
  ],
  { stdio: ['ignore', 'ignore', 'pipe'] },
);
let browserErr = '';
child.stderr.on('data', (d) => {
  browserErr = (browserErr + d.toString()).slice(-4000);
});

const requests = [];
let ws;
let nextId = 1;
const pending = new Map();
let sessionId;

function send(method, params = {}, withSession = true) {
  const id = nextId++;
  const msg = { id, method, params };
  if (withSession && sessionId) msg.sessionId = sessionId;
  ws.send(JSON.stringify(msg));
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject, method });
  });
}

async function evaluate(expression) {
  const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error(`page exception: ${JSON.stringify(r.exceptionDetails).slice(0, 400)}`);
  return r.result ? r.result.value : undefined;
}

const bodyText = () => evaluate('document.body ? document.body.innerText : ""');

async function waitFor(pred, timeoutMs, what) {
  const deadline = Date.now() + (timeoutMs || 20000);
  for (;;) {
    if (await pred()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(150);
  }
}

async function connect() {
  const portFile = path.join(profile, 'DevToolsActivePort');
  // A cold Chromium on a busy CI runner (cargo test compiling alongside) can take well over 20 s.
  // Fail at once, with its stderr, if it exits instead of starting.
  const startMs = Number(process.env.SEALBOX_BROWSER_START_MS || 60000);
  await waitFor(async () => {
    if (child.exitCode !== null) throw new Error(`browser exited (${child.exitCode}) before DevTools came up`);
    return fs.existsSync(portFile) && fs.readFileSync(portFile, 'utf8').includes('\n');
  }, startMs, 'DevToolsActivePort');
  const [port, wsPath] = fs.readFileSync(portFile, 'utf8').trim().split('\n');
  ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath}`);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = (e) => reject(new Error(`devtools websocket: ${e.message || 'error'}`));
  });
  ws.onmessage = (ev) => {
    const msg = JSON.parse(typeof ev.data === 'string' ? ev.data : ev.data.toString());
    if (msg.id && pending.has(msg.id)) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) p.reject(new Error(`${p.method}: ${msg.error.message}`));
      else p.resolve(msg.result);
      return;
    }
    if (msg.method === 'Network.requestWillBeSent') {
      const r = msg.params.request;
      requests.push({ url: r.url, fragment: r.urlFragment || '', method: r.method, postData: r.postData || '' });
    }
  };
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' }, false);
  ({ sessionId } = await send('Target.attachToTarget', { targetId, flatten: true }, false));
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Network.enable');
}

async function runStep(step) {
  if (step.open) {
    await send('Page.navigate', { url: step.open });
    await waitFor(async () => (await evaluate('document.readyState')) === 'complete', 20000, 'page load');
  } else if (step.waitText) {
    await waitFor(async () => (await bodyText()).includes(step.waitText), step.timeoutMs, `text ${JSON.stringify(step.waitText)}`);
  } else if (step.waitVisible) {
    const sel = JSON.stringify(step.waitVisible);
    await waitFor(
      async () => evaluate(`(() => { const e = document.querySelector(${sel}); return !!e && !e.closest('[hidden]'); })()`),
      step.timeoutMs,
      `visible ${step.waitVisible}`,
    );
  } else if (step.fill || step.fillFromStdin) {
    const sel = step.fill || step.fillFromStdin;
    let value = step.value;
    if (step.fillFromStdin) {
      process.stdout.write(`NEED ${step.name || 'input'}\n`);
      value = (await readLine()).trim();
    }
    const ok = await evaluate(
      `(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.value = ${JSON.stringify(value)}; e.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`,
    );
    if (!ok) throw new Error(`no element ${sel}`);
  } else if (step.submit) {
    const ok = await evaluate(`(() => { const f = document.querySelector(${JSON.stringify(step.submit)}); if (!f) return false; f.requestSubmit(); return true; })()`);
    if (!ok) throw new Error(`no form ${step.submit}`);
  } else if (step.click) {
    const ok = await evaluate(`(() => { const e = document.querySelector(${JSON.stringify(step.click)}); if (!e) return false; e.click(); return true; })()`);
    if (!ok) throw new Error(`no element ${step.click}`);
  } else if (step.assertNoText) {
    const t = await bodyText();
    if (t.includes(step.assertNoText)) throw new Error(`page unexpectedly shows ${JSON.stringify(step.assertNoText)}`);
  } else if (step.assertUrlNoFragment) {
    const href = await evaluate('location.href');
    if (href.includes('#')) throw new Error(`fragment still in the address bar: ${href}`);
  } else if (step.sleepMs) {
    await sleep(step.sleepMs);
  } else {
    throw new Error(`unknown step ${JSON.stringify(step)}`);
  }
}

function leaksOf() {
  const leaks = [];
  for (const r of requests) {
    for (const s of secrets) {
      for (const form of new Set([s, encodeURIComponent(s)])) {
        if (r.url.includes(form) || r.postData.includes(form)) leaks.push({ url: r.url, secret: '<redacted>' });
      }
    }
  }
  return leaks;
}

let result = { ok: false };
let exitCode = 1;
try {
  await connect();
  for (const step of plan.steps) await runStep(step);
  const leaks = leaksOf();
  result = { ok: leaks.length === 0, error: leaks.length ? 'a request carried the secret' : undefined, text: await bodyText(), requests: requests.map(({ url, method }) => ({ url, method })), leaks };
  exitCode = result.ok ? 0 : 1;
} catch (err) {
  let text = '';
  try {
    text = await bodyText();
  } catch {
    /* page gone */
  }
  result = { ok: false, error: String(err && err.message ? err.message : err), text, requests: requests.map(({ url, method }) => ({ url, method })), leaks: leaksOf(), browserStderr: browserErr.slice(-1500) };
} finally {
  try {
    if (ws && ws.readyState === 1) await Promise.race([send('Browser.close', {}, false), sleep(2000)]);
  } catch {
    /* already closing */
  }
  await sleep(300);
  if (child.exitCode === null) child.kill('SIGKILL');
  rl.close();
  try {
    fs.rmSync(profile, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}
process.stdout.write(`${JSON.stringify(result)}\n`);
process.exit(exitCode);
