// G28 fixture e2e: the unpacked MV3 extension in headless Chromium against a Gmail-like
// fixture page and a mock of the Google endpoints (mock-google.mjs). Proves the extension
// against a FIXTURE, not real Gmail.
//
//   node test/fixture/e2e.mjs --dist dist/chrome --wasm-node wasm/pkg-node \
//        --scratch ../target/agent-ext/g28-e2e [--browser /usr/bin/chromium]
//
// Flow (every step through the real UI):
//  1. options page: save OAuth client id → "Connect Google" → launchWebAuthFlow + PKCE
//     against the mock IdP → token → users.getProfile;
//  2. options page: create Alice's key with a passphrase (wrapped in storage.local);
//  3. gpg ("Gina") encrypts+signs a PGP/MIME message to Alice carrying an Autocrypt header;
//     the mock serves it as message 18c0ffee00000001;
//  4. fixture Gmail page: the content script asks the API (metadata) and places
//     "Decrypt with Sealbox" on that message only → reader iframe fetches format=raw →
//     decrypted text + "Good signature" (Gina's key learned from Autocrypt);
//  5. fixture page: "Sealbox" button → compose iframe → encrypt to Gina → the mock receives
//     users.messages.send; the raw is valid PGP/MIME and gpg decrypts it (GOODSIG Alice).
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import puppeteer from 'puppeteer-core';
import { startMock } from './mock-google.mjs';
import http from 'node:http';

const arg = (n, d) => {
  const i = process.argv.indexOf(n);
  return i > 0 ? process.argv[i + 1] : d;
};
const dist = path.resolve(arg('--dist', 'dist/chrome'));
const wasmNode = path.resolve(arg('--wasm-node', 'wasm/pkg-node'));
const scratch = path.resolve(arg('--scratch', '../target/agent-ext/g28-e2e'));
const browserBin = arg('--browser', '/usr/bin/chromium');
const CLIENT_ID = 'fixture-client-id.apps.googleusercontent.com';
const PASS = 'fixture passphrase 1';

fs.rmSync(scratch, { recursive: true, force: true });
fs.mkdirSync(scratch, { recursive: true });
const sb = createRequire(import.meta.url)(path.join(wasmNode, 'sealbox_wasm.js'));

let failed = 0;
const step = async (name, fn) => {
  try {
    const r = await fn();
    console.log(`PASS ${name}`);
    return r;
  } catch (e) {
    failed++;
    console.log(`FAIL ${name}: ${e?.message ?? e}`);
    throw e;
  }
};
const assert = (c, m) => {
  if (!c) throw new Error(m);
};

// --- gpg (isolated GNUPGHOME) -------------------------------------------------------------
const gnupg = path.join(scratch, 'gnupg');
fs.mkdirSync(gnupg, { mode: 0o700 });
const genv = { ...process.env, GNUPGHOME: gnupg };
const gpg = (args, input) =>
  execFileSync('gpg', ['--batch', '--yes', '--no-tty', '--pinentry-mode', 'loopback', '--passphrase', '', '--trust-model', 'always', ...args], { env: genv, input, maxBuffer: 64 << 20, stdio: ['pipe', 'pipe', 'pipe'] });
gpg(['--quick-gen-key', 'Gina Gpg <gina@sealbox.test>', 'future-default', 'default', 'never']);
const ginaPub = gpg(['--armor', '--export', 'gina@sealbox.test']).toString();

// --- mock + browser ----------------------------------------------------------------------
execFileSync('openssl', [
  'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '2',
  '-subj', '/CN=sealbox-g28-fixture', '-addext', 'subjectAltName=DNS:mail.google.com,DNS:gmail.googleapis.com,DNS:accounts.google.com,DNS:oauth2.googleapis.com',
  '-keyout', path.join(scratch, 'key.pem'), '-out', path.join(scratch, 'cert.pem'),
], { stdio: 'ignore' });
const { server, port, state } = await startMock({
  cert: fs.readFileSync(path.join(scratch, 'cert.pem')),
  key: fs.readFileSync(path.join(scratch, 'key.pem')),
  clientId: CLIENT_ID,
});
const hosts = ['mail.google.com', 'gmail.googleapis.com', 'accounts.google.com', 'oauth2.googleapis.com'];
const browser = await puppeteer.launch({
  executablePath: browserBin,
  headless: true,
  pipe: true,
  enableExtensions: [dist],
  userDataDir: path.join(scratch, 'profile'),
  args: [
    '--no-sandbox',
    '--disable-gpu',
    '--no-first-run',
    `--host-resolver-rules=${hosts.map((h) => `MAP ${h} 127.0.0.1:${port}`).join(', ')}, EXCLUDE localhost`,
    // Throw-away profile; only the four mapped hosts are reachable, all served by the mock.
    '--ignore-certificate-errors',
  ],
});
const browserPid = browser.process()?.pid;
let exitCode = 1;
try {
  const sw = await step('extension loads (MV3 service worker up)', async () =>
    browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().endsWith('/background.js'), { timeout: 20000 }),
  );
  const extId = new URL(sw.url()).host;
  const ext = (p) => `chrome-extension://${extId}/${p}`;

  const opts = await browser.newPage();
  await opts.goto(ext('options.html'));
  await step('options: OAuth (launchWebAuthFlow + PKCE S256) against the mock IdP', async () => {
    await opts.waitForSelector('#client-id');
    await opts.type('#client-id', CLIENT_ID);
    await opts.click('#connect');
    await opts.waitForFunction(() => document.getElementById('account').textContent.startsWith('Connected as'), { timeout: 20000 }).catch(async () => {
      throw new Error(`${await opts.$eval('#status', (e) => e.textContent).catch(() => '?')} | mock errors: ${state.errors.join('; ')}`);
    });
    const t = await opts.$eval('#account', (e) => e.textContent);
    assert(t === 'Connected as alice@sealbox.test', t);
    assert(state.log.some((l) => l.startsWith('POST oauth2.googleapis.com /token')), 'no token exchange');
  });

  const alicePub = await step('options: create key; secret stored only wrapped (Argon2id/XChaCha)', async () => {
    await opts.type('#new-name', 'Alice Fixture');
    await opts.$eval('#new-email', (e) => (e.value = ''));
    await opts.type('#new-email', 'alice@sealbox.test');
    await opts.type('#new-pass', PASS);
    await opts.click('#generate');
    await opts.waitForSelector('#key-have:not([hidden])', { timeout: 30000 });
    const pub = await opts.$eval('#my-public', (e) => e.value);
    assert(pub.includes('BEGIN PGP PUBLIC KEY BLOCK'), 'no public key shown');
    const stored = await sw.worker().then((w) => w.evaluate(async () => JSON.stringify(await chrome.storage.local.get(null))));
    assert(!stored.includes('PRIVATE KEY'), 'plaintext secret key in storage.local');
    assert(JSON.parse(stored).identity.wrapped.includes('"kdf":"argon2id"'), 'identity not wrapped');
    return pub;
  });

  // Gina → Alice, RFC 3156, signed, with Autocrypt (Gina's key). Built by gpg + a hand MIME frame.
  const inner =
    'Content-Type: text/plain; charset=utf-8; protected-headers="v1"\r\nSubject: Fixture secret plan\r\n' +
    'From: Gina Gpg <gina@sealbox.test>\r\nTo: alice@sealbox.test\r\n\r\nMeet at the fixture at noon. — Gina\r\n';
  fs.writeFileSync(path.join(scratch, 'alice.asc'), alicePub);
  gpg(['--import', path.join(scratch, 'alice.asc')]);
  const ct = gpg(['--armor', '--encrypt', '--sign', '-u', 'gina@sealbox.test', '-r', 'alice@sealbox.test'], inner).toString();
  const ac = sb.autocryptHeader('gina@sealbox.test', ginaPub, true);
  state.messages.set(
    '18c0ffee00000001',
    Buffer.from(
      'From: Gina Gpg <gina@sealbox.test>\r\nTo: alice@sealbox.test\r\nSubject: ...\r\nDate: Tue, 27 Oct 2026 12:00:00 +0000\r\n' +
        `Message-ID: <fixture-1@sealbox.test>\r\nAutocrypt: ${ac}\r\nMIME-Version: 1.0\r\n` +
        'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="fx"\r\n\r\n' +
        '--fx\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n' +
        '--fx\r\nContent-Type: application/octet-stream; name="encrypted.asc"\r\n\r\n' +
        ct.replace(/\r?\n/g, '\r\n') +
        '\r\n--fx--\r\n',
    ),
  );
  state.messages.set('18c0ffee00000002', Buffer.from('From: plain@sealbox.test\r\nTo: alice@sealbox.test\r\nSubject: hi\r\n\r\nplain\r\n'));

  const gmail = await browser.newPage();
  await gmail.goto('https://mail.google.com/mail/u/0/#inbox');
  await step('content script: "Decrypt with Sealbox" only on the PGP/MIME message (API metadata, not DOM)', async () => {
    await gmail.waitForSelector('div[data-legacy-message-id="18c0ffee00000001"] .sealbox-decrypt', { timeout: 20000 });
    await new Promise((r) => setTimeout(r, 1000));
    const onPlain = await gmail.$('div[data-legacy-message-id="18c0ffee00000002"] .sealbox-decrypt');
    assert(!onPlain, 'decrypt button on a plaintext message');
    assert(state.log.some((l) => l.includes('/messages/18c0ffee00000001?format=metadata')), 'no metadata API call');
    assert(await gmail.$('#sealbox-compose'), 'no Sealbox compose button');
  });

  await step('reader panel: raw via API → wasm decrypt → text + Good signature (key via Autocrypt)', async () => {
    await gmail.click('div[data-legacy-message-id="18c0ffee00000001"] .sealbox-decrypt');
    const frameEl = await gmail.waitForSelector('iframe.sealbox-inline-frame');
    const frame = await frameEl.contentFrame();
    await frame.waitForSelector('#msg:not([hidden]), #status.bad', { timeout: 30000 });
    const r = await frame.evaluate(() => ({
      subject: document.getElementById('subject').textContent,
      body: document.getElementById('body').textContent,
      sig: document.getElementById('sig').textContent,
      status: document.getElementById('status').textContent,
    }));
    assert(r.body.includes('Meet at the fixture at noon.'), `body: ${JSON.stringify(r)}`);
    assert(r.subject === 'Fixture secret plan', `subject ${r.subject}`);
    assert(r.sig.includes('Good signature'), `sig ${r.sig}`);
    assert(state.log.some((l) => l.includes('/messages/18c0ffee00000001?format=raw')), 'raw not fetched via API');
    // The plaintext never entered Gmail's DOM (it lives in the extension-origin iframe).
    assert(!(await gmail.evaluate(() => document.body.innerText.includes('Meet at the fixture'))), 'plaintext leaked into page DOM');
  });

  const sent = await step('compose panel: encrypt to Gina (Autocrypt-learned key) → users.messages.send', async () => {
    await gmail.click('#sealbox-compose');
    const frameEl = await gmail.waitForSelector('#sealbox-overlay iframe');
    const frame = await frameEl.contentFrame();
    await frame.waitForSelector('#form:not([hidden])', { timeout: 20000 });
    await frame.type('#to', 'Gina Gpg <gina@sealbox.test>');
    await frame.type('#subject', 'Re: Fixture secret plan');
    await frame.type('#body', 'Noon works.\nSee you — Alice');
    await frame.waitForFunction(() => document.getElementById('keys').textContent.includes('have keys'), { timeout: 5000 });
    await frame.click('#send');
    await frame.waitForFunction(() => /Sent ✓|error|Cannot/i.test(document.getElementById('status').textContent), { timeout: 30000 });
    const st = await frame.$eval('#status', (e) => e.textContent);
    assert(st.startsWith('Sent ✓'), st);
    assert(state.sent.length === 1, `mock got ${state.sent.length} sends`);
    return state.sent[0].raw;
  });

  await step('sent raw is RFC 3156 PGP/MIME with protected subject + Autocrypt; gpg decrypts it', async () => {
    const p = sb.parseMessage(sent);
    assert(p.kind === 'pgpMimeEncrypted', `kind ${p.kind}`);
    assert(p.headers.subject === '...', `outer subject leaked: ${p.headers.subject}`);
    assert(!sent.toString().includes('Noon works'), 'plaintext in sent raw');
    assert(p.headers.to[0].address === 'gina@sealbox.test', 'To header');
    const acs = sb.parseAutocryptHeaders(p.headers.autocrypt, 'alice@sealbox.test');
    assert(acs.forSender, 'no valid Autocrypt header for Alice');
    const r = spawnSync('gpg', ['--batch', '--no-tty', '--pinentry-mode', 'loopback', '--passphrase', '', '--status-fd', '2', '--decrypt'], { env: genv, input: p.ciphertext });
    assert(r.status === 0, `gpg exit ${r.status}: ${r.stderr}`);
    const out = r.stdout.toString();
    assert(out.includes('Noon works.'), 'body not in gpg plaintext');
    assert(out.includes('protected-headers="v1"') && /Subject: Re: Fixture secret plan/.test(out), 'protected subject missing');
    assert(r.stderr.toString().includes('[GNUPG:] GOODSIG'), 'gpg: no GOODSIG');
  });

  await step('reader list view: users.messages.list finds the encrypted message only', async () => {
    const lp = await browser.newPage();
    await lp.goto(ext('reader.html'));
    await lp.waitForSelector('#items .card, #items p', { timeout: 15000 });
    const links = await lp.$$eval('#items a', (as) => as.map((a) => a.textContent));
    assert(links.length === 1 && links[0].includes('18c0ffee00000001'), `list: ${links}`);
    await lp.close();
  });

  await step('HTML part in the reader frame: remote image never fetched (R8 CSP), text still renders', async () => {
    // A throw-away pixel server: the only way a remote image could reach it is a fetch
    // from the sandboxed srcdoc frame; the CSP must prevent that.
    let pixelHits = 0;
    const pixel = http.createServer((req, res) => {
      pixelHits += 1;
      res.writeHead(200, { 'content-type': 'image/gif' });
      res.end(Buffer.from('R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==', 'base64'));
    });
    await new Promise((r) => pixel.listen(0, '127.0.0.1', r));
    const pixelUrl = `http://127.0.0.1:${pixel.address().port}/pixel.gif`;
    try {
      const lp = await browser.newPage();
      await lp.goto(ext('reader.html'));
      await lp.waitForSelector('#html', { timeout: 15000 });
      // Through the reader's own wrapper (document CSP; the build bundles the module into
      // reader.js, so the wrapper is taken from its dependency-free source here) …
      const { htmlDocument } = await import(new URL('../../chrome/src/html-part.js', import.meta.url));
      const wrapped = htmlDocument(`<p id="t">hello <b>html</b></p><img id="i" src="${pixelUrl}"><p style="color:red" id="s">styled</p>`);
      assert(wrapped.includes('Content-Security-Policy') && wrapped.includes("default-src 'none'"), 'wrapper has no document CSP');
      await lp.evaluate((doc) => {
        const f = document.getElementById('html');
        f.hidden = false;
        f.srcdoc = doc;
      }, wrapped);
      await new Promise((r) => setTimeout(r, 1500));
      let fr = lp.frames().find((f) => f.url() === 'about:srcdoc');
      assert(fr, 'srcdoc frame did not load (frame-src?)');
      let r = await fr.evaluate(() => ({ text: document.getElementById('t').textContent, w: document.getElementById('i').naturalWidth, styled: getComputedStyle(document.getElementById('s')).color }));
      assert(r.text === 'hello html', `text: ${r.text}`);
      assert(r.w === 0, `remote image rendered (${r.w}px)`);
      assert(r.styled === 'rgb(255, 0, 0)', `inline style lost: ${r.styled}`);
      assert(pixelHits === 0, `pixel fetched ${pixelHits}× through the wrapped document`);
      // … and a bare document without the wrapper: the manifest CSP alone must still block it.
      await lp.evaluate((url) => {
        document.getElementById('html').srcdoc = `<img id="i" src="${url}"><p id="t">bare</p>`;
      }, pixelUrl);
      await new Promise((r) => setTimeout(r, 1500));
      fr = lp.frames().find((f) => f.url() === 'about:srcdoc');
      r = await fr.evaluate(() => ({ text: document.getElementById('t').textContent, w: document.getElementById('i').naturalWidth }));
      assert(r.text === 'bare' && r.w === 0, `bare document: ${JSON.stringify(r)}`);
      assert(pixelHits === 0, `pixel fetched ${pixelHits}× through the bare document`);
      await lp.close();
    } finally {
      pixel.close();
    }
  });

  await step('only documented Google endpoints were called', async () => {
    const allowed = [
      /^GET mail\.google\.com \/mail\//,
      /^GET accounts\.google\.com \/o\/oauth2\/v2\/auth\?/,
      /^POST oauth2\.googleapis\.com \/token$/,
      /^GET gmail\.googleapis\.com \/gmail\/v1\/users\/me\/profile$/,
      /^GET gmail\.googleapis\.com \/gmail\/v1\/users\/me\/messages\/[0-9a-f]+\?format=(raw|metadata&metadataHeaders=Content-Type)$/,
      /^POST gmail\.googleapis\.com \/gmail\/v1\/users\/me\/messages\/send$/,
      /^GET gmail\.googleapis\.com \/gmail\/v1\/users\/me\/messages\?maxResults=25&q=filename%3Aencrypted\.asc$/,
      /^OPTIONS /,
      /^GET mail\.google\.com \/favicon\.ico$/,
      // Chromium's own account-consistency probe (source=ChromiumBrowser), not the extension.
      /^POST accounts\.google\.com \/ListAccounts\?.*source=ChromiumBrowser/,
    ];
    const odd = state.log.filter((l) => !allowed.some((re) => re.test(l)));
    assert(!odd.length, `unexpected requests: ${odd.join(' | ')}`);
    console.log(`# ${state.log.length} requests to the mock: ${[...new Set(state.log.map((l) => l.replace(/\?.*/, '').replace(/[0-9a-f]{16}/, '{id}')))].join(', ')}`);
  });
  exitCode = failed ? 1 : 0;
} catch {
  exitCode = 1;
} finally {
  await browser.close().catch(() => {
    // Only ever kill the Chromium we launched, verified by name.
    if (browserPid) {
      const comm = spawnSync('ps', ['-o', 'comm=', '-p', String(browserPid)]).stdout.toString().trim();
      if (/chrom/i.test(comm)) process.kill(browserPid, 'SIGKILL');
    }
  });
  server.close();
}
console.log(exitCode === 0 ? 'E2E PASS' : 'E2E FAIL');
process.exit(exitCode);
