// Interop test for the guest viewer core, run with `node --test web/guest/test/viewer.test.mjs`.
//
// gpg (the oracle) encrypts a symmetric message → the viewer code must decrypt it; the viewer
// encrypts a reply to a gpg-generated key → gpg must decrypt it. gpg runs in an isolated
// GNUPGHOME under target/ and its agent is killed afterwards.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  MODE_COPY,
  decryptGuestMessage,
  describeError,
  describeKey,
  encryptReply,
  fetchGuest,
  formatExpiry,
  formatWait,
  normalizeCode,
  parseGuestId,
  passphraseFromHash,
  plausibleEmail,
  requestCode,
  verifyCode,
} from '../viewer-core.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const guestDir = path.resolve(here, '..');
const repoRoot = path.resolve(guestDir, '..', '..');
const GPG = '/usr/bin/gpg';
const GPGCONF = '/usr/bin/gpgconf';

/** Load the exact browser bundle (UMD/IIFE) in this realm; `openpgp` is its completion value. */
function loadBrowserOpenpgp() {
  const file = path.join(guestDir, 'vendor', 'openpgp.min.js');
  const src = fs.readFileSync(file, 'utf8');
  return vm.runInThisContext(`${src};openpgp`, { filename: file });
}

const targetDir = process.env.CARGO_TARGET_DIR || path.join(repoRoot, 'target');
let work; // temp dir holding GNUPGHOME + files
let gnupghome;
let openpgp;

function gpg(args, opts = {}) {
  return execFileSync(GPG, ['--homedir', gnupghome, '--batch', '--yes', '--no-tty', '--pinentry-mode', 'loopback', ...args], {
    env: { ...process.env, GNUPGHOME: gnupghome },
    stdio: ['pipe', 'pipe', 'pipe'],
    ...opts,
  });
}

before(() => {
  fs.mkdirSync(path.join(targetDir, 'gpg-viewer-test'), { recursive: true });
  work = fs.mkdtempSync(path.join(targetDir, 'gpg-viewer-test', 'run-'));
  gnupghome = path.join(work, 'gnupg');
  fs.mkdirSync(gnupghome, { mode: 0o700 });
  openpgp = loadBrowserOpenpgp();
  assert.equal(typeof openpgp.decrypt, 'function', 'browser bundle exposes openpgp.decrypt');
});

after(() => {
  try {
    execFileSync(GPGCONF, ['--homedir', gnupghome, '--kill', 'all'], { stdio: 'ignore' });
  } catch {
    /* agent may not be running */
  }
  fs.rmSync(work, { recursive: true, force: true });
});

test('pure helpers', () => {
  assert.equal(parseGuestId('/g/AbCdEfGhIjKlMnOpQrStUv'), 'AbCdEfGhIjKlMnOpQrStUv');
  assert.equal(parseGuestId('/g/short'), null);
  assert.equal(parseGuestId('/v1/guest/AbCdEfGhIjKlMnOpQrStUv'), null);
  assert.equal(passphraseFromHash('#correct%20horse'), 'correct horse');
  assert.equal(passphraseFromHash(''), '');
  assert.equal(passphraseFromHash('#'), '');
  assert.deepEqual(formatExpiry(1000, 1000), { expired: true, text: 'expired' });
  assert.deepEqual(formatExpiry(1000 + 3 * 86400 + 5, 1000), { expired: false, text: 'in 3 days' });
  assert.deepEqual(formatExpiry(1000 + 3600, 1000), { expired: false, text: 'in 1 hour' });
  assert.deepEqual(formatExpiry(1000 + 30, 1000), { expired: false, text: 'in less than a minute' });
  assert.match(describeError(new Error('Error decrypting message: Session key decryption failed.')), /passphrase/);
});

test('decrypts a gpg --symmetric message (default S2K, AES-256, compressed)', async () => {
  const plaintext = 'Hello from the Sealbox guest test ✓ — ünïcödé 你好\nsecond line <b>not html</b>\n';
  const passphrase = 'correct horse battery staple';
  const inFile = path.join(work, 'plain.txt');
  fs.writeFileSync(inFile, plaintext);
  const armored = gpg(['--armor', '--symmetric', '--cipher-algo', 'AES256', '--passphrase', passphrase, '-o', '-', inFile]).toString('utf8');
  assert.match(armored, /^-----BEGIN PGP MESSAGE-----/);

  const out = await decryptGuestMessage(openpgp, armored, passphrase);
  assert.equal(out.text, plaintext);

  await assert.rejects(decryptGuestMessage(openpgp, armored, 'wrong passphrase'), (err) => {
    assert.match(describeError(err), /passphrase/);
    return true;
  });
  await assert.rejects(decryptGuestMessage(openpgp, armored, ''), /passphrase is required/);
});

test('decrypts a gpg --symmetric message with uncompressed literal data and a file name', async () => {
  const plaintext = 'uncompressed body\n';
  const inFile = path.join(work, 'note.txt');
  fs.writeFileSync(inFile, plaintext);
  const armored = gpg(['--armor', '--symmetric', '--compress-algo', 'none', '--cipher-algo', 'AES128', '--passphrase', 'pw-2', '-o', '-', inFile]).toString('utf8');
  const out = await decryptGuestMessage(openpgp, armored, 'pw-2');
  assert.equal(out.text, plaintext);
  assert.equal(out.filename, 'note.txt');
});

test('a reply encrypted by the viewer decrypts with gpg', async () => {
  gpg(['--passphrase', '', '--quick-gen-key', 'Sealbox Sender <sender@sealbox.test>', 'default', 'default', 'never']);
  const pub = gpg(['--armor', '--export', 'sender@sealbox.test']).toString('utf8');
  assert.match(pub, /^-----BEGIN PGP PUBLIC KEY BLOCK-----/);

  const info = await describeKey(openpgp, pub);
  assert.equal(info.userIDs[0], 'Sealbox Sender <sender@sealbox.test>');
  const fprs = gpg(['--with-colons', '--list-keys', 'sender@sealbox.test']).toString('utf8');
  const fpr = fprs.split('\n').find((l) => l.startsWith('fpr:')).split(':')[9];
  assert.equal(info.fingerprint, fpr.toUpperCase());

  const reply = 'Thanks, got it ✓\n';
  const armored = await encryptReply(openpgp, pub, reply);
  assert.match(armored, /^-----BEGIN PGP MESSAGE-----/);
  const replyFile = path.join(work, 'reply.asc');
  fs.writeFileSync(replyFile, armored);
  const decrypted = gpg(['--decrypt', replyFile]).toString('utf8');
  assert.equal(decrypted, reply);

  await assert.rejects(encryptReply(openpgp, pub, '   '), /empty/);
});

test('the Node build of OpenPGP.js agrees with the browser bundle', async () => {
  const nodeBuild = await import(path.join(guestDir, 'vendor', 'openpgp.node.min.mjs'));
  assert.equal(nodeBuild.config.versionString, openpgp.config.versionString);
  const inFile = path.join(work, 'x.txt');
  fs.writeFileSync(inFile, 'cross-build\n');
  const armored = gpg(['--armor', '--symmetric', '--passphrase', 'pw-3', '-o', '-', inFile]).toString('utf8');
  const a = await decryptGuestMessage(nodeBuild, armored, 'pw-3');
  const b = await decryptGuestMessage(openpgp, armored, 'pw-3');
  assert.equal(a.text, b.text);
  assert.equal(a.text, 'cross-build\n');
  assert.equal(os.platform(), 'linux');
});

// ---------------------------------------------------------------------------------------------
// G29: guest-link modes
// ---------------------------------------------------------------------------------------------

/** A fake fetch that answers from `routes` and records every request. */
function fakeFetch(routes) {
  const calls = [];
  const impl = async (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body || '' });
    const key = `${init.method || 'GET'} ${url.split('?')[0]}`;
    const handler = routes[key];
    if (!handler) return new Response('{"error":"not found"}', { status: 404 });
    const [status, body] = handler(url, init.body ? JSON.parse(init.body) : null);
    return new Response(body === null ? null : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  };
  return { impl, calls };
}

const ID = 'AbCdEfGhIjKlMnOpQrStUv';
const SECRET = 'wxyz-2345-abcd-efgh-jkmn';

test('mode copy says what each mode does and does not protect', () => {
  assert.match(MODE_COPY.passphrase, /not sent by e-mail/);
  assert.match(MODE_COPY.oneClick, /anyone who has the link can read it/);
  assert.match(MODE_COPY.emailCode, /one-time code/);
  assert.match(MODE_COPY.emailCode, /never leaves this page/);
});

test('code, address and wait helpers', () => {
  assert.equal(normalizeCode('123 456'), '123456');
  assert.equal(normalizeCode('123-456'), '123456');
  assert.equal(normalizeCode('12345'), null);
  assert.equal(normalizeCode('12345a'), null);
  assert.equal(normalizeCode(undefined), null);
  assert.ok(plausibleEmail('u44@sealbox.test'));
  assert.ok(!plausibleEmail('nope'));
  assert.ok(!plausibleEmail('a b@c.d'));
  assert.equal(formatWait(900), '15 minutes');
  assert.equal(formatWait(60), '1 minute');
  assert.equal(formatWait(3), '3 seconds');
  assert.equal(passphraseFromHash(`#${encodeURIComponent(SECRET)}`), SECRET);
});

test('fetchGuest maps 200 / 401 / 404 / 5xx / network failure', async () => {
  const guest = { id: ID, ciphertext_armored: 'x', created_at: 1, expires_at: 2 };
  let gated = true;
  const f = fakeFetch({
    [`GET /v1/guest/${ID}`]: (url) => {
      if (gated && !url.includes('token=tok')) return [401, { error: 'verification_required' }];
      return [200, guest];
    },
    'GET /v1/guest/BbCdEfGhIjKlMnOpQrStUv': () => [500, { error: 'internal error' }],
  });
  assert.deepEqual(await fetchGuest(f.impl, ID), { kind: 'gated' });
  assert.deepEqual(await fetchGuest(f.impl, ID, 'tok'), { kind: 'ok', guest });
  assert.equal(f.calls[1].url, `/v1/guest/${ID}?token=tok`);
  gated = false;
  assert.deepEqual(await fetchGuest(f.impl, ID), { kind: 'ok', guest });
  assert.deepEqual(await fetchGuest(f.impl, 'CbCdEfGhIjKlMnOpQrStUv'), { kind: 'gone' });
  assert.deepEqual(await fetchGuest(f.impl, 'BbCdEfGhIjKlMnOpQrStUv'), { kind: 'error', status: 500 });
  const broken = async () => {
    throw new TypeError('network');
  };
  assert.deepEqual(await fetchGuest(broken, ID), { kind: 'error', status: 0 });
});

test('email-code flow: request, wrong codes, lock, right code — and the secret is never sent', async () => {
  const state = { code: null, attempts: 0, locked: false };
  const f = fakeFetch({
    [`POST /v1/guest/${ID}/send-code`]: (_u, body) => {
      if (state.locked) return [429, { error: 'locked', retry_after: 900 }];
      if (body.email === 'u44@sealbox.test') state.code = '424242';
      return [202, { status: 'sent_if_recipient', expires_in: 600 }];
    },
    [`POST /v1/guest/${ID}/verify`]: (_u, body) => {
      if (state.locked) return [429, { error: 'locked', retry_after: 900 }];
      if (!state.code) return [400, { error: 'no_active_code' }];
      if (body.code === state.code) {
        state.code = null;
        return [200, { access_token: 'tok-1', expires_in: 900 }];
      }
      state.attempts += 1;
      if (state.attempts >= 5) {
        state.locked = true;
        state.code = null;
        return [429, { error: 'locked', retry_after: 900 }];
      }
      return [401, { error: 'invalid_code', attempts_left: 5 - state.attempts }];
    },
  });
  assert.deepEqual(await verifyCode(f.impl, ID, '000000'), { kind: 'no_code' });
  assert.deepEqual(await requestCode(f.impl, ID, ' u44@sealbox.test '), { kind: 'sent', expiresIn: 600 });
  assert.equal(JSON.parse(f.calls[1].body).email, 'u44@sealbox.test');
  for (let i = 1; i <= 4; i += 1) {
    assert.deepEqual(await verifyCode(f.impl, ID, '111111'), { kind: 'wrong', attemptsLeft: 5 - i });
  }
  assert.deepEqual(await verifyCode(f.impl, ID, '111111'), { kind: 'locked', retryAfter: 900 });
  assert.deepEqual(await requestCode(f.impl, ID, 'u44@sealbox.test'), { kind: 'locked', retryAfter: 900 });
  state.locked = false;
  state.attempts = 0;
  await requestCode(f.impl, ID, 'u44@sealbox.test');
  assert.deepEqual(await verifyCode(f.impl, ID, '424242'), { kind: 'ok', token: 'tok-1', expiresIn: 900 });

  for (const c of f.calls) {
    for (const form of [SECRET, encodeURIComponent(SECRET), '#']) {
      assert.ok(!c.url.includes(form), `request URL leaks the secret: ${c.url}`);
      assert.ok(!c.body.includes(form), `request body leaks the secret: ${c.body}`);
    }
  }
});

test('rate limiting and server errors are reported, not hidden', async () => {
  const f = fakeFetch({
    [`POST /v1/guest/${ID}/send-code`]: () => [429, { error: 'rate_limited' }],
    [`POST /v1/guest/${ID}/verify`]: () => [500, { error: 'internal error' }],
  });
  assert.deepEqual(await requestCode(f.impl, ID, 'a@b.c'), { kind: 'rate_limited' });
  assert.deepEqual(await verifyCode(f.impl, ID, '123456'), { kind: 'error', status: 500 });
  assert.deepEqual(await requestCode(f.impl, 'ZZCdEfGhIjKlMnOpQrStUv', 'a@b.c'), { kind: 'gone' });
});
