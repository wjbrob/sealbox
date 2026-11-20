// G28 wasm interop test: the Sealbox wasm core against GnuPG (the interop oracle), in Node.
//
//   node extension/wasm/test/roundtrip.mjs <pkg-node dir> <scratch dir>
//
// gpg runs with an isolated GNUPGHOME under <scratch dir> (never ~/.gnupg). Prints one
// `PASS <case>` / `FAIL <case>: why` line per case; exits 0 only if every case passed.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const [pkgDir, scratch] = process.argv.slice(2);
if (!pkgDir || !scratch) {
  console.error('usage: roundtrip.mjs <pkg-node dir> <scratch dir>');
  process.exit(2);
}
const require = createRequire(import.meta.url);
const sb = require(path.resolve(pkgDir, 'sealbox_wasm.js'));

const home = path.join(path.resolve(scratch), 'gnupg');
fs.rmSync(home, { recursive: true, force: true });
fs.mkdirSync(home, { recursive: true, mode: 0o700 });
const env = { ...process.env, GNUPGHOME: home };
function gpg(args, input) {
  return execFileSync('gpg', ['--batch', '--yes', '--no-tty', '--pinentry-mode', 'loopback', '--passphrase', '', ...args], {
    env,
    input,
    stdio: ['pipe', 'pipe', 'pipe'],
    maxBuffer: 64 << 20,
  });
}
function gpgStatus(args, input) {
  // --status-fd 2 → machine-readable status on stderr.
  const r = require('node:child_process').spawnSync(
    'gpg',
    ['--batch', '--yes', '--no-tty', '--pinentry-mode', 'loopback', '--passphrase', '', '--status-fd', '2', ...args],
    { env, input, maxBuffer: 64 << 20 },
  );
  return { code: r.status, out: r.stdout, status: r.stderr.toString() };
}

let failed = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`PASS ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL ${name}: ${e && e.message ? e.message : e}`);
  }
}
function assert(c, msg) {
  if (!c) throw new Error(msg);
}
const dec = new TextDecoder();
const enc = new TextEncoder();

// --- keys -------------------------------------------------------------------------------
console.log(`# ${sb.version()}`);
gpg(['--quick-gen-key', 'Gina Gpg <gina@sealbox.test>', 'future-default', 'default', 'never']);
const ginaPub = gpg(['--armor', '--export', 'gina@sealbox.test']).toString();
const ginaFpr = gpg(['--with-colons', '--fingerprint', 'gina@sealbox.test'])
  .toString()
  .split('\n')
  .find((l) => l.startsWith('fpr:'))
  .split(':')[9];

const alice = sb.generateIdentity('Alice Wasm', 'alice@sealbox.test');
gpg(['--import'], alice.publicArmored);
// Trust Alice's key so gpg reports a clean validity (signature checking works regardless).
gpg(['--import-ownertrust'], `${alice.fingerprint}:6:\n${ginaFpr}:6:\n`);

await check('wasm generateIdentity is gpg-readable (v4 Ed25519 + Curve25519)', () => {
  const cols = gpg(['--with-colons', '--list-keys', alice.fingerprint]).toString();
  assert(/^pub:.*:22:/m.test(cols), 'primary is not EdDSA (algo 22)');
  assert(/^sub:.*:18:/m.test(cols), 'no ECDH (algo 18) subkey');
  assert(alice.userIds[0] === 'Alice Wasm <alice@sealbox.test>', `uid ${alice.userIds}`);
});

await check('importIdentity / exportPublicKey / inspectPublicKey', () => {
  const again = sb.importIdentity(alice.secretArmored);
  assert(again.fingerprint === alice.fingerprint, 'fingerprint changed on import');
  const pub = sb.exportPublicKey(alice.secretArmored);
  assert(sb.inspectPublicKey(pub).fingerprint === alice.fingerprint, 'export/inspect mismatch');
  const g = sb.inspectPublicKey(ginaPub);
  assert(g.fingerprint === ginaFpr, `gina fpr ${g.fingerprint} != ${ginaFpr}`);
  assert(g.encryptionCapable, 'gina key not encryption capable');
});

await check('import of a gpg passphrase-protected secret key', () => {
  const pp = ['--batch', '--yes', '--no-tty', '--pinentry-mode', 'loopback', '--passphrase', 'pat-pass-1'];
  execFileSync('gpg', [...pp, '--quick-gen-key', 'Pat Protected <pat@sealbox.test>', 'future-default', 'default', 'never'], { env });
  const sec = execFileSync('gpg', [...pp, '--armor', '--export-secret-keys', 'pat@sealbox.test'], { env }).toString();
  let refused = false;
  try {
    sb.importIdentity(sec, 'not-the-passphrase');
  } catch {
    refused = true;
  }
  assert(refused, 'wrong passphrase accepted on import');
  const id = sb.importIdentity(sec, 'pat-pass-1');
  assert(id.emails.includes('pat@sealbox.test'), 'pat email missing');
});

// --- wasm → gpg -------------------------------------------------------------------------
const plain = 'Grüße from the wasm core — ünïcödé ✓\nline 2\n';
await check('wasm encryptAndSign → gpg --decrypt (GOODSIG from Alice)', () => {
  const ct = sb.encryptAndSign(plain, [ginaPub], alice.secretArmored);
  assert(ct.startsWith('-----BEGIN PGP MESSAGE-----'), 'not armored');
  const r = gpgStatus(['--decrypt'], ct);
  assert(r.code === 0, `gpg exit ${r.code}: ${r.status}`);
  assert(dec.decode(r.out) === plain, 'plaintext mismatch');
  assert(r.status.includes('[GNUPG:] GOODSIG'), 'no GOODSIG');
  assert(r.status.includes(`VALIDSIG ${alice.fingerprint}`), 'VALIDSIG not Alice');
  assert(r.status.includes('DECRYPTION_OKAY'), 'no DECRYPTION_OKAY');
});

await check('wasm encryptAndSign of binary bytes → gpg', () => {
  const bytes = new Uint8Array(4096).map((_, i) => (i * 7919) & 0xff);
  const ct = sb.encryptAndSign(bytes, [ginaPub, alice.publicArmored]);
  const r = gpgStatus(['--decrypt'], ct);
  assert(r.code === 0, `gpg exit ${r.code}`);
  assert(Buffer.compare(r.out, Buffer.from(bytes)) === 0, 'bytes mismatch');
  // And Alice (second recipient) can read it too.
  const d = sb.decryptAndVerify(ct, [alice.secretArmored], []);
  assert(Buffer.compare(Buffer.from(d.plaintext), Buffer.from(bytes)) === 0, 'alice cannot read');
});

// --- gpg → wasm -------------------------------------------------------------------------
await check('gpg --encrypt --sign → wasm decryptAndVerify (Good from Gina)', () => {
  const ct = gpg(['--armor', '--trust-model', 'always', '--encrypt', '--sign', '-u', 'gina@sealbox.test', '-r', 'alice@sealbox.test'], plain).toString();
  const d = sb.decryptAndVerify(ct, [alice.secretArmored], [ginaPub]);
  assert(d.text === plain, 'plaintext mismatch');
  assert(d.signedByKnownKey, `not signed by known key: ${JSON.stringify(d.signatures)}`);
  assert(d.signatures[0].status === 'good' && d.signatures[0].fingerprint === ginaFpr, 'wrong signer');
});

await check('gpg binary (non-armored) message → wasm; unknown signer reported', () => {
  const ct = gpg(['--trust-model', 'always', '--encrypt', '--sign', '-u', 'gina@sealbox.test', '-r', 'alice@sealbox.test'], plain);
  const d = sb.decryptAndVerify(new Uint8Array(ct), [alice.secretArmored], []);
  assert(d.text === plain, 'plaintext mismatch');
  assert(!d.signedByKnownKey && d.signatures[0].status === 'unknown_key', JSON.stringify(d.signatures));
});

await check('tampered ciphertext is rejected', () => {
  const ct = gpg(['--trust-model', 'always', '--encrypt', '-r', 'alice@sealbox.test'], plain);
  const t = new Uint8Array(ct);
  t[t.length - 30] ^= 0x01;
  let threw = false;
  try {
    sb.decryptAndVerify(t, [alice.secretArmored], []);
  } catch {
    threw = true;
  }
  assert(threw, 'tampered message decrypted');
});

// --- PGP/MIME ---------------------------------------------------------------------------
const draft = {
  from: { name: 'Alice Wasm', address: 'alice@sealbox.test' },
  to: ['Gina Gpg <gina@sealbox.test>'],
  subject: 'Protected subject ✓',
  text: 'Hello Gina,\r\nthis is PGP/MIME from wasm.\r\n',
  attachments: [{ filename: 'note.txt', contentType: 'text/plain', data: enc.encode('attached!') }],
  extraHeaders: [['Autocrypt', sb.autocryptHeader('alice@sealbox.test', alice.publicArmored)]],
};

await check('PGP/MIME build (finalize → renderInner → encryptAndSign → build) → parse round trip', () => {
  const fin = sb.finalizeDraft(draft);
  assert(fin.messageId && fin.messageId.endsWith('@sealbox.test'), `messageId ${fin.messageId}`);
  assert(typeof fin.date === 'number', 'no date');
  const inner = sb.renderInnerForEncryption(fin);
  assert(dec.decode(inner).includes('protected-headers="v1"'), 'inner lacks protected-headers');
  const ct = sb.encryptAndSign(inner, [ginaPub, alice.publicArmored], alice.secretArmored);
  const raw = sb.buildPgpMimeEncrypted(fin, ct);
  const text = dec.decode(raw);
  assert(/Content-Type: multipart\/encrypted;[^]*protocol="application\/pgp-encrypted"/.test(text), 'not multipart/encrypted');
  assert(/^Subject: \.\.\.\r?$/m.test(text), 'outer subject not "..."');
  assert(!text.includes('Protected subject'), 'real subject leaked to outer headers');
  const p = sb.parseMessage(raw);
  assert(p.kind === 'pgpMimeEncrypted', `kind ${p.kind}`);
  assert(p.headers.messageId === fin.messageId, 'message-id mismatch');
  assert(p.headers.autocrypt.length === 1, 'autocrypt header not parsed back');
  const ac = sb.parseAutocryptHeaders(p.headers.autocrypt, 'alice@sealbox.test');
  assert(ac.forSender && ac.forSender.fingerprint === alice.fingerprint, 'autocrypt forSender mismatch');
  const d = sb.decryptMessage(raw, [alice.secretArmored], [alice.publicArmored]);
  assert(d.subject === 'Protected subject ✓', `subject ${d.subject}`);
  assert(d.protectedHeaders.present, 'protected headers not present');
  assert(d.text.includes('PGP/MIME from wasm'), 'body mismatch');
  assert(d.attachments.length === 1 && dec.decode(d.attachments[0].data) === 'attached!', 'attachment mismatch');
  assert(d.signedByKnownKey, 'signature not good');
});

await check('wasm PGP/MIME (encryptDraft) → gpg decrypts the payload, inner MIME intact', () => {
  const out = sb.encryptDraft(draft, [ginaPub, alice.publicArmored], alice.secretArmored);
  const p = sb.parseMessage(out.raw);
  assert(p.kind === 'pgpMimeEncrypted', `kind ${p.kind}`);
  const r = gpgStatus(['--decrypt'], p.ciphertext);
  assert(r.code === 0, `gpg exit ${r.code}`);
  const inner = r.out.toString();
  assert(inner.includes('Subject: =?utf-8?') || inner.includes('Subject: Protected subject'), 'inner subject missing');
  assert(inner.includes('protected-headers="v1"'), 'protected-headers missing');
  assert(r.status.includes(`VALIDSIG ${alice.fingerprint}`), 'not signed by Alice');
  const i = sb.parseDecryptedInner(r.out);
  assert(i.protectedHeaders.subject === 'Protected subject ✓', 'protected subject mismatch');
});

await check('gpg-encrypted RFC 3156 message → wasm decryptMessage', () => {
  const innerEntity =
    'Content-Type: text/plain; charset=utf-8; protected-headers="v1"\r\n' +
    'Subject: From gpg with love\r\nFrom: Gina Gpg <gina@sealbox.test>\r\nTo: alice@sealbox.test\r\n\r\n' +
    'Body made by gpg.\r\n';
  const ct = gpg(['--armor', '--trust-model', 'always', '--encrypt', '--sign', '-u', 'gina@sealbox.test', '-r', 'alice@sealbox.test'], innerEntity).toString();
  const raw =
    'From: Gina Gpg <gina@sealbox.test>\r\nTo: alice@sealbox.test\r\nSubject: ...\r\n' +
    'Message-ID: <gpg-1@sealbox.test>\r\nDate: Tue, 27 Oct 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n' +
    'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="b1"\r\n\r\n' +
    '--b1\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n' +
    '--b1\r\nContent-Type: application/octet-stream; name="encrypted.asc"\r\n\r\n' +
    ct.replace(/\r?\n/g, '\r\n') +
    '\r\n--b1--\r\n';
  const d = sb.decryptMessage(raw, [alice.secretArmored], [ginaPub]);
  assert(d.subject === 'From gpg with love', `subject ${d.subject}`);
  assert(d.text.includes('Body made by gpg.'), 'body mismatch');
  assert(d.signedByKnownKey, 'gina signature not good');
});

// --- key store wrapping ------------------------------------------------------------------
await check('wrapSecret/unwrapSecret (Argon2id 64 MiB t=3 → XChaCha20-Poly1305), wrong passphrase rejected', () => {
  const t0 = Date.now();
  const w = sb.wrapSecret(alice.secretArmored, 'correct horse battery staple');
  const ms = Date.now() - t0;
  const env = JSON.parse(w);
  assert(env.kdf === 'argon2id' && env.m === 65536 && env.t === 3, 'params');
  assert(!w.includes('PRIVATE KEY'), 'plaintext visible in envelope');
  assert(sb.unwrapSecret(w, 'correct horse battery staple') === alice.secretArmored, 'roundtrip');
  let threw = false;
  try {
    sb.unwrapSecret(w, 'wrong');
  } catch {
    threw = true;
  }
  assert(threw, 'wrong passphrase accepted');
  console.log(`# argon2id 64MiB/t=3 wrap took ${ms} ms`);
});

console.log(failed ? `FAILED ${failed}` : 'ALL PASS');
process.exit(failed ? 1 : 0);
