// Sealbox Outlook taskpane. Office.js only (documented APIs, Mailbox 1.8):
//   compose: item.body.getAsync / setAsync, item.to|cc.getAsync, item.internetHeaders.setAsync
//   read:    item.getAllInternetHeadersAsync, item.attachments + getAttachmentContentAsync,
//            item.body.getAsync
// Keys live in this origin's localStorage, wrapped (Argon2id → XChaCha20-Poly1305); the
// unlocked key only in sessionStorage. Nothing is sent anywhere but through Outlook itself.
import initWasm, * as sb from 'sealbox-wasm';

const $ = (id) => document.getElementById(id);
const store = {
  get: (k) => {
    try {
      return JSON.parse(localStorage.getItem(`sealbox.${k}`));
    } catch {
      return null;
    }
  },
  set: (k, v) => localStorage.setItem(`sealbox.${k}`, JSON.stringify(v)),
};
const unlocked = {
  get: () => sessionStorage.getItem('sealbox.secret'),
  set: (v) => sessionStorage.setItem('sealbox.secret', v),
};
function status(text, cls = '') {
  const s = $('status');
  s.hidden = false;
  s.className = `status ${cls}`;
  s.textContent = text;
}
const call = (fn, ...args) =>
  new Promise((res, rej) => fn(...args, (r) => (r.status === Office.AsyncResultStatus.Succeeded ? res(r.value) : rej(new Error(r.error?.message ?? 'Office.js call failed')))));
const guard = (fn) => async () => {
  try {
    await fn();
  } catch (e) {
    status(String(e?.message ?? e), 'bad');
  }
};
const contacts = () => store.get('contacts') ?? {};
function addContact(k, source) {
  const c = contacts();
  for (const a of k.emails) c[a.toLowerCase()] = { publicArmored: k.publicArmored, fingerprint: k.fingerprint, source };
  store.set('contacts', c);
}

function render() {
  const id = store.get('identity');
  const item = Office.context.mailbox?.item;
  // In compose mode Office.js exposes subject as an object with getAsync; in read mode it is a string.
  const isCompose = !!item && typeof item.subject?.getAsync === 'function';
  $('setup').hidden = !!id;
  $('locked').hidden = !id || !!unlocked.get();
  const ready = !!id && !!unlocked.get();
  $('compose').hidden = !ready || !isCompose;
  $('read').hidden = !ready || isCompose;
  $('keys').hidden = !id;
  if (id) $('my-public').value = id.publicArmored;
}

function saveIdentity(info, pass) {
  if (!pass || pass.length < 8) throw new Error('Choose a Sealbox passphrase of at least 8 characters.');
  store.set('identity', { wrapped: sb.wrapSecret(info.secretArmored, pass), publicArmored: info.publicArmored, fingerprint: info.fingerprint, email: info.primaryEmail ?? info.emails[0] });
  unlocked.set(info.secretArmored);
  render();
}

async function encryptCompose() {
  const item = Office.context.mailbox.item;
  const id = store.get('identity');
  const [to, cc, body] = await Promise.all([call(item.to.getAsync.bind(item.to)), call(item.cc.getAsync.bind(item.cc)), call(item.body.getAsync.bind(item.body), Office.CoercionType.Text)]);
  if (body.includes('-----BEGIN PGP MESSAGE-----')) throw new Error('This body is already encrypted.');
  const c = contacts();
  const addrs = [...to, ...cc].map((r) => r.emailAddress.toLowerCase());
  if (!addrs.length) throw new Error('Add recipients first.');
  const missing = addrs.filter((a) => !c[a]);
  if (missing.length) throw new Error(`No key for ${missing.join(', ')} — nothing was changed.`);
  const keys = [...new Set(addrs.map((a) => c[a].publicArmored)), id.publicArmored];
  const armored = sb.encryptAndSign(body, keys, unlocked.get());
  await call(item.body.setAsync.bind(item.body), armored, { coercionType: Office.CoercionType.Text });
  try {
    await call(item.internetHeaders.setAsync.bind(item.internetHeaders), { Autocrypt: sb.autocryptHeader(id.email, id.publicArmored, true).replace(/\s+/g, ' ') });
  } catch {
    // Some hosts refuse non-X- headers; encryption itself already happened.
  }
  status('Body encrypted and signed ✓ — press Send.', 'good');
}

async function decryptRead() {
  const item = Office.context.mailbox.item;
  const id = store.get('identity');
  const headers = await call(item.getAllInternetHeadersAsync.bind(item));
  // Autocrypt: learn the sender's key from the raw headers.
  const values = [];
  const unfolded = headers.replace(/\r?\n[ \t]+/g, ' ');
  for (const line of unfolded.split(/\r?\n/)) if (/^autocrypt:/i.test(line)) values.push(line.slice(line.indexOf(':') + 1).trim());
  const from = item.from?.emailAddress;
  if (values.length && from) {
    const r = sb.parseAutocryptHeaders(values, from);
    if (r.forSender && contacts()[from.toLowerCase()]?.source !== 'manual') addContact({ emails: [from], publicArmored: r.forSender.publicArmored, fingerprint: r.forSender.fingerprint }, 'autocrypt');
  }
  // PGP/MIME arrives as an "encrypted.asc" attachment; inline PGP in the body.
  let ciphertext = null;
  const att = (item.attachments ?? []).find((a) => /\.asc$|\.pgp$/i.test(a.name) && !/signature/i.test(a.name));
  if (att) {
    const content = await call(item.getAttachmentContentAsync.bind(item), att.id);
    ciphertext = content.format === Office.MailboxEnums.AttachmentContentFormat.Base64 ? Uint8Array.from(atob(content.content), (ch) => ch.charCodeAt(0)) : content.content;
  } else {
    const body = await call(item.body.getAsync.bind(item.body), Office.CoercionType.Text);
    const m = body.match(/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/);
    if (m) ciphertext = m[0];
  }
  if (!ciphertext) throw new Error('No OpenPGP message found in this item.');
  const known = Object.values(contacts()).map((k) => k.publicArmored).concat(id.publicArmored);
  const d = sb.decryptAndVerify(ciphertext, [unlocked.get()], known);
  let subject = item.subject;
  let text = d.text ?? '';
  if (att) {
    const inner = sb.parseDecryptedInner(d.plaintext);
    if (inner.protectedHeaders.present && inner.protectedHeaders.subject) subject = inner.protectedHeaders.subject;
    text = inner.text ?? '';
  }
  $('subject').textContent = subject;
  $('body').textContent = text;
  const good = d.signedByKnownKey;
  $('sig').className = `meta ${good ? 'good' : d.signatures.some((s) => s.status === 'bad') ? 'bad' : 'warn'}`;
  $('sig').textContent = good ? '🔒 Decrypted · good signature' : d.signatures.length ? '🔒 Decrypted · signature not verified' : '🔒 Decrypted · not signed';
}

Office.onReady(async () => {
  await initWasm({ module_or_path: new URL('sealbox_wasm_bg.wasm', location.href) });
  $('create').addEventListener('click', guard(() => saveIdentity(sb.generateIdentity($('name').value, $('email').value), $('new-pass').value)));
  $('do-import').addEventListener('click', guard(() => saveIdentity(sb.importIdentity($('import').value, $('import-pass').value || undefined), $('new-pass').value)));
  $('unlock').addEventListener(
    'click',
    guard(() => {
      unlocked.set(sb.unwrapSecret(store.get('identity').wrapped, $('pass').value));
      $('pass').value = '';
      render();
    }),
  );
  $('encrypt').addEventListener('click', guard(encryptCompose));
  $('decrypt').addEventListener('click', guard(decryptRead));
  $('add-contact').addEventListener(
    'click',
    guard(() => {
      const k = sb.inspectPublicKey($('contact-key').value);
      addContact(k, 'manual');
      $('contact-key').value = '';
      status(`Added ${k.emails.join(', ')}`, 'good');
    }),
  );
  render();
});
