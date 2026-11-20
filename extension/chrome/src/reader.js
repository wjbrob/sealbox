// Reader panel: raw message from users.messages.get?format=raw (by id) → wasm decrypt.
// Untrusted content is rendered as text; an HTML part goes into a sandboxed iframe with
// scripts, forms and same-origin access all disabled, under a document CSP that allows no
// network (`html-part.js`, R8) on top of the extension-page CSP it inherits.
import { core, send, getIdentity, getUnlockedSecret, unlock, getContacts, learnAutocrypt, b64urlDecode, fmtSignatures, el } from './common.js';
import { htmlDocument } from './html-part.js';

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const msgId = params.get('id');
function status(text, cls = '') {
  const s = $('status');
  s.hidden = false;
  s.className = `status ${cls}`;
  s.textContent = text;
}

async function decrypt(id) {
  const sb = await core();
  const me = await getIdentity();
  const secret = await getUnlockedSecret();
  if (!me) throw new Error('No key yet — open the Sealbox options.');
  if (!secret) {
    $('locked').hidden = false;
    return;
  }
  $('locked').hidden = true;
  status('Fetching message…');
  const { raw } = await send('gmail.getRaw', { id });
  const bytes = b64urlDecode(raw);
  const parsed = sb.parseMessage(bytes);
  const from = parsed.headers.from[0]?.address;
  // Autocrypt: learn the sender's key before verifying, so a first message verifies too.
  await learnAutocrypt(sb, parsed.headers.autocrypt, from, parsed.headers.date);
  const known = Object.values(await getContacts()).map((c) => c.publicArmored);
  known.push(me.publicArmored);
  status('Decrypting…');
  const d = sb.decryptMessage(bytes, [secret], known);
  $('status').hidden = true;
  $('msg').hidden = false;
  $('subject').textContent = d.subject ?? '(no subject)';
  const f = d.headers.from[0];
  $('from').textContent = f ? (f.name ? `${f.name} <${f.address}>` : f.address) : '?';
  $('date').textContent = d.headers.date ? new Date(d.headers.date * 1000).toLocaleString() : '';
  const s = fmtSignatures(d);
  $('sig').className = `meta ${s.cls}`;
  $('sig').textContent = `🔒 Decrypted · ${s.text}`;
  $('body').textContent = d.text ?? '';
  if (d.html && !d.text) {
    $('html').hidden = false;
    $('html').srcdoc = htmlDocument(d.html);
  }
  $('attachments').replaceChildren(
    ...d.attachments.map((a) => {
      const url = URL.createObjectURL(new Blob([a.data], { type: 'application/octet-stream' }));
      return el('div', { class: 'card' }, el('a', { href: url, download: a.filename }, `📎 ${a.filename}`), el('span', { class: 'meta' }, ` ${a.data.length} bytes`));
    }),
  );
}

async function list() {
  $('list').hidden = false;
  const items = await send('gmail.listEncrypted');
  $('items').replaceChildren(
    ...(items.length
      ? items.map((m) => el('div', { class: 'card' }, el('a', { href: `reader.html?id=${encodeURIComponent(m.id)}` }, `Message ${m.id}`)))
      : [el('p', { class: 'meta' }, 'No encrypted messages found.')]),
  );
}

$('unlock').addEventListener('click', async () => {
  try {
    await unlock($('pass').value);
    $('pass').value = '';
    await decrypt(msgId);
  } catch (e) {
    status(String(e.message ?? e), 'bad');
  }
});

(msgId ? decrypt(msgId) : list()).catch((e) => status(String(e.message ?? e), 'bad'));
