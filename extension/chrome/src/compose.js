import { core, send, getIdentity, getUnlockedSecret, unlock, getContacts, b64urlEncode } from './common.js';

const $ = (id) => document.getElementById(id);
function status(text, cls = '') {
  const s = $('status');
  s.hidden = false;
  s.className = `status ${cls}`;
  s.textContent = text;
}

const splitAddrs = (v) =>
  v
    .split(/[,;]/)
    .map((s) => s.trim())
    .filter(Boolean);
const bare = (s) => (s.match(/<([^>]+)>/)?.[1] ?? s).trim().toLowerCase();

async function showForm() {
  const id = await getIdentity();
  if (!id) {
    status('No key yet. Open the Sealbox options (toolbar icon) to create or import one.', 'warn');
    await send('open.options').catch(() => {});
    return;
  }
  const secret = await getUnlockedSecret();
  $('locked').hidden = !!secret;
  $('form').hidden = !secret;
  $('from').textContent = id.userId ?? id.email;
}

async function keyCheck() {
  const contacts = await getContacts();
  const rcpts = [...splitAddrs($('to').value), ...splitAddrs($('cc').value)].map(bare);
  const missing = rcpts.filter((a) => !contacts[a]);
  $('keys').textContent = rcpts.length
    ? missing.length
      ? `No key yet for: ${missing.join(', ')} — they need to send you a Sealbox/Autocrypt mail first, or add their key in the options.`
      : `All ${rcpts.length} recipient(s) have keys ✓`
    : '';
  $('keys').className = `meta ${missing.length ? 'warn' : 'good'}`;
  return { rcpts, missing, contacts };
}
$('to').addEventListener('input', keyCheck);
$('cc').addEventListener('input', keyCheck);

$('unlock').addEventListener('click', async () => {
  try {
    await unlock($('pass').value);
    $('pass').value = '';
    $('status').hidden = true;
    await showForm();
  } catch (e) {
    status(String(e.message ?? e), 'bad');
  }
});

$('form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  $('send').disabled = true;
  try {
    const sb = await core();
    const id = await getIdentity();
    const secret = await getUnlockedSecret();
    if (!secret) throw new Error('Key is locked.');
    const { rcpts, missing, contacts } = await keyCheck();
    if (!rcpts.length) throw new Error('Add at least one recipient.');
    if (missing.length) throw new Error(`Cannot encrypt: no key for ${missing.join(', ')}. Nothing was sent.`);
    const attachments = [];
    for (const f of $('files').files) {
      attachments.push({ filename: f.name, contentType: f.type || 'application/octet-stream', data: new Uint8Array(await f.arrayBuffer()) });
    }
    status('Encrypting…');
    const draft = {
      from: { name: (id.userId ?? '').replace(/\s*<[^>]*>$/, '') || null, address: id.email },
      to: splitAddrs($('to').value),
      cc: splitAddrs($('cc').value),
      subject: $('subject').value,
      text: $('body').value.replace(/\r?\n/g, '\r\n'),
      attachments,
      extraHeaders: [['Autocrypt', sb.autocryptHeader(id.email, id.publicArmored, true)]],
    };
    // Encrypt to every recipient and to ourselves (so the Sent copy stays readable).
    const keys = [...new Set(rcpts.map((a) => contacts[a].publicArmored)), id.publicArmored];
    const out = sb.encryptDraft(draft, keys, secret);
    status('Sending through the Gmail API…');
    const r = await send('gmail.send', { raw: b64urlEncode(out.raw) });
    status(`Sent ✓ (Gmail id ${r.id})`, 'good');
    $('form').reset();
    $('keys').textContent = '';
  } catch (e) {
    status(String(e.message ?? e), 'bad');
  } finally {
    $('send').disabled = false;
  }
});

showForm().catch((e) => status(String(e.message ?? e), 'bad'));
