// Sealbox guest viewer — browser glue. Everything that touches the DOM lives here; the
// crypto calls are in viewer-core.mjs. Rules: plaintext only ever goes through textContent
// (never innerHTML — the page's CSP also enforces Trusted Types), no remote content, no images.

import {
  MODE_COPY,
  decryptGuestMessage,
  describeError,
  describeKey,
  encryptReply,
  fetchGuest,
  formatExpiry,
  formatTimestamp,
  formatWait,
  normalizeCode,
  parseGuestId,
  passphraseFromHash,
  plausibleEmail,
  requestCode,
  verifyCode,
} from './viewer-core.mjs';

const openpgp = globalThis.openpgp;
const $ = (id) => document.getElementById(id);

const ui = {
  status: $('status'),
  meta: $('meta'),
  created: $('created'),
  expires: $('expires'),
  unlock: $('unlock'),
  passphrase: $('passphrase'),
  decrypt: $('decrypt'),
  message: $('message'),
  plaintext: $('plaintext'),
  filename: $('filename'),
  replybox: $('replybox'),
  senderkey: $('senderkey'),
  replytext: $('replytext'),
  sendreply: $('sendreply'),
  replystatus: $('replystatus'),
  modeinfo: $('modeinfo'),
  gateEmail: $('gate-email'),
  gateAddress: $('gate-address'),
  sendCode: $('send-code'),
  gateCode: $('gate-code'),
  gateCodeInput: $('gate-code-input'),
  verifyCode: $('verify-code'),
  newCode: $('new-code'),
};

let guest = null; // { id, ciphertext_armored, created_at, expires_at, sender_key_armored }
let guestId = null;
let viaGate = false;

// G29: the secret (one-click / email-code links) is read from the fragment once, kept only in
// this page's memory, and removed from the address bar so it does not linger in history or get
// copied along with the URL. Browsers never send the fragment to the server.
const linkSecret = passphraseFromHash(location.hash);
if (location.hash) {
  try {
    history.replaceState(null, '', location.pathname + location.search);
  } catch {
    /* not fatal */
  }
}

function setMode(kind) {
  const text = MODE_COPY[kind];
  ui.modeinfo.textContent = text || '';
  ui.modeinfo.hidden = !text;
  ui.modeinfo.classList.toggle('warn', kind === 'oneClick');
}

function setStatus(el, text, kind) {
  el.textContent = text;
  el.classList.remove('ok', 'err');
  if (kind) el.classList.add(kind);
}

async function load() {
  if (!openpgp) {
    setStatus(ui.status, 'The OpenPGP library did not load; cannot decrypt.', 'err');
    return;
  }
  const id = parseGuestId(location.pathname);
  if (!id) {
    setStatus(ui.status, 'This is not a valid message link.', 'err');
    return;
  }
  guestId = id;
  const r = await fetchGuest(fetch.bind(globalThis), id);
  await handleFetch(r);
}

async function handleFetch(r) {
  if (r.kind === 'gone') {
    ui.gateEmail.hidden = true;
    ui.gateCode.hidden = true;
    setStatus(ui.status, 'This message has expired or does not exist. Ask the sender to send it again.', 'err');
    return;
  }
  if (r.kind === 'error') {
    setStatus(
      ui.status,
      r.status ? `The server answered ${r.status}. Try again later.` : 'Could not reach the server. Check your connection and reload.',
      'err',
    );
    return;
  }
  if (r.kind === 'gated') {
    showGate();
    return;
  }
  await showGuest(r.guest);
}

function showGate() {
  viaGate = true;
  setMode('emailCode');
  setStatus(ui.status, 'This message is protected by a one-time code. Enter the address it was sent to.');
  ui.gateEmail.hidden = false;
  ui.gateCode.hidden = true;
  ui.gateAddress.focus();
}

async function onSendCode() {
  const email = ui.gateAddress.value.trim();
  if (!plausibleEmail(email)) {
    setStatus(ui.status, 'Please enter a valid e-mail address.', 'err');
    return;
  }
  ui.sendCode.disabled = true;
  ui.newCode.disabled = true;
  setStatus(ui.status, 'Requesting a code…');
  try {
    const r = await requestCode(fetch.bind(globalThis), guestId, email);
    if (r.kind === 'sent') {
      ui.gateEmail.hidden = true;
      ui.gateCode.hidden = false;
      ui.gateCodeInput.value = '';
      ui.gateCodeInput.focus();
      setStatus(
        ui.status,
        `If ${email} is the address this message was sent to, a code is on its way. It is valid for ${formatWait(r.expiresIn)}.`,
      );
    } else if (r.kind === 'locked') {
      setStatus(ui.status, `Too many wrong codes. Try again in ${formatWait(r.retryAfter)}.`, 'err');
    } else if (r.kind === 'rate_limited') {
      setStatus(ui.status, 'Too many codes were requested for this message. Try again later.', 'err');
    } else if (r.kind === 'gone') {
      await handleFetch(r);
    } else {
      setStatus(ui.status, `Could not request a code (${r.status || 'network error'}). Try again.`, 'err');
    }
  } finally {
    ui.sendCode.disabled = false;
    ui.newCode.disabled = false;
  }
}

async function onVerifyCode() {
  const code = normalizeCode(ui.gateCodeInput.value);
  if (!code) {
    setStatus(ui.status, 'The code has 6 digits.', 'err');
    return;
  }
  ui.verifyCode.disabled = true;
  setStatus(ui.status, 'Checking the code…');
  try {
    const r = await verifyCode(fetch.bind(globalThis), guestId, code);
    if (r.kind === 'ok') {
      ui.gateCode.hidden = true;
      const fetched = await fetchGuest(fetch.bind(globalThis), guestId, r.token);
      if (fetched.kind === 'gated') {
        setStatus(ui.status, 'The code was accepted but the message could not be opened. Request a new code.', 'err');
        ui.gateEmail.hidden = false;
        return;
      }
      await handleFetch(fetched);
    } else if (r.kind === 'wrong') {
      setStatus(
        ui.status,
        `That code is not right. ${r.attemptsLeft} attempt${r.attemptsLeft === 1 ? '' : 's'} left.`,
        'err',
      );
      ui.gateCodeInput.select();
    } else if (r.kind === 'locked') {
      ui.gateCode.hidden = true;
      ui.gateEmail.hidden = false;
      setStatus(
        ui.status,
        `Too many wrong codes. This message is locked for ${formatWait(r.retryAfter)}; then request a new code.`,
        'err',
      );
    } else if (r.kind === 'no_code') {
      ui.gateCode.hidden = true;
      ui.gateEmail.hidden = false;
      setStatus(ui.status, 'That code has expired or was already used. Request a new one.', 'err');
    } else if (r.kind === 'gone') {
      await handleFetch(r);
    } else {
      setStatus(ui.status, `Could not check the code (${r.status || 'network error'}). Try again.`, 'err');
    }
  } finally {
    ui.verifyCode.disabled = false;
  }
}

async function showGuest(g) {
  guest = g;
  ui.created.textContent = formatTimestamp(guest.created_at);
  const exp = formatExpiry(guest.expires_at);
  ui.expires.textContent = `${exp.text} (${formatTimestamp(guest.expires_at)})`;
  ui.meta.hidden = false;
  if (linkSecret) {
    if (!viaGate) setMode('oneClick');
    ui.passphrase.value = linkSecret;
    await decrypt();
  } else {
    if (!viaGate) setMode('passphrase');
    setStatus(ui.status, 'Enter the passphrase to decrypt this message.');
    ui.unlock.hidden = false;
    ui.passphrase.focus();
  }
}

async function decrypt() {
  const passphrase = ui.passphrase.value;
  if (!passphrase) {
    setStatus(ui.status, 'Please enter the passphrase.', 'err');
    return;
  }
  ui.decrypt.disabled = true;
  setStatus(ui.status, 'Decrypting…');
  try {
    const { text, filename } = await decryptGuestMessage(openpgp, guest.ciphertext_armored, passphrase);
    ui.plaintext.textContent = text; // escaped by construction: textContent never parses HTML
    if (filename) {
      ui.filename.textContent = `Original file name: ${filename}`;
      ui.filename.hidden = false;
    }
    ui.message.hidden = false;
    ui.unlock.hidden = true;
    setStatus(ui.status, 'Decrypted in your browser.', 'ok');
    await showReplyBox();
  } catch (err) {
    setStatus(ui.status, describeError(err), 'err');
    ui.unlock.hidden = false; // a damaged link falls back to typing the passphrase
    ui.passphrase.select();
  } finally {
    ui.decrypt.disabled = false;
  }
}

async function showReplyBox() {
  if (!guest.sender_key_armored) return;
  try {
    const info = await describeKey(openpgp, guest.sender_key_armored);
    const who = info.userIDs.length ? info.userIDs[0] : 'sender';
    ui.senderkey.textContent = `${who} · ${info.fingerprint.slice(-16)}`;
    ui.replybox.hidden = false;
  } catch {
    // An unreadable sender key just means no reply option; the message itself is fine.
  }
}

async function sendReply() {
  const text = ui.replytext.value;
  if (!text.trim()) {
    setStatus(ui.replystatus, 'Write something first.', 'err');
    return;
  }
  ui.sendreply.disabled = true;
  setStatus(ui.replystatus, 'Encrypting…');
  try {
    const ciphertext_armored = await encryptReply(openpgp, guest.sender_key_armored, text);
    setStatus(ui.replystatus, 'Uploading…');
    const res = await fetch(`/v1/guest/${guest.id}/reply`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'omit',
      body: JSON.stringify({ ciphertext_armored }),
    });
    if (res.status === 204) {
      ui.replytext.value = '';
      setStatus(ui.replystatus, 'Encrypted reply sent. The sender will pick it up from Sealbox.', 'ok');
    } else if (res.status === 404) {
      setStatus(ui.replystatus, 'The message has expired; the reply could not be delivered.', 'err');
    } else if (res.status === 409) {
      setStatus(ui.replystatus, 'This message cannot take more replies.', 'err');
    } else {
      setStatus(ui.replystatus, `The server answered ${res.status}.`, 'err');
    }
  } catch (err) {
    setStatus(ui.replystatus, describeError(err), 'err');
  } finally {
    ui.sendreply.disabled = false;
  }
}

ui.unlock.addEventListener('submit', (ev) => {
  ev.preventDefault();
  decrypt();
});
ui.sendreply.addEventListener('click', sendReply);
ui.gateEmail.addEventListener('submit', (ev) => {
  ev.preventDefault();
  onSendCode();
});
ui.gateCode.addEventListener('submit', (ev) => {
  ev.preventDefault();
  onVerifyCode();
});
ui.newCode.addEventListener('click', () => {
  ui.gateCode.hidden = true;
  ui.gateEmail.hidden = false;
  onSendCode();
});

load();
