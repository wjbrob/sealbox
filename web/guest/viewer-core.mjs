// Sealbox guest viewer — pure logic, no DOM. Used by viewer.js in the browser and by
// test/viewer.test.mjs under Node. `openpgp` is injected (window.openpgp in the browser).

/** Guest id from a viewer path such as "/g/AbCdEf..." (22 URL-safe base64 chars). */
export function parseGuestId(pathname) {
  const m = /^\/g\/([A-Za-z0-9_-]{22})\/?$/.exec(pathname || '');
  return m ? m[1] : null;
}

/**
 * Optional passphrase carried in the URL fragment ("#…"). The fragment never reaches the
 * server, so a sender may hand out one link that opens without typing. Returns '' if none.
 */
export function passphraseFromHash(hash) {
  if (!hash || hash.length < 2) return '';
  const raw = hash.slice(1);
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/** Human-readable expiry. `expiresAt` and `now` are Unix seconds. */
export function formatExpiry(expiresAt, now = Date.now() / 1000) {
  const left = Math.floor(expiresAt - now);
  if (left <= 0) return { expired: true, text: 'expired' };
  const units = [
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60],
  ];
  for (const [name, secs] of units) {
    if (left >= secs) {
      const n = Math.floor(left / secs);
      return { expired: false, text: `in ${n} ${name}${n === 1 ? '' : 's'}` };
    }
  }
  return { expired: false, text: 'in less than a minute' };
}

/** Format a Unix-seconds timestamp for display (local time, no library). */
export function formatTimestamp(secs) {
  const d = new Date(secs * 1000);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString();
}

/**
 * Decrypt a passphrase-protected (SKESK) OpenPGP message.
 * Resolves to { text, filename }. Rejects on a wrong passphrase or a tampered message
 * (OpenPGP.js refuses messages without integrity protection by default).
 */
export async function decryptGuestMessage(openpgp, armoredMessage, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('A passphrase is required.');
  }
  const message = await openpgp.readMessage({ armoredMessage });
  const { data, filename } = await openpgp.decrypt({
    message,
    passwords: [passphrase],
    format: 'utf8',
  });
  return { text: String(data), filename: filename || '' };
}

/** Fingerprint and user IDs of an armored public key, for display. */
export async function describeKey(openpgp, armoredKey) {
  const key = await openpgp.readKey({ armoredKey });
  return {
    fingerprint: key.getFingerprint().toUpperCase(),
    userIDs: key.getUserIDs(),
  };
}

/**
 * Encrypt a reply to the sender's public key. Returns an armored OpenPGP message.
 * The reply is not signed (a guest has no key).
 */
export async function encryptReply(openpgp, senderKeyArmored, text) {
  if (typeof text !== 'string' || text.trim().length === 0) {
    throw new Error('The reply is empty.');
  }
  const encryptionKeys = await openpgp.readKey({ armoredKey: senderKeyArmored });
  const message = await openpgp.createMessage({ text });
  return openpgp.encrypt({ message, encryptionKeys, format: 'armored' });
}

/** Turn an OpenPGP.js error into a short message safe to show. */
export function describeError(err) {
  const msg = String((err && err.message) || err || 'unknown error');
  // A wrong SKESK passphrase derives a wrong session key; depending on the packet format
  // OpenPGP.js reports that either directly or as a failed integrity check (MDC / AEAD tag).
  if (/session key decryption failed|password|modification detected|integrity|authentication tag/i.test(msg)) {
    return 'That passphrase does not open this message (or the message was altered).';
  }
  if (/misformed|armor|no valid/i.test(msg)) {
    return 'The stored message is not a valid OpenPGP message.';
  }
  return msg;
}

// ---------------------------------------------------------------------------------------------
// G29 — guest-link modes. The decryption secret only ever lives in the URL fragment and in
// page memory: none of the functions below takes it, so it cannot end up in a request.
// ---------------------------------------------------------------------------------------------

/** What the page tells the reader, per mode. Exported so tests (and the app copy) agree. */
export const MODE_COPY = Object.freeze({
  passphrase:
    'Enter the passphrase the sender gave you. It was not sent by e-mail. Nothing you type here leaves your browser.',
  oneClick:
    'This link contains the key to the message, so anyone who has the link can read it. Do not forward it.',
  emailCode:
    'To open this message, confirm it was sent to you: we e-mail a one-time code to the recipient\'s address. The key to the message is in your link and never leaves this page.',
});

/**
 * Fetch a guest message. `fetchImpl` is window.fetch (injected for tests).
 * Resolves to one of
 *   { kind: 'ok', guest } · { kind: 'gated' } · { kind: 'gone' } · { kind: 'error', status }
 */
export async function fetchGuest(fetchImpl, id, token) {
  const url = token ? `/v1/guest/${id}?token=${encodeURIComponent(token)}` : `/v1/guest/${id}`;
  let res;
  try {
    res = await fetchImpl(url, {
      headers: { accept: 'application/json' },
      cache: 'no-store',
      credentials: 'omit',
    });
  } catch {
    return { kind: 'error', status: 0 };
  }
  if (res.status === 404) return { kind: 'gone' };
  if (res.status === 401) return { kind: 'gated' };
  if (!res.ok) return { kind: 'error', status: res.status };
  return { kind: 'ok', guest: await res.json() };
}

async function postJson(fetchImpl, url, body) {
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    credentials: 'omit',
    cache: 'no-store',
    body: JSON.stringify(body),
  });
  let json = {};
  try {
    json = await res.json();
  } catch {
    /* empty body */
  }
  return { status: res.status, json };
}

/** Plausible e-mail address (the server checks again). */
export function plausibleEmail(s) {
  return typeof s === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.trim()) && s.trim().length <= 254;
}

/** Normalize what a person types as a code: digits only; null unless exactly 6. */
export function normalizeCode(s) {
  const digits = String(s || '').replace(/[\s-]/g, '');
  return /^[0-9]{6}$/.test(digits) ? digits : null;
}

/**
 * Ask the server to mail a code to `email` (only delivered if it is the recipient).
 * Resolves to { kind: 'sent', expiresIn } · { kind: 'locked', retryAfter } ·
 * { kind: 'rate_limited' } · { kind: 'gone' } · { kind: 'error', status }
 */
export async function requestCode(fetchImpl, id, email) {
  let r;
  try {
    r = await postJson(fetchImpl, `/v1/guest/${id}/send-code`, { email: email.trim() });
  } catch {
    return { kind: 'error', status: 0 };
  }
  if (r.status === 202) return { kind: 'sent', expiresIn: r.json.expires_in || 600 };
  if (r.status === 404) return { kind: 'gone' };
  if (r.status === 429 && r.json.error === 'locked') return { kind: 'locked', retryAfter: r.json.retry_after || 0 };
  if (r.status === 429) return { kind: 'rate_limited' };
  return { kind: 'error', status: r.status };
}

/**
 * Exchange a code for an access token.
 * Resolves to { kind: 'ok', token, expiresIn } · { kind: 'wrong', attemptsLeft } ·
 * { kind: 'locked', retryAfter } · { kind: 'no_code' } · { kind: 'gone' } · { kind: 'error', status }
 */
export async function verifyCode(fetchImpl, id, code) {
  let r;
  try {
    r = await postJson(fetchImpl, `/v1/guest/${id}/verify`, { code });
  } catch {
    return { kind: 'error', status: 0 };
  }
  if (r.status === 200 && r.json.access_token) {
    return { kind: 'ok', token: r.json.access_token, expiresIn: r.json.expires_in || 0 };
  }
  if (r.status === 401) return { kind: 'wrong', attemptsLeft: r.json.attempts_left ?? 0 };
  if (r.status === 429 && r.json.error === 'locked') return { kind: 'locked', retryAfter: r.json.retry_after || 0 };
  if (r.status === 400 && r.json.error === 'no_active_code') return { kind: 'no_code' };
  if (r.status === 404) return { kind: 'gone' };
  return { kind: 'error', status: r.status };
}

/** "15 minutes" / "1 minute" / "30 seconds" for a lock or code lifetime. */
export function formatWait(secs) {
  const s = Math.max(1, Math.ceil(Number(secs) || 0));
  if (s >= 60) {
    const m = Math.ceil(s / 60);
    return `${m} minute${m === 1 ? '' : 's'}`;
  }
  return `${s} second${s === 1 ? '' : 's'}`;
}
