// Helpers shared by the extension pages (options, compose, reader). Not used by the
// content script (which never touches keys) except `send`.

import initWasm, * as wasm from 'sealbox-wasm';

export const api = globalThis.browser ?? globalThis.chrome;

/** Message the background service worker; throws its error. */
export async function send(type, payload = {}) {
  const r = await api.runtime.sendMessage({ type, ...payload });
  if (!r) throw new Error(`no response to ${type}`);
  if (r.error) throw new Error(r.error);
  return r.result;
}

export function b64urlEncode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(str) {
  const b = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out;
}

export const local = {
  get: async (k) => (await api.storage.local.get(k))[k],
  set: (k, v) => api.storage.local.set({ [k]: v }),
  remove: (k) => api.storage.local.remove(k),
};
// storage.session is memory-only and (by default) not visible to content scripts: the
// unlocked secret key lives only here, never in storage.local.
export const session = {
  get: async (k) => (await api.storage.session.get(k))[k],
  set: (k, v) => api.storage.session.set({ [k]: v }),
  remove: (k) => api.storage.session.remove(k),
};

let wasmReady;
/** Load the Sealbox wasm core once per page. */
export async function core() {
  if (!wasmReady) {
    wasmReady = (async () => {
      await initWasm({ module_or_path: api.runtime.getURL('sealbox_wasm_bg.wasm') });
      return wasm;
    })();
  }
  return wasmReady;
}

/** Stored identity: { wrapped, publicArmored, fingerprint, email } (secret only wrapped). */
export const getIdentity = () => local.get('identity');

/** The unlocked armored secret, or null when locked. */
export const getUnlockedSecret = async () => (await session.get('unlockedSecret')) ?? null;

export async function unlock(passphrase) {
  const id = await getIdentity();
  if (!id) throw new Error('No key yet — create or import one in the Sealbox options.');
  const sb = await core();
  const secret = sb.unwrapSecret(id.wrapped, passphrase);
  await session.set('unlockedSecret', secret);
  return secret;
}

export const lock = () => session.remove('unlockedSecret');

/** contacts: { [lowercased addr]: { publicArmored, fingerprint, source, preferEncrypt, updated } } */
export async function getContacts() {
  return (await local.get('contacts')) ?? {};
}

export async function putContact(addr, entry) {
  const c = await getContacts();
  c[addr.trim().toLowerCase()] = { ...entry, updated: Date.now() };
  await local.set('contacts', c);
}

/** Autocrypt Level 1 (simplified): remember the sender's key from a valid header. */
export async function learnAutocrypt(sb, autocryptValues, fromAddr, messageDate) {
  if (!autocryptValues?.length || !fromAddr) return null;
  const r = sb.parseAutocryptHeaders(autocryptValues, fromAddr);
  if (!r.forSender) return null;
  const c = await getContacts();
  const key = fromAddr.trim().toLowerCase();
  const prev = c[key];
  const when = (messageDate ?? 0) * 1000;
  if (prev && prev.source === 'manual') return prev; // a manually verified key wins
  if (prev && prev.autocryptDate && prev.autocryptDate > when) return prev;
  c[key] = {
    publicArmored: r.forSender.publicArmored,
    fingerprint: r.forSender.fingerprint,
    preferEncrypt: r.forSender.preferEncrypt,
    source: 'autocrypt',
    autocryptDate: when,
    updated: Date.now(),
  };
  await local.set('contacts', c);
  return c[key];
}

export function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children) e.append(c);
  return e;
}

export function fmtSignatures(d) {
  if (!d.signatures.length) return { cls: 'warn', text: 'Not signed' };
  if (d.signedByKnownKey) {
    const fp = d.signatures.find((s) => s.status === 'good').fingerprint;
    return { cls: 'good', text: `Good signature from ${fp.slice(-16).replace(/(.{4})/g, '$1 ').trim()}` };
  }
  if (d.signatures.some((s) => s.status === 'bad')) return { cls: 'bad', text: 'BAD signature — do not trust this message' };
  return { cls: 'warn', text: 'Signed by an unknown key' };
}
