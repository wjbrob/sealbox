// Sealbox background service worker: OAuth (chrome.identity.launchWebAuthFlow + PKCE) and the
// documented Gmail REST API — nothing else talks to Google. No key material ever reaches
// this worker: encryption/decryption happens in the extension pages with the wasm core.
//
// Gmail endpoints used (https://developers.google.com/gmail/api/reference/rest):
//   GET  users/me/profile
//   GET  users/me/messages/{id}?format=raw              (raw RFC 5322, base64url)
//   GET  users/me/messages/{id}?format=metadata&metadataHeaders=Content-Type
//   GET  users/me/messages?q=…                         (users.messages.list)
//   POST users/me/messages/send   {"raw": base64url}    (users.messages.send)

const api = globalThis.browser ?? globalThis.chrome;

const GMAIL = 'https://gmail.googleapis.com/gmail/v1/users/me';
const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send'];

const local = {
  get: async (k) => (await api.storage.local.get(k))[k],
  set: (k, v) => api.storage.local.set({ [k]: v }),
};

function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomString(n = 32) {
  return b64url(crypto.getRandomValues(new Uint8Array(n)));
}

async function pkcePair() {
  const verifier = randomString(48);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  return { verifier, challenge: b64url(digest) };
}

async function oauthConfig() {
  const o = (await local.get('oauth')) ?? {};
  if (!o.clientId) throw new Error('Set your Google OAuth client id in the Sealbox options first.');
  return o;
}

async function tokenRequest(params) {
  const r = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`token endpoint: ${j.error_description || j.error || r.status}`);
  return j;
}

async function storeTokens(j, prev = {}) {
  const t = {
    accessToken: j.access_token,
    refreshToken: j.refresh_token ?? prev.refreshToken,
    expiresAt: Date.now() + (Number(j.expires_in ?? 3600) - 60) * 1000,
  };
  await api.storage.session.set({ tokens: t });
  // Only the refresh token is persisted (the access token stays in memory-only session storage).
  if (t.refreshToken) await local.set('refreshToken', t.refreshToken);
  return t;
}

/** Interactive sign-in: authorization code + PKCE (S256) through launchWebAuthFlow. */
async function connect() {
  const cfg = await oauthConfig();
  const redirectUri = api.identity.getRedirectURL();
  const { verifier, challenge } = await pkcePair();
  const state = randomString(16);
  const url = new URL(AUTH_URL);
  url.search = new URLSearchParams({
    client_id: cfg.clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: SCOPES.join(' '),
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    access_type: 'offline',
    prompt: 'consent',
  }).toString();
  const back = await api.identity.launchWebAuthFlow({ url: url.toString(), interactive: true });
  const ret = new URL(back);
  const p = ret.searchParams;
  if (p.get('state') !== state) throw new Error('OAuth state mismatch (possible CSRF) — aborted');
  if (p.get('error')) throw new Error(`authorization denied: ${p.get('error')}`);
  const code = p.get('code');
  if (!code) throw new Error('no authorization code returned');
  const params = {
    grant_type: 'authorization_code',
    code,
    code_verifier: verifier,
    client_id: cfg.clientId,
    redirect_uri: redirectUri,
  };
  // Google requires the (non-confidential, per Google's installed-app docs) client secret for
  // some client types even with PKCE. It is user-supplied in the options, never shipped.
  if (cfg.clientSecret) params.client_secret = cfg.clientSecret;
  await storeTokens(await tokenRequest(params));
  const profile = await gmail('/profile');
  await local.set('account', { email: profile.emailAddress });
  return { email: profile.emailAddress };
}

async function accessToken() {
  const { tokens } = await api.storage.session.get('tokens');
  if (tokens?.accessToken && tokens.expiresAt > Date.now()) return tokens.accessToken;
  const refreshToken = tokens?.refreshToken ?? (await local.get('refreshToken'));
  if (!refreshToken) throw new Error('Not connected to Google — open the Sealbox options and connect.');
  const cfg = await oauthConfig();
  const params = { grant_type: 'refresh_token', refresh_token: refreshToken, client_id: cfg.clientId };
  if (cfg.clientSecret) params.client_secret = cfg.clientSecret;
  return (await storeTokens(await tokenRequest(params), { refreshToken })).accessToken;
}

async function gmail(path, init = {}) {
  const token = await accessToken();
  const r = await fetch(GMAIL + path, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, ...(init.body ? { 'Content-Type': 'application/json' } : {}) },
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`Gmail API ${r.status}: ${j.error?.message ?? r.statusText}`);
  return j;
}

const validId = (id) => typeof id === 'string' && /^[0-9a-zA-Z_-]{6,64}$/.test(id);

const handlers = {
  async 'auth.status'() {
    const [account, refreshToken, oauth] = await Promise.all([local.get('account'), local.get('refreshToken'), local.get('oauth')]);
    return { connected: !!refreshToken, email: account?.email ?? null, clientId: oauth?.clientId ?? null, redirectUri: api.identity.getRedirectURL() };
  },
  'auth.connect': () => connect(),
  async 'auth.disconnect'() {
    await api.storage.session.remove('tokens');
    await api.storage.local.remove(['refreshToken', 'account']);
    return true;
  },
  async 'gmail.isEncrypted'({ id }) {
    if (!validId(id)) throw new Error('bad message id');
    const m = await gmail(`/messages/${id}?format=metadata&metadataHeaders=Content-Type`);
    const ct = (m.payload?.headers ?? []).find((h) => h.name.toLowerCase() === 'content-type')?.value ?? m.payload?.mimeType ?? '';
    return /multipart\/encrypted/i.test(ct) && /application\/pgp-encrypted/i.test(ct);
  },
  async 'gmail.getRaw'({ id }) {
    if (!validId(id)) throw new Error('bad message id');
    const m = await gmail(`/messages/${id}?format=raw`);
    return { raw: m.raw, threadId: m.threadId };
  },
  async 'gmail.send'({ raw, threadId }) {
    if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]+$/.test(raw)) throw new Error('raw must be base64url');
    const body = { raw };
    if (threadId) body.threadId = threadId;
    const r = await gmail('/messages/send', { method: 'POST', body: JSON.stringify(body) });
    return { id: r.id, threadId: r.threadId };
  },
  async 'gmail.listEncrypted'() {
    const r = await gmail(`/messages?maxResults=25&q=${encodeURIComponent('filename:encrypted.asc')}`);
    return r.messages ?? [];
  },
  async 'open.options'() {
    await api.runtime.openOptionsPage();
    return true;
  },
};

const CONTENT_SCRIPT_ALLOWED = new Set(['gmail.isEncrypted', 'open.options']);

api.runtime.onMessage.addListener((msg, sender, reply) => {
  // Only our own extension contexts and our content script may call us.
  if (sender.id !== api.runtime.id) return false;
  // The content script (running inside mail.google.com) may only ask "is this message
  // PGP/MIME?" and open the options; raw mail and sending are for extension pages only.
  const fromExtensionPage = typeof sender.url === 'string' && sender.url.startsWith(api.runtime.getURL(''));
  if (!fromExtensionPage && !CONTENT_SCRIPT_ALLOWED.has(msg?.type)) {
    reply({ error: `${msg?.type} is not available to content scripts` });
    return false;
  }
  const h = handlers[msg?.type];
  if (!h) {
    reply({ error: `unknown request ${msg?.type}` });
    return false;
  }
  Promise.resolve()
    .then(() => h(msg))
    .then((result) => reply({ result }), (e) => reply({ error: String(e?.message ?? e) }));
  return true;
});

api.action?.onClicked?.addListener(() => api.runtime.openOptionsPage());
