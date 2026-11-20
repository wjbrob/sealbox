// Node mock of the Google endpoints the extension uses — and nothing else:
//   accounts.google.com   GET  /o/oauth2/v2/auth          (authorization code + PKCE S256)
//   oauth2.googleapis.com POST /token                     (authorization_code / refresh_token)
//   gmail.googleapis.com  GET  /gmail/v1/users/me/profile
//                         GET  /gmail/v1/users/me/messages/{id}?format=raw|metadata
//                         GET  /gmail/v1/users/me/messages?q=…
//                         POST /gmail/v1/users/me/messages/send
//   mail.google.com       GET  /mail/…                    (the static fixture page)
// One HTTPS server; Chromium reaches it through --host-resolver-rules, so the extension
// runs with its real, unmodified endpoint URLs. Shapes follow the public Gmail API reference.
import https from 'node:https';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const b64url = (buf) => Buffer.from(buf).toString('base64url');

export function startMock({ cert, key, clientId, mailbox = 'alice@sealbox.test' }) {
  const state = {
    messages: new Map(), // id → raw Buffer
    sent: [], // { raw Buffer, body }
    log: [], // "METHOD host path"
    codes: new Map(), // code → { challenge, redirectUri }
    tokens: new Set(),
    refresh: new Set(),
    errors: [],
  };
  const page = fs.readFileSync(path.join(here, 'gmail.html'));

  function json(res, code, obj) {
    res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(obj));
  }
  function fail(res, code, msg) {
    state.errors.push(msg);
    json(res, code, { error: { code, message: msg } });
  }
  async function body(req) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    return Buffer.concat(chunks).toString();
  }
  function headerOf(raw, name) {
    const head = raw.toString('latin1').split(/\r?\n\r?\n/)[0].replace(/\r?\n[ \t]+/g, ' ');
    const line = head.split(/\r?\n/).find((l) => l.toLowerCase().startsWith(name.toLowerCase() + ':'));
    return line ? line.slice(name.length + 1).trim() : undefined;
  }

  const server = https.createServer({ cert, key }, async (req, res) => {
    const host = (req.headers.host || '').split(':')[0];
    const url = new URL(req.url, `https://${host}`);
    state.log.push(`${req.method} ${host} ${url.pathname}${url.search}`);
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'authorization, content-type',
        'Access-Control-Allow-Methods': 'GET, POST',
      });
      return res.end();
    }
    try {
      if (host === 'mail.google.com') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(page);
      }
      if (host === 'accounts.google.com' && url.pathname === '/o/oauth2/v2/auth') {
        const p = url.searchParams;
        const redirect = p.get('redirect_uri') || '';
        if (p.get('client_id') !== clientId) return fail(res, 400, 'unknown client_id');
        if (p.get('response_type') !== 'code') return fail(res, 400, 'response_type must be code');
        if (p.get('code_challenge_method') !== 'S256' || !p.get('code_challenge')) return fail(res, 400, 'PKCE S256 required');
        if (!/^https:\/\/[a-p]{32}\.chromiumapp\.org\//.test(redirect)) return fail(res, 400, `bad redirect_uri ${redirect}`);
        const scope = p.get('scope') || '';
        if (!scope.includes('gmail.send') || !scope.includes('gmail.readonly')) return fail(res, 400, 'missing gmail scopes');
        const code = b64url(crypto.randomBytes(16));
        state.codes.set(code, { challenge: p.get('code_challenge'), redirect });
        const to = new URL(redirect);
        to.searchParams.set('code', code);
        to.searchParams.set('state', p.get('state') || '');
        res.writeHead(302, { Location: to.toString() });
        return res.end();
      }
      if (host === 'oauth2.googleapis.com' && url.pathname === '/token' && req.method === 'POST') {
        const p = new URLSearchParams(await body(req));
        if (p.get('client_id') !== clientId) return json(res, 401, { error: 'invalid_client' });
        if (p.get('grant_type') === 'authorization_code') {
          const c = state.codes.get(p.get('code'));
          state.codes.delete(p.get('code'));
          if (!c) return json(res, 400, { error: 'invalid_grant' });
          const want = b64url(crypto.createHash('sha256').update(p.get('code_verifier') || '').digest());
          if (want !== c.challenge) return json(res, 400, { error: 'invalid_grant', error_description: 'PKCE verifier mismatch' });
          if (p.get('redirect_uri') !== c.redirect) return json(res, 400, { error: 'redirect_uri_mismatch' });
        } else if (p.get('grant_type') === 'refresh_token') {
          if (!state.refresh.has(p.get('refresh_token'))) return json(res, 400, { error: 'invalid_grant' });
        } else return json(res, 400, { error: 'unsupported_grant_type' });
        const access = `ya29.mock-${b64url(crypto.randomBytes(12))}`;
        const refresh = `1//mock-${b64url(crypto.randomBytes(12))}`;
        state.tokens.add(access);
        state.refresh.add(refresh);
        return json(res, 200, { access_token: access, refresh_token: refresh, expires_in: 3599, token_type: 'Bearer', scope: 'gmail' });
      }
      if (host === 'gmail.googleapis.com' && url.pathname.startsWith('/gmail/v1/users/me/')) {
        const auth = req.headers.authorization || '';
        if (!auth.startsWith('Bearer ') || !state.tokens.has(auth.slice(7))) return fail(res, 401, 'Request had invalid authentication credentials.');
        const rest = url.pathname.slice('/gmail/v1/users/me/'.length);
        if (rest === 'profile') return json(res, 200, { emailAddress: mailbox, messagesTotal: state.messages.size, threadsTotal: state.messages.size, historyId: '1' });
        if (rest === 'messages/send' && req.method === 'POST') {
          const b = JSON.parse(await body(req));
          if (!b.raw || !/^[A-Za-z0-9_-]+=*$/.test(b.raw)) return fail(res, 400, 'raw must be base64url');
          const raw = Buffer.from(b.raw, 'base64url');
          const id = `19${crypto.randomBytes(7).toString('hex')}`;
          state.sent.push({ id, raw, body: b });
          return json(res, 200, { id, threadId: id, labelIds: ['SENT'] });
        }
        if (rest === 'messages' && req.method === 'GET') {
          const q = url.searchParams.get('q') || '';
          const ids = [...state.messages.keys()].filter((id) => !q.includes('encrypted.asc') || /multipart\/encrypted/i.test(headerOf(state.messages.get(id), 'Content-Type') || ''));
          return json(res, 200, { messages: ids.map((id) => ({ id, threadId: id })), resultSizeEstimate: ids.length });
        }
        const m = rest.match(/^messages\/([0-9a-zA-Z]+)$/);
        if (m && req.method === 'GET') {
          const raw = state.messages.get(m[1]);
          if (!raw) return fail(res, 404, 'Requested entity was not found.');
          const fmt = url.searchParams.get('format') || 'full';
          if (fmt === 'raw') return json(res, 200, { id: m[1], threadId: m[1], labelIds: ['INBOX'], sizeEstimate: raw.length, raw: raw.toString('base64url') });
          if (fmt === 'metadata') {
            const wanted = url.searchParams.getAll('metadataHeaders');
            const headers = wanted.map((n) => ({ name: n, value: headerOf(raw, n) })).filter((h) => h.value !== undefined);
            return json(res, 200, { id: m[1], threadId: m[1], payload: { mimeType: (headerOf(raw, 'Content-Type') || '').split(';')[0], headers } });
          }
          return fail(res, 400, `format ${fmt} not mocked`);
        }
      }
      fail(res, 404, `not mocked: ${req.method} ${host}${url.pathname}`);
    } catch (e) {
      fail(res, 500, String(e?.stack || e));
    }
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, state })));
}
