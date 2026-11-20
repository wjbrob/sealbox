import { core, send, local, getIdentity, getUnlockedSecret, unlock, lock, session, getContacts, putContact, el } from './common.js';

const $ = (id) => document.getElementById(id);
function status(text, cls = '') {
  const s = $('status');
  s.hidden = false;
  s.className = `status ${cls}`;
  s.textContent = text;
}
async function guard(fn) {
  try {
    await fn();
  } catch (e) {
    status(String(e?.message ?? e), 'bad');
  }
}

async function renderAccount() {
  const st = await send('auth.status');
  $('redirect-uri').textContent = st.redirectUri;
  const o = (await local.get('oauth')) ?? {};
  $('client-id').value = o.clientId ?? '';
  $('client-secret').value = o.clientSecret ?? '';
  $('account').textContent = st.connected ? `Connected as ${st.email ?? '(unknown)'}` : 'Not connected.';
  $('account').className = `status ${st.connected ? 'good' : ''}`;
  if (st.email && !$('new-email').value) $('new-email').value = st.email;
}

async function renderKey() {
  const id = await getIdentity();
  $('key-none').hidden = !!id;
  $('key-have').hidden = !id;
  if (!id) return;
  $('my-fpr').textContent = id.fingerprint;
  $('my-uid').textContent = id.userId ?? id.email;
  $('my-public').value = id.publicArmored;
  $('lock-state').textContent = (await getUnlockedSecret()) ? 'Unlocked for this browser session.' : 'Locked.';
}

async function renderContacts() {
  const c = await getContacts();
  const tb = $('contacts');
  tb.replaceChildren(
    ...Object.entries(c).map(([addr, k]) => el('tr', {}, el('td', {}, addr), el('td', {}, el('code', {}, k.fingerprint)), el('td', {}, k.source))),
  );
}

async function saveIdentity(info, pass) {
  if (!pass || pass.length < 8) throw new Error('Choose a Sealbox passphrase of at least 8 characters.');
  const sb = await core();
  const wrapped = sb.wrapSecret(info.secretArmored, pass);
  await local.set('identity', {
    wrapped,
    publicArmored: info.publicArmored,
    fingerprint: info.fingerprint,
    email: info.primaryEmail ?? info.emails[0],
    userId: info.userIds[0],
  });
  await session.set('unlockedSecret', info.secretArmored);
  await renderKey();
}

$('save-oauth').addEventListener('click', () =>
  guard(async () => {
    await local.set('oauth', { clientId: $('client-id').value.trim(), clientSecret: $('client-secret').value.trim() || undefined });
    status('Saved.', 'good');
  }),
);
$('connect').addEventListener('click', () =>
  guard(async () => {
    await local.set('oauth', { clientId: $('client-id').value.trim(), clientSecret: $('client-secret').value.trim() || undefined });
    status('Connecting…');
    const r = await send('auth.connect');
    status(`Connected as ${r.email}`, 'good');
    await renderAccount();
  }),
);
$('disconnect').addEventListener('click', () => guard(async () => (await send('auth.disconnect'), renderAccount())));

$('generate').addEventListener('click', () =>
  guard(async () => {
    const sb = await core();
    status('Creating key…');
    const info = sb.generateIdentity($('new-name').value.trim(), $('new-email').value.trim());
    await saveIdentity(info, $('new-pass').value);
    status(`Key created: ${info.fingerprint}`, 'good');
  }),
);
$('import').addEventListener('click', () =>
  guard(async () => {
    const sb = await core();
    const info = sb.importIdentity($('import-secret').value, $('import-pass').value || undefined);
    await saveIdentity(info, $('new-pass').value);
    $('import-secret').value = '';
    status(`Key imported: ${info.fingerprint}`, 'good');
  }),
);
$('unlock').addEventListener('click', () =>
  guard(async () => {
    await unlock($('unlock-pass').value);
    $('unlock-pass').value = '';
    await renderKey();
    status('Unlocked.', 'good');
  }),
);
$('lock').addEventListener('click', () => guard(async () => (await lock(), renderKey())));

$('add-contact').addEventListener('click', () =>
  guard(async () => {
    const sb = await core();
    const k = sb.inspectPublicKey($('contact-key').value);
    if (!k.emails.length) throw new Error('That key has no e-mail address in its User IDs.');
    if (!k.encryptionCapable) throw new Error('That key cannot encrypt.');
    for (const addr of k.emails) await putContact(addr, { publicArmored: k.publicArmored, fingerprint: k.fingerprint, source: 'manual' });
    $('contact-key').value = '';
    await renderContacts();
    status(`Added ${k.emails.join(', ')}`, 'good');
  }),
);

guard(async () => {
  await Promise.all([renderAccount(), renderKey(), renderContacts()]);
});
