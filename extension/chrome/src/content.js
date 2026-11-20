// Gmail content script. Uses the page DOM ONLY to place two things (see gmail-selectors.js):
//  1. a "Sealbox" button next to Gmail's Compose button, opening the extension's compose
//     panel (an extension-origin iframe — the page cannot read what is typed there);
//  2. a "Decrypt with Sealbox" button on messages the Gmail API reports as PGP/MIME, opening
//     the reader panel (extension-origin iframe) which fetches the raw message by id.
// Message content is never read from, or written into, Gmail's DOM.
import { SEL } from './gmail-selectors.js';

const api = globalThis.browser ?? globalThis.chrome;
const seen = new WeakSet();

function overlay(src, title) {
  document.getElementById('sealbox-overlay')?.remove();
  const wrap = document.createElement('div');
  wrap.id = 'sealbox-overlay';
  wrap.setAttribute('role', 'dialog');
  wrap.setAttribute('aria-label', title);
  const close = document.createElement('button');
  close.className = 'sealbox-close';
  close.textContent = '×';
  close.title = 'Close';
  close.addEventListener('click', () => wrap.remove());
  const frame = document.createElement('iframe');
  frame.src = src;
  frame.className = 'sealbox-frame';
  frame.title = title;
  wrap.append(close, frame);
  document.body.append(wrap);
}

function placeComposeButton() {
  const compose = document.querySelector(SEL.composeButton);
  if (!compose || document.getElementById('sealbox-compose')) return;
  const b = document.createElement('div');
  b.id = 'sealbox-compose';
  b.className = 'sealbox-btn';
  b.setAttribute('role', 'button');
  b.tabIndex = 0;
  b.textContent = 'Sealbox';
  b.title = 'Write an end-to-end encrypted message';
  const open = () => overlay(api.runtime.getURL('compose.html'), 'Sealbox compose');
  b.addEventListener('click', open);
  b.addEventListener('keydown', (e) => (e.key === 'Enter' || e.key === ' ') && open());
  compose.insertAdjacentElement('afterend', b);
}

async function placeDecryptPanels() {
  for (const msg of document.querySelectorAll(SEL.message)) {
    if (seen.has(msg)) continue;
    seen.add(msg);
    const id = msg.getAttribute(SEL.messageIdAttr);
    if (!id) continue;
    let encrypted = false;
    try {
      const r = await api.runtime.sendMessage({ type: 'gmail.isEncrypted', id });
      encrypted = r?.result === true;
    } catch {
      encrypted = false;
    }
    if (!encrypted) continue;
    const bar = document.createElement('div');
    bar.className = 'sealbox-bar';
    const b = document.createElement('button');
    b.className = 'sealbox-btn sealbox-decrypt';
    b.textContent = 'Decrypt with Sealbox';
    b.addEventListener('click', () => {
      if (bar.querySelector('iframe')) return;
      const f = document.createElement('iframe');
      f.className = 'sealbox-inline-frame';
      f.title = 'Sealbox decrypted message';
      f.src = api.runtime.getURL(`reader.html?id=${encodeURIComponent(id)}`);
      bar.append(f);
    });
    bar.append(b);
    const body = msg.querySelector(SEL.messageBody);
    if (body) body.insertAdjacentElement('beforebegin', bar);
    else msg.append(bar);
  }
}

let pending = false;
function scan() {
  if (pending) return;
  pending = true;
  requestAnimationFrame(() => {
    pending = false;
    placeComposeButton();
    placeDecryptPanels();
  });
}

new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true });
scan();
