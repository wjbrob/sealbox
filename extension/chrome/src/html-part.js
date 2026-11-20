// The document put into the reader's sandboxed `srcdoc` iframe for an HTML part (threat-model
// R8): the part is preceded by a document CSP that allows no network at all — no remote images
// (read receipts / IP disclosure), fonts, media, frames or form posts; inline styles stay so the
// mail still looks like itself, `data:` images stay (no fetch). The extension-page CSP in
// manifest.json (inherited by srcdoc frames) is the second layer; this one does not depend on
// that inheritance. No imports: test/fixture/e2e.mjs loads this file in Node as well.
export const HTML_PART_CSP =
  "default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'";

export function htmlDocument(html) {
  return `<!doctype html><meta http-equiv="Content-Security-Policy" content="${HTML_PART_CSP}">${html}`;
}
