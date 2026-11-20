// THE ONLY PLACE the extension knows anything about Gmail's page DOM.
//
// Policy (see extension/README.md "Selectors policy"):
//  * The DOM is used for exactly two things: placing the "Sealbox" compose button and placing
//    the "Decrypt with Sealbox" panel next to a message. Message content is NEVER read from
//    the DOM and nothing is ever posted through the page: raw messages come from
//    `users.messages.get?format=raw` and mail leaves through `users.messages.send`.
//  * The one value taken from the DOM is the message's id attribute, which is the Gmail API
//    message id (hex) — used only as the argument of the documented API call.
//  * If a selector stops matching, the extension degrades to "no button", never to scraping.
//
// Version note: selectors as observed on mail.google.com web UI, 2026-10. They are exercised
// in CI only against extension/test/fixture/gmail.html (a static page that mimics them), NOT
// against live Gmail. Re-verify on a real account (see extension/README.md) when Gmail changes.
export const GMAIL_SELECTORS_VERSION = '2026-10';

export const SEL = {
  /** Gmail's own "Compose" button (left navigation); our button goes right after it. */
  composeButton: 'div[gh="cm"]',
  /** One expanded message in a conversation; carries the API message id. */
  message: 'div[data-legacy-message-id]',
  /** Attribute on `message` holding the Gmail API message id (hex). */
  messageIdAttr: 'data-legacy-message-id',
  /** Where inside a message the panel is inserted (before it); falls back to the message. */
  messageBody: 'div.a3s',
};
