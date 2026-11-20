# Safe HTML mail

Most mail is HTML, and an HTML part is attacker-controlled: anyone can send one. It can carry
script, CSS that overlays or hides content, forms that phish, and images that tell the sender
when (and roughly where) a message was opened. Sealbox therefore never renders what arrived.
Everything a user sees went through one sanitizer, in one place, with one policy.

| Layer | What it does | Where |
|---|---|---|
| `sealbox-mail::html` | the sanitizer: `sanitize(html, RemoteContent) -> SafeHtml`, `html_to_text` | `crates/sealbox-mail/src/html.rs` |
| `sealbox-core` | `Engine::message_html(id, allow_remote) -> Option<HtmlBody>` — the **only** HTML a UI may render | `crates/sealbox-core/src/html.rs` |
| CLI | `sealbox read <id> --html` (and `--load-images`); the text view uses `html_to_text` | `crates/sealbox-cli/src/cmd_read.rs` |
| App | `MessageBody` renders it; remote images blocked, inline `cid:` images from the store, links confirmed, "Show as text" | `app/lib/src/features/inbox/message_body.dart` |
| Fuzzing | `html_sanitize` target asserts the contract on every input (gate G13) | `fuzz/fuzz_targets/html_sanitize.rs` |

`MessageDetail.html` keeps the HTML exactly as it arrived — the send path, quoting and the spam
features read it — and says in its own doc comment that a UI must not render it.

## What survives

**Tags.** `p br div span b strong i em u s a ul ol li blockquote pre code h1–h6 table thead
tbody tfoot tr td th hr img sub sup small`. Any other tag is *unwrapped*: its text stays, the
element goes — except `script style svg math iframe object embed noscript template textarea
select video audio datalist applet noembed noframes title`, which are removed **with their
content**. Comments, doctypes and processing instructions go.

**Attributes.** `dir`, `lang`, `title` anywhere; `align`/`valign` on tables, cells and blocks;
`colspan`/`rowspan` (≤ 100); `start` on `<ol>`; `alt`, `width`, `height` on images; `href` on
links; `src` on images. Values are validated, not just copied (a `dir` is one of three
keywords, a `width` is a number or a percentage). Everything else is dropped: every `on*`
handler, `style`, `class`, `id`, `name`, `target`, `srcset`, `background`, `ping`, `formaction`,
`xlink:href`, `data-*` — the one exception is the blocked-image placeholder below.

**Links.** Only `http:`, `https:` and `mailto:`, parsed with the WHATWG URL parser, so an
obfuscated scheme (`java&#x09;script:`, `&#106;avascript:`, a leading control character) is
recognised for what it is and dropped. What survives is normalised: punycode host,
percent-encoded path, `user:password@` removed — the URL the UI shows before opening a link is
plain ASCII and cannot be dressed up as another domain. Every link gets
`rel="noopener noreferrer nofollow"`; `target` never survives; a link with no usable target is
unwrapped to its text.

**Images.** `cid:` (inline parts), `data:image/(png|jpeg|gif|webp);base64,…` and remote
`http(s):`. An image with no usable source is dropped. A **tracking pixel** — a remote image
whose declared width and height are both ≤ 2 — is dropped and not counted.

**Hidden content.** An element with `hidden`, or whose `style` ends in `display:none`, is
removed with its subtree: newsletter pre-headers and hidden tracking blocks would otherwise
become visible text when the CSS is stripped.

**Control characters.** C0/C1 controls other than tab, newline and carriage return are removed
from both outputs. A mail can carry `ESC [ 2 J`, and the CLI prints text straight to a terminal.

## Remote content

Remote images are **counted** and, by default, **blocked**: each becomes

```html
<span class="sealbox-blocked-image" data-src="https://cdn.example/banner.png"></span>
```

so a renderer fetches nothing until the reader asks. `SafeHtml::remote_images` /
`HtmlBody.remote_images` is what the UI shows as "N images blocked · Load images". Asking again
with `allow_remote = true` returns the same body with real `<img>` elements. The choice is per
message and belongs to the screen: the engine stores no "images allowed" state.

That placeholder is also *accepted on input* and counted like the image it replaced, which is
what makes sanitizing idempotent (below). A sender who writes one gains nothing: it is fetched
only after the reader asks for images, exactly like the `<img>` they could have written instead.

## Inline images

A mail can carry its own pictures: a part with a `Content-ID: <logo@example.com>` header
(usually inside `multipart/related`), which the HTML names as `<img src="cid:logo@example.com">`
(RFC 2392). The store keeps every part's Content-ID (`attachments.content_id`, angle brackets and
control characters removed; plaintext, like the file name), and `AttachmentInfo.content_id`
carries it to the CLI and through the bridge to the app.

* **What resolves.** The `cid:` URL is percent-decoded and stripped of `<>`, then compared with
  each part's Content-ID exactly: case-sensitive, no other normalisation
  (`sealbox_core::cid_content_id` and `MessageDetail::inline_part`; `cidContentId` and
  `inlinePartFor` in the app, same vectors in both test suites). An escape that does not decode
  leaves the URL as written. The bytes come from the local store, never the network, so inline
  images are not remote content: they are neither blocked nor counted in the banner.
* **The app** shows the matching part when its type is `image/*` and its stored size is at most
  **5 MiB** (`kInlineImageMaxBytes`, decided before anything is read). It reads the bytes once per
  Content-ID while the message is on screen ("Show as text" and back or "Load images" read
  nothing again) and decodes them at most **2048 px** on the longer side (`kInlineImageMaxSide`),
  so a small file that describes an enormous bitmap cannot exhaust memory. The image sits at the
  start of its line at its own size, scaled down to fit.
* **What stays a placeholder** (the labelled box with the image's `alt` text, as before): a `cid:`
  that no part carries, a part that is not an image or is over the cap, a read that fails, bytes
  that do not decode, and briefly an image still being read. None of these is an error in the
  thread. "Show as text" is unchanged (the image is its `[alt]`).
* **The attachment chips** under the body leave out a part shown inline, so the logo is not
  listed twice (review N4; `listedAttachments`). A part the HTML never names, and one a `cid:`
  names that is not an image or is over the cap, keep their chip; so does every part while the
  body is shown as text, which is how an inline image is saved ("Show as text" lists it again).
  One whose read or decode fails has no chip in the HTML view either: "Show as text" reaches it.
* **The CLI** prints one line per distinct `cid:` after `read --html`'s markup:
  `inline image: cid:logo@x → attachment 0 (logo.png, image/png, 76 bytes)`, or
  `… → no part of this message has that Content-ID (shown as a placeholder)`.
  `sealbox attachment save <id> <n> <path>` writes the part; `read --json` has
  `attachments[].content_id`.

## CSS: the deliberate trade-off

`style` attributes and `<style>` blocks are **removed**, not filtered. CSS is where remote
fetches (`url()`), legacy script (`expression()`) and overlay/spoofing tricks live, and a CSS
sanitizer is a project of its own. The price is layout fidelity: senders' colours, fonts,
spacing and multi-column layouts are gone, and a newsletter reads as a plain, legible document
in the app's own typography (which is also why it inherits the dark theme correctly). Tables
still lay out, so invoices and statements keep their shape.

## Properties the implementation holds to

* **Never panics, on any input**, and a panic inside the parser would still produce an empty
  result rather than crash the sync loop or the UI.
* **Bounded time.** html5ever's tree builder is quadratic in the depth of the open-element
  stack, so 1 MiB of `<div>` cost **332 s** and 1 MiB of stray end tags 81 s before this was
  addressed. `clamp_structure` now rewrites the input first — 2 MiB of bytes, depth 100, 64
  attributes per tag — which is a *cost* limit, not a security boundary: whatever it leaves
  still goes through the full sanitizer. Measured after: 0.12 s for a 1 MiB newsletter, worst
  of twelve adversarial 1 MiB shapes 0.18 s (release). The twelve are asserted in the tests.
* **A fixed point.** Sanitizing an output again changes nothing. Unwrapping a tag can leave two
  allowed elements nested in a way the parser then re-nests differently (`<h1>a<font><h1>b` →
  two sibling headings on a re-parse); handing a renderer a tree it does not reproduce is the
  shape mutation-XSS exploits, so `sanitize` iterates to a fixed point (at most 3 rounds).
* **Audited output.** `audit_safe_html` re-tokenizes a result and rejects anything outside the
  allow-list; the test corpus and the fuzz target use it as their oracle, so the checks are the
  policy itself rather than a list of strings.

## `html_to_text`

The text rendering of a message (snippets, quoting, accessibility, the CLI's default view):
block elements on their own lines, paragraphs separated by a blank line, `• ` / `N. ` list
items with indentation, `> ` for blockquotes, `text <url>` when a link's text is not already
its target, `[alt]` for images, tab-separated table cells, `<pre>` verbatim, entities decoded,
whitespace collapsed. It applies the same allow-list first, so script and style content and
hidden elements never become text.

## Known limits

* **Inline images of mail stored before the Content-ID column** (2026-10-29) stay placeholders:
  the migration adds the column but cannot re-read the originals (sealed, often encrypted), so
  those parts keep no Content-ID. Their inline image is listed among the attachment chips below
  the body, like any other part.
* **No CSS at all**, as above: a design-heavy newsletter loses its design.
* **`srcset`, `<picture>`, video, audio and web fonts are not supported** — they are dropped.
* **Depth beyond 100 and 64 attributes per tag** are mail no client renders faithfully; the
  content stays, the extra nesting does not.
* The app's HTML view is `flutter_widget_from_html_core`, which supports a subset of layout
  (no floats, limited table sizing). It is only ever given sanitized markup.
