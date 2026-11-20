//! Safe HTML for display: the sanitizer that must sit between a received HTML body and any
//! renderer, and the HTML → text conversion for snippets, quoting and the CLI. Policy, the
//! remote-content rules and the known limits: `docs/HTML_MAIL.md`.
//!
//! Received HTML is attacker-controlled. [`sanitize`] parses it the way a browser does
//! (html5ever, through [ammonia]) and keeps an allow-list only:
//!
//! * **Tags** — [`ALLOWED_TAGS`]: structure and formatting (`p br div span b strong i em u s
//!   a ul ol li blockquote pre code h1–h6 table thead tbody tfoot tr td th hr img sub sup
//!   small`). Anything else is unwrapped (its text stays), except [`DROPPED_WITH_CONTENT`]
//!   (`script style svg math iframe object embed noscript template textarea select video
//!   audio title …`), which goes together with everything inside it. Comments, doctypes and
//!   processing instructions go.
//! * **Attributes** — a handful per tag, values validated (`dir`, `lang`, `title`, `align`,
//!   `valign`, `colspan`/`rowspan` ≤ 100, image `width`/`height`, `ol start`). Every event
//!   handler, `style`, `class`, `id`, `name`, `target`, `srcset`, `background`, `ping` … goes.
//! * **Links** — `a[href]` only `http:`, `https:` and `mailto:`, normalised by the WHATWG URL
//!   parser (so `java\tscript:` and `&#106;avascript:` are recognised for what they are, hosts
//!   are punycode, paths percent-encoded: the URL a UI shows before opening it is plain ASCII),
//!   with `user:password@` removed and `rel="noopener noreferrer nofollow"`; `target` never
//!   survives. A link without a usable target is unwrapped to its text.
//! * **Images** — `img[src]` only `cid:`, `data:image/(png|jpeg|gif|webp);base64,…` and remote
//!   `http(s):`. Remote images are counted in [`SafeHtml::remote_images`]; with
//!   [`RemoteContent::Blocked`] each becomes `<span class="sealbox-blocked-image"
//!   data-src="…"></span>` ([`BLOCKED_IMAGE_CLASS`]), so a renderer fetches nothing until the
//!   user asks, and with [`RemoteContent::Allowed`] it stays an `<img>`. Images without a usable
//!   source and remote tracking pixels (declared width and height both ≤ 2) are dropped. That
//!   placeholder is also *accepted* on input — it is another spelling of a remote image, counted
//!   like one — so sanitizing an output again is a no-op. A sender who writes one gains nothing:
//!   it is fetched only after the user asks for images, exactly like the `<img>` they could have
//!   written instead. `class` and `data-src` survive on nothing else.
//! * **Control characters** — C0/C1 controls other than tab, newline and carriage return are
//!   dropped from both outputs. A received mail may contain `ESC [ 2 J` or `ESC ] 0 ;`, and the
//!   CLI prints [`html_to_text`] straight to a terminal, where those would move the cursor,
//!   repaint the screen or set the window title.
//! * **CSS** — `style` attributes and `<style>` blocks are removed: CSS is where remote fetches
//!   (`url()`), legacy script (`expression()`) and overlay/spoofing tricks live, and a CSS
//!   sanitizer is a project of its own. The price is layout fidelity (colours, fonts, spacing).
//!   The one declaration that is read is `display:none` (and the `hidden` attribute): such
//!   elements — newsletter pre-headers, hidden tracking blocks — are dropped with their content
//!   instead of becoming visible.
//!
//! Sanitizing is run to a **fixed point** (at most [`MAX_PASSES`] rounds): unwrapping a tag can
//! leave two allowed elements nested in a way the parser then re-nests differently (`<h1>` inside
//! `<h1>` becomes two sibling headings on a re-parse), so one round is not always stable, and an
//! output that re-parses to a different tree is the shape mutation-XSS exploits. The result is a
//! canonical form: a renderer, a second sanitizer or a `message_html` re-render all see the same
//! tree. The remote-image count is unchanged by a further round, which is why a blocked-image
//! placeholder is accepted on input.
//!
//! Each round is two passes: ammonia (the HTML standard's parsing algorithm, the allow-list, URL schemes and
//! [`filter_attribute`]), then a post-pass over ammonia's serialisation with html5ever's
//! tokenizer — the serialisation is well-formed, so the tokenizer sees exactly ammonia's tree —
//! which re-checks the allow-list, applies the remote-content policy and writes the result with
//! every text and attribute value escaped. [`audit_safe_html`] re-checks any output against the
//! same rules (tests and the `html_sanitize` fuzz target use it as their oracle).
//!
//! Neither function panics on any input (a panic inside the parser would be caught and give an
//! empty result) and the work is bounded. Bounding needs more than a byte limit: html5ever's tree
//! builder is quadratic in the depth of the open-element stack (the in-scope and "any other end
//! tag" walks), so 1 MiB of `<div>` or of stray end tags costs minutes, which would hang the sync
//! loop or the UI on one hostile mail. [`clamp_structure`] therefore rewrites the input first —
//! bytes beyond [`MAX_HTML_BYTES`], nesting beyond [`MAX_DEPTH`], unmatched end tags and tags with
//! more than [`MAX_ATTRS`] attributes — and that clamp is a **cost** limit, not a security
//! boundary: whatever it leaves still goes through the full sanitizer below, so mangling it could
//! do can never make the output unsafe. Measured on 1 MiB inputs: 0.14 s for a real newsletter and
//! under 1 s for each of the twelve adversarial shapes in the tests (before: 332 s).

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::LazyLock;

use ammonia::url::Url;
use ammonia::UrlRelative;
use html5ever::buffer_queue::BufferQueue;
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::{
    Tag, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
};

/// Whether remote (`http:`/`https:`) images may be fetched by the renderer.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum RemoteContent {
    /// Remote images become [`BLOCKED_IMAGE_CLASS`] placeholders (the default).
    #[default]
    Blocked,
    /// Remote images stay `<img>` elements (the user chose "Load images" for this message).
    Allowed,
}

/// The result of [`sanitize`].
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SafeHtml {
    /// Well-formed HTML within the allow-list; safe to hand to a renderer as is.
    pub html: String,
    /// Remote images in the message (blocked or not; tracking pixels and hidden images are
    /// dropped and not counted). A UI shows "N images blocked · Load images" when this is > 0
    /// and the content was [`RemoteContent::Blocked`].
    pub remote_images: usize,
}

/// Class of the placeholder that replaces a blocked remote image:
/// `<span class="sealbox-blocked-image" data-src="https://…"></span>`. Input can never carry a
/// `class` or `data-*` attribute, so every element with this class came from [`sanitize`].
pub const BLOCKED_IMAGE_CLASS: &str = "sealbox-blocked-image";

/// Rounds of sanitizing allowed while looking for a fixed point (see above); two are enough for
/// every input found so far, the third is the bound.
pub const MAX_PASSES: usize = 3;

/// HTML input beyond this many bytes is cut off (at a character boundary) before parsing. Mail
/// clients clip much earlier (Gmail at 102 KB); this only bounds the work on hostile input.
pub const MAX_HTML_BYTES: usize = 2 * 1024 * 1024;

/// Deepest element nesting that survives [`clamp_structure`]; deeper start tags are dropped and
/// their content is kept. Real mail nests far less (Outlook's table layouts ~40).
pub const MAX_DEPTH: usize = 100;

/// Most attributes kept on one tag by [`clamp_structure`]; a tag with more keeps none (the
/// tokenizer's duplicate-attribute check is quadratic in the attribute count).
pub const MAX_ATTRS: usize = 64;

/// The tags that survive. `span` doubles as the blocked-image placeholder.
pub const ALLOWED_TAGS: &[&str] = &[
    "a",
    "b",
    "blockquote",
    "br",
    "code",
    "div",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "img",
    "li",
    "ol",
    "p",
    "pre",
    "s",
    "small",
    "span",
    "strong",
    "sub",
    "sup",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "u",
    "ul",
];

/// Elements removed together with their content (everything else outside [`ALLOWED_TAGS`] is
/// unwrapped and keeps its text).
pub const DROPPED_WITH_CONTENT: &[&str] = &[
    "applet", "audio", "datalist", "embed", "iframe", "math", "noembed", "noframes", "noscript",
    "object", "script", "select", "style", "svg", "template", "textarea", "title", "video",
];

const VOID_TAGS: &[&str] = &["br", "hr", "img"];

/// Attributes accepted on every allowed tag. `style` and `hidden` are only read (to drop hidden
/// elements) and never written.
const GENERIC_ATTRIBUTES: &[&str] = &["dir", "hidden", "lang", "style", "title"];

/// Per-tag attributes (on top of [`GENERIC_ATTRIBUTES`]).
const TAG_ATTRIBUTES: &[(&str, &[&str])] = &[
    ("a", &["href"]),
    ("img", &["src", "alt", "width", "height"]),
    ("td", &["colspan", "rowspan", "align", "valign"]),
    ("th", &["colspan", "rowspan", "align", "valign"]),
    ("tr", &["align", "valign"]),
    ("ol", &["start"]),
    // only ever as the blocked-image placeholder pair, both validated below
    ("span", &["class", "data-src"]),
    ("p", &["align"]),
    ("div", &["align"]),
    ("h1", &["align"]),
    ("h2", &["align"]),
    ("h3", &["align"]),
    ("h4", &["align"]),
    ("h5", &["align"]),
    ("h6", &["align"]),
    ("table", &["align"]),
    ("thead", &["align"]),
    ("tbody", &["align"]),
    ("tfoot", &["align"]),
];

/// The `rel` every surviving link gets.
pub const LINK_REL: &str = "noopener noreferrer nofollow";

const MAX_SPAN: u32 = 100;

static AMMONIA: LazyLock<ammonia::Builder<'static>> = LazyLock::new(|| {
    let tag_attributes: HashMap<&'static str, HashSet<&'static str>> = TAG_ATTRIBUTES
        .iter()
        .map(|(tag, attrs)| (*tag, attrs.iter().copied().collect()))
        .collect();
    let mut b = ammonia::Builder::empty();
    b.tags(ALLOWED_TAGS.iter().copied().collect())
        .clean_content_tags(DROPPED_WITH_CONTENT.iter().copied().collect())
        .generic_attributes(GENERIC_ATTRIBUTES.iter().copied().collect())
        .tag_attributes(tag_attributes)
        .tag_attribute_values(HashMap::new())
        .set_tag_attribute_values(HashMap::new())
        .allowed_classes(HashMap::new())
        // a first, coarse scheme check; `filter_attribute` narrows it per element
        .url_schemes(
            ["http", "https", "mailto", "cid", "data"]
                .into_iter()
                .collect(),
        )
        .url_relative(UrlRelative::Deny)
        .link_rel(Some(LINK_REL))
        .strip_comments(true)
        .id_prefix(None)
        .attribute_filter(filter_attribute);
    b
});

/// Sanitize received HTML for display. See the module documentation for what survives.
pub fn sanitize(html: &str, remote: RemoteContent) -> SafeHtml {
    catch_unwind(AssertUnwindSafe(|| {
        let mut out = sanitize_once(html, remote);
        for _ in 1..MAX_PASSES {
            let next = sanitize_once(&out.html, remote);
            if next.html == out.html {
                break;
            }
            out = next;
        }
        out
    }))
    .unwrap_or_default()
}

/// One round: clamp, ammonia, post-pass.
fn sanitize_once(html: &str, remote: RemoteContent) -> SafeHtml {
    let html = clamp_structure(bounded(html));
    let normalised = AMMONIA.clean(&html).to_string();
    let sink = tokenize(
        &normalised,
        PostPass {
            remote,
            out: RefCell::new(String::with_capacity(normalised.len())),
            remote_images: Cell::new(0),
            anchors: RefCell::new(Vec::new()),
            hidden_depth: Cell::new(0),
            after_pre: Cell::new(false),
        },
    );
    SafeHtml {
        html: sink.out.into_inner(),
        remote_images: sink.remote_images.get(),
    }
}

/// Readable plain text from (untrusted) HTML: block elements on their own lines, paragraphs
/// separated by a blank line, `• ` / `N. ` list items, `> ` for blockquotes, `text <url>` for
/// links whose text is not already the URL, `[alt]` for images, table cells separated by a tab,
/// `<pre>` verbatim, entities decoded, whitespace collapsed. Applies the same allow-list as
/// [`sanitize`] first, so script and style content and hidden elements never become text.
pub fn html_to_text(html: &str) -> String {
    let html = clamp_structure(bounded(html));
    catch_unwind(AssertUnwindSafe(|| {
        let normalised = AMMONIA.clean(&html).to_string();
        let sink = tokenize(&normalised, TextSink::default());
        sink.finish()
    }))
    .unwrap_or_default()
}

fn bounded(html: &str) -> &str {
    if html.len() <= MAX_HTML_BYTES {
        return html;
    }
    let mut end = MAX_HTML_BYTES;
    while !html.is_char_boundary(end) {
        end -= 1;
    }
    &html[..end]
}

/// Elements whose content is not markup: the tokenizer reads everything up to their own end tag
/// as text, so the clamp copies that span verbatim instead of looking for tags inside it.
const RAW_TEXT_TAGS: &[&str] = &["script", "style", "textarea", "title"];

/// Elements with no end tag (the HTML void set): they never open a level.
const HTML_VOID_TAGS: &[&str] = &[
    "area", "base", "basefont", "bgsound", "br", "col", "embed", "frame", "hr", "img", "input",
    "keygen", "link", "meta", "param", "source", "track", "wbr",
];

/// Rewrite `html` so that the parser's cost is linear: nesting is capped at [`MAX_DEPTH`] (deeper
/// start tags are dropped, their content kept) and a tag with more than [`MAX_ATTRS`] attributes
/// keeps none. Everything else — text, every end tag, comments, declarations, raw-text spans —
/// is copied through unchanged: with the depth cap in place the parser's per-tag stack walks are
/// bounded, so stray end tags cost nothing and dropping them would only mangle misnested
/// formatting that the parser recovers correctly.
///
/// This is a **cost** limit, not a security boundary: everything it emits still goes through
/// [`sanitize`]'s allow-list, so no mangling here can produce unsafe output.
fn clamp_structure(html: &str) -> Cow<'_, str> {
    let mut out = String::new();
    // Open elements, innermost last. Capped at MAX_DEPTH, so the match below is O(MAX_DEPTH).
    let mut open: Vec<&str> = Vec::new();
    let mut rest = html;
    let mut changed = false;
    while !rest.is_empty() {
        let Some(lt) = rest.find('<') else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..lt]);
        rest = &rest[lt..];
        // comments, declarations, processing instructions: not markup, copied as they are
        for (start, end) in [("<!--", "-->"), ("<!", ">"), ("<?", ">")] {
            if rest.starts_with(start) {
                let upto = rest.find(end).map_or(rest.len(), |e| e + end.len());
                out.push_str(&rest[..upto]);
                rest = &rest[upto..];
                break;
            }
        }
        if !rest.starts_with('<') {
            continue;
        }
        let after = &rest[1..];
        let closing = after.starts_with('/');
        let named = if closing { &after[1..] } else { after };
        let name_len = named
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'-')
            .count();
        if name_len == 0 {
            // not a tag: a literal `<`, which the sanitizer escapes
            out.push('<');
            rest = after;
            continue;
        }
        let (name, attrs) = named.split_at(name_len);
        let Some((attr_text, consumed)) = scan_tag_end(attrs) else {
            // unterminated tag: nothing after it can open a level
            out.push_str(rest);
            break;
        };
        let tag = &rest[..1 + usize::from(closing) + name_len + consumed];
        rest = &named[name_len + consumed..];
        let matches = |set: &[&str]| set.iter().any(|t| t.eq_ignore_ascii_case(name));
        let void = attr_text.trim_end().ends_with('/') || matches(HTML_VOID_TAGS);
        let mut emit = |tag: &str| {
            if count_attributes(attr_text) > MAX_ATTRS {
                changed = true;
                out.push('<');
                if closing {
                    out.push('/');
                }
                out.push_str(name);
                out.push('>');
            } else {
                out.push_str(tag);
            }
        };
        if closing {
            if let Some(p) = open.iter().rposition(|o| o.eq_ignore_ascii_case(name)) {
                open.truncate(p);
            }
            emit(tag);
            continue;
        }
        if matches(RAW_TEXT_TAGS) {
            // copy the element whole, so its text is never read as markup
            open.push(name);
            emit(tag);
            let lower = rest.to_ascii_lowercase();
            let upto = lower
                .find(&format!("</{}", name.to_ascii_lowercase()))
                .map_or(rest.len(), |e| e);
            out.push_str(&rest[..upto]);
            rest = &rest[upto..];
            continue;
        }
        if void {
            emit(tag);
        } else if open.len() < MAX_DEPTH {
            open.push(name);
            emit(tag);
        } else {
            changed = true; // too deep: the tag goes, its content stays
        }
    }
    if changed {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(html)
    }
}

/// End of a tag after its name, honouring quoted attribute values (a quote opens a value only
/// right after `=`). Returns the attribute text and the bytes consumed, `>` included.
fn scan_tag_end(s: &str) -> Option<(&str, usize)> {
    let mut quote: Option<u8> = None;
    let mut expect_value = false;
    for (i, b) in s.bytes().enumerate() {
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' if expect_value => {
                    quote = Some(b);
                    expect_value = false;
                }
                b'>' => return Some((&s[..i], i + 1)),
                b'=' => expect_value = true,
                b' ' | b'\t' | b'\r' | b'\n' => {}
                _ => expect_value = false,
            },
        }
    }
    None
}

/// Attributes in a tag's attribute text, counted up to `MAX_ATTRS + 1` (no more is needed).
/// Names only: a value — quoted or bare — is skipped, never counted.
fn count_attributes(attr_text: &str) -> usize {
    let b = attr_text.as_bytes();
    let mut i = 0;
    let mut n = 0;
    while i < b.len() {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        let name_start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'=' && b[i] != b'/' {
            i += 1;
        }
        if i == name_start {
            break;
        }
        n += 1;
        if n > MAX_ATTRS {
            return n;
        }
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            match b.get(i) {
                Some(q @ (b'"' | b'\'')) => {
                    let q = *q;
                    i += 1;
                    while i < b.len() && b[i] != q {
                        i += 1;
                    }
                    i += 1; // the closing quote (or past the end)
                }
                _ => {
                    while i < b.len() && !b[i].is_ascii_whitespace() {
                        i += 1;
                    }
                }
            }
        }
    }
    n
}

fn tokenize<S: TokenSink<Handle = ()>>(html: &str, sink: S) -> S {
    let input = BufferQueue::default();
    input.push_back(StrTendril::from_slice(html));
    let tok = Tokenizer::new(sink, TokenizerOpts::default());
    let _ = tok.feed(&input);
    tok.end();
    tok.sink
}

/// Does `text` look like the HTML *body of a mail* rather than plain text that happens to
/// contain an angle bracket?
///
/// Needed because of a parsing quirk upstream of here: mail-parser lists the HTML part as a
/// *text* body when a message has no `text/plain` alternative, so an HTML-only mail arrives with
/// its markup in the text field and no HTML part at all (`mime::parse` → `PlainBody`). Callers
/// that must render such a mail safely ask this first; a plain-text mail mentioning `<u8>` or
/// `a < b` must not be mistaken for HTML, so a lone unknown tag is not enough: the text has to
/// open an element that only a document has ([`DOCUMENT_TAGS`]) and parse as containing markup.
pub fn looks_like_html_document(text: &str) -> bool {
    let head: String = text
        .chars()
        .take(MAX_HTML_BYTES / 8)
        .collect::<String>()
        .to_ascii_lowercase();
    DOCUMENT_TAGS.iter().any(|t| head.contains(t)) && ammonia::is_html(&head)
}

/// Element openings that mark mail HTML (and that no plain-text mail writes by accident).
const DOCUMENT_TAGS: &[&str] = &[
    "<html",
    "<body",
    "<head",
    "<!doctype html",
    "<div",
    "<table",
    "<p>",
    "<p ",
    "<br>",
    "<br/>",
    "<br />",
    "<span",
    "<img ",
    "<a href",
    "<ul>",
    "<ol>",
    "<h1",
    "<h2",
    "<h3",
    "<blockquote",
    "<center",
    "<font",
];

// ---- attribute policy ---------------------------------------------------------------------

/// ammonia's per-attribute hook (and the post-pass's re-check): `None` drops the attribute,
/// otherwise the (normalised) value to keep. Only allow-listed attributes of allow-listed tags
/// reach it from ammonia; anything else is dropped here too.
pub fn filter_attribute<'u>(
    element: &str,
    attribute: &str,
    value: &'u str,
) -> Option<Cow<'u, str>> {
    match attribute {
        "style" => is_display_none(value).then_some(Cow::Borrowed("display:none")),
        "hidden" => Some(Cow::Borrowed("")),
        "rel" if element == "a" => Some(Cow::Borrowed(LINK_REL)),
        "class" if element == "span" => {
            (value == BLOCKED_IMAGE_CLASS).then_some(Cow::Borrowed(BLOCKED_IMAGE_CLASS))
        }
        "data-src" if element == "span" => {
            image_src(value).filter(|s| is_remote(s)).map(Cow::Owned)
        }
        "title" => Some(Cow::Borrowed(value)),
        "alt" if element == "img" => Some(Cow::Borrowed(value)),
        "dir" => keyword(value, &["ltr", "rtl", "auto"]),
        "lang" => {
            let v = value.trim();
            (!v.is_empty()
                && v.len() <= 35
                && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            .then(|| Cow::Owned(v.to_owned()))
        }
        "align" => keyword(value, &["left", "right", "center", "justify"]),
        "valign" => keyword(value, &["top", "middle", "bottom", "baseline"]),
        "colspan" | "rowspan" if element == "td" || element == "th" => {
            number(value).map(|n| Cow::Owned(n.clamp(1, MAX_SPAN).to_string()))
        }
        "start" if element == "ol" => {
            number(value).map(|n| Cow::Owned(n.min(1_000_000).to_string()))
        }
        "width" | "height" if element == "img" => dimension(value).map(Cow::Owned),
        "href" if element == "a" => link_href(value).map(Cow::Owned),
        "src" if element == "img" => image_src(value).map(Cow::Owned),
        _ => None,
    }
}

fn keyword<'u>(value: &str, allowed: &[&'static str]) -> Option<Cow<'u, str>> {
    let v = value.trim();
    allowed
        .iter()
        .find(|k| k.eq_ignore_ascii_case(v))
        .map(|k| Cow::Borrowed(*k))
}

fn number(value: &str) -> Option<u32> {
    let v = value.trim();
    if v.is_empty() || v.len() > 9 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

/// `123` or `45%` (pixels or percent), nothing else.
fn dimension(value: &str) -> Option<String> {
    let v = value.trim();
    let (digits, percent) = match v.strip_suffix('%') {
        Some(d) => (d, true),
        None => (v, false),
    };
    let n = number(digits)?;
    if (percent && n > 100) || n > 10_000 {
        return None;
    }
    Some(if percent {
        format!("{n}%")
    } else {
        n.to_string()
    })
}

/// The last `display` declaration of a style attribute says `none`. A heuristic that only
/// ever hides content the sender hid: false negatives just show it.
fn is_display_none(style: &str) -> bool {
    let mut hidden = false;
    for decl in style.split(';') {
        if let Some((prop, val)) = decl.split_once(':') {
            if prop.trim().eq_ignore_ascii_case("display") {
                let v = val.trim().to_ascii_lowercase();
                hidden = v.trim_end_matches("!important").trim() == "none";
            }
        }
    }
    hidden
}

fn parse_url(value: &str) -> Option<Url> {
    // The WHATWG parser trims C0 controls and spaces and removes tabs and newlines, exactly as
    // a browser does, so the scheme seen here is the scheme a renderer would act on.
    Url::parse(value).ok()
}

fn strip_credentials(url: &mut Url) {
    // Neither setter can fail on an http(s) URL with a host; ignore the impossible error.
    let _ = url.set_username("");
    let _ = url.set_password(None);
}

/// `http(s):` (with a host, credentials removed) or `mailto:`, normalised.
fn link_href(value: &str) -> Option<String> {
    let mut url = parse_url(value)?;
    match url.scheme() {
        "http" | "https" => {
            url.host()?;
            strip_credentials(&mut url);
            Some(url.into())
        }
        "mailto" => (!url.path().is_empty()).then(|| url.into()),
        _ => None,
    }
}

/// `http(s):`, `cid:` or a base64 PNG/JPEG/GIF/WebP `data:` URL, normalised.
fn image_src(value: &str) -> Option<String> {
    let mut url = parse_url(value)?;
    match url.scheme() {
        "http" | "https" => {
            url.host()?;
            strip_credentials(&mut url);
            Some(url.into())
        }
        "cid" => (!url.path().is_empty()).then(|| url.into()),
        "data" => {
            (url.query().is_none() && url.fragment().is_none() && is_allowed_data_image(url.path()))
                .then(|| url.into())
        }
        _ => None,
    }
}

fn is_allowed_data_image(path: &str) -> bool {
    let Some((meta, payload)) = path.split_once(',') else {
        return false;
    };
    let meta = meta.to_ascii_lowercase();
    matches!(
        meta.as_str(),
        "image/png;base64" | "image/jpeg;base64" | "image/gif;base64" | "image/webp;base64"
    ) && payload.bytes().any(|b| b != b'=' && b != b' ')
        && payload
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b' '))
}

fn is_remote(src: &str) -> bool {
    src.starts_with("https://") || src.starts_with("http://")
}

fn allowed_tag(name: &str) -> Option<&'static str> {
    ALLOWED_TAGS.iter().copied().find(|t| *t == name)
}

fn tag_allows(tag: &str, attribute: &str) -> bool {
    GENERIC_ATTRIBUTES.contains(&attribute)
        || (tag == "a" && attribute == "rel")
        || TAG_ATTRIBUTES
            .iter()
            .any(|(t, attrs)| *t == tag && attrs.contains(&attribute))
}

fn attr<'t>(tag: &'t Tag, name: &str) -> Option<&'t str> {
    tag.attrs
        .iter()
        .find(|a| &*a.name.local == name)
        .map(|a| &*a.value)
}

fn is_hidden(tag: &Tag) -> bool {
    attr(tag, "hidden").is_some() || attr(tag, "style").is_some_and(is_display_none)
}

/// The remote image URL of a blocked-image placeholder (`<span class="sealbox-blocked-image"
/// data-src="https://…">`), whether we wrote it or the sender did.
fn placeholder_src(tag: &Tag) -> Option<String> {
    if &*tag.name != "span" || attr(tag, "class") != Some(BLOCKED_IMAGE_CLASS) {
        return None;
    }
    attr(tag, "data-src")
        .and_then(image_src)
        .filter(|s| is_remote(s))
}

/// Remote image whose declared width and height are both at most 2 px.
fn is_tracking_pixel(tag: &Tag) -> bool {
    let px = |name| {
        attr(tag, name)
            .and_then(|v| number(v.trim()))
            .is_some_and(|n| n <= 2)
    };
    px("width") && px("height")
}

// ---- escaping -----------------------------------------------------------------------------

/// A C0/C1 control character that is not tab, newline or carriage return: dropped from every
/// output (see the module documentation — the CLI prints text to a terminal).
fn is_control(c: char) -> bool {
    c.is_control() && !matches!(c, '\t' | '\n' | '\r')
}

fn escape_text(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\u{a0}' => out.push_str("&nbsp;"),
            c if is_control(c) => {}
            _ => out.push(c),
        }
    }
}

fn escape_attr(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\u{a0}' => out.push_str("&nbsp;"),
            c if is_control(c) => {}
            _ => out.push(c),
        }
    }
}

// ---- post-pass ----------------------------------------------------------------------------

struct PostPass {
    remote: RemoteContent,
    out: RefCell<String>,
    remote_images: Cell<usize>,
    /// One entry per open `<a>`: was its start tag written (did it have a usable href)?
    anchors: RefCell<Vec<bool>>,
    /// > 0 inside a hidden element, whose whole subtree is dropped.
    hidden_depth: Cell<usize>,
    /// A `<pre>` start tag was just written: if its text starts with a newline, write one more
    /// (the parser drops a newline right after `<pre>`, html5ever's serialiser does not add it
    /// back, and without it every round trip would lose one).
    after_pre: Cell<bool>,
}

impl TokenSink for PostPass {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<()> {
        match token {
            Token::TagToken(tag) => {
                self.after_pre.set(false);
                self.tag(&tag);
            }
            Token::CharacterTokens(text) if self.hidden_depth.get() == 0 => {
                let mut out = self.out.borrow_mut();
                if self.after_pre.replace(false) && text.starts_with('\n') {
                    out.push('\n');
                }
                escape_text(&mut out, &text);
            }
            // comments, doctypes, NUL and parse errors: ammonia's output has none, and none
            // is ever written
            _ => {}
        }
        TokenSinkResult::Continue
    }
}

impl PostPass {
    fn tag(&self, tag: &Tag) {
        let Some(name) = allowed_tag(&tag.name) else {
            return;
        };
        let void = VOID_TAGS.contains(&name);
        let depth = self.hidden_depth.get();
        if tag.kind == TagKind::EndTag {
            if void {
                return;
            }
            if depth > 0 {
                self.hidden_depth.set(depth - 1);
                return;
            }
            if name == "a" && !self.anchors.borrow_mut().pop().unwrap_or(false) {
                return;
            }
            let mut out = self.out.borrow_mut();
            out.push_str("</");
            out.push_str(name);
            out.push('>');
            return;
        }
        if depth > 0 || is_hidden(tag) {
            if !void {
                self.hidden_depth.set(depth + 1);
            }
            return;
        }
        match name {
            "img" => {
                let Some(src) = attr(tag, "src").and_then(image_src) else {
                    return;
                };
                if is_remote(&src) {
                    if is_tracking_pixel(tag) {
                        return;
                    }
                    self.remote_images.set(self.remote_images.get() + 1);
                    if self.remote == RemoteContent::Blocked {
                        let mut out = self.out.borrow_mut();
                        out.push_str("<span class=\"");
                        out.push_str(BLOCKED_IMAGE_CLASS);
                        out.push_str("\" data-src=\"");
                        escape_attr(&mut out, &src);
                        out.push_str("\"></span>");
                        return;
                    }
                }
                self.write_start(name, tag);
            }
            "a" => {
                let keep = attr(tag, "href").and_then(link_href).is_some();
                self.anchors.borrow_mut().push(keep);
                if keep {
                    self.write_start(name, tag);
                }
            }
            "span" => {
                if placeholder_src(tag).is_some() {
                    self.remote_images.set(self.remote_images.get() + 1);
                }
                self.write_start(name, tag);
            }
            _ => {
                self.write_start(name, tag);
                self.after_pre.set(name == "pre");
            }
        }
    }

    fn write_start(&self, name: &str, tag: &Tag) {
        // `class` and `data-src` only ever travel together, as the placeholder pair
        let placeholder = placeholder_src(tag).is_some();
        let mut out = self.out.borrow_mut();
        out.push('<');
        out.push_str(name);
        for a in &tag.attrs {
            let key: &str = &a.name.local;
            if matches!(key, "style" | "hidden" | "rel") || !tag_allows(name, key) {
                continue;
            }
            if matches!(key, "class" | "data-src") && !placeholder {
                continue;
            }
            if let Some(v) = filter_attribute(name, key, &a.value) {
                out.push(' ');
                out.push_str(key);
                out.push_str("=\"");
                escape_attr(&mut out, &v);
                out.push('"');
            }
        }
        if name == "a" {
            out.push_str(" rel=\"");
            out.push_str(LINK_REL);
            out.push('"');
        }
        out.push('>');
    }
}

// ---- HTML → text --------------------------------------------------------------------------

#[derive(Default)]
struct TextSink {
    st: RefCell<TextState>,
}

#[derive(Default)]
struct TextState {
    out: String,
    /// Consecutive newlines at the end of `out`.
    nl: usize,
    /// Line breaks owed before the next content: 1 = new line, 2 = blank line.
    breaks: usize,
    /// Quote depth that owed blank lines are prefixed with (the lowest since the request).
    break_quote: usize,
    /// A collapsed space is owed before the next content on this line.
    space: bool,
    /// A table-cell separator is owed before the next content on this line.
    sep: bool,
    pre: usize,
    quote: usize,
    /// Open lists: `None` bulleted, `Some(n)` numbered with the next number.
    lists: Vec<Option<u64>>,
    /// Open links: the target (if any) and where their text starts in `out`.
    links: Vec<Option<(String, usize)>>,
    /// Cells seen in the current row of every open table.
    cells: Vec<usize>,
    hidden: usize,
}

impl TokenSink for TextSink {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<()> {
        let mut st = self.st.borrow_mut();
        match token {
            Token::TagToken(tag) => st.tag(&tag),
            Token::CharacterTokens(text) if st.hidden == 0 => st.text(&text),
            _ => {}
        }
        TokenSinkResult::Continue
    }
}

impl TextSink {
    fn finish(self) -> String {
        let out = self.st.into_inner().out;
        let mut result = String::with_capacity(out.len());
        let mut blank = 0;
        for line in out.lines() {
            let line = line.trim_end();
            if line.is_empty() {
                blank += 1;
                continue;
            }
            if !result.is_empty() {
                result.push_str(if blank > 0 { "\n\n" } else { "\n" });
            }
            blank = 0;
            result.push_str(line);
        }
        result
    }
}

/// Characters that are invisible in text and only pad or break words (zero-width space,
/// word joiner, BOM, soft hyphen, combining grapheme joiner). ZWJ/ZWNJ stay: emoji sequences
/// and several scripts need them.
fn invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200b}' | '\u{2060}' | '\u{feff}' | '\u{ad}' | '\u{34f}'
    )
}

impl TextState {
    fn tag(&mut self, tag: &Tag) {
        let name: &str = &tag.name;
        let start = tag.kind == TagKind::StartTag;
        if !VOID_TAGS.contains(&name) && allowed_tag(name).is_some() {
            if self.hidden > 0 {
                if start {
                    self.hidden += 1;
                } else {
                    self.hidden -= 1;
                }
                return;
            }
            if start && is_hidden(tag) {
                self.hidden = 1;
                return;
            }
        } else if self.hidden > 0 || (start && is_hidden(tag)) {
            return;
        }
        match (name, start) {
            ("br", true) => self.hard_newline(),
            ("hr", true) => {
                self.want(1);
                self.put_str("———");
                self.want(1);
            }
            ("img", true) => {
                if let Some(alt) = attr(tag, "alt").map(str::trim).filter(|a| !a.is_empty()) {
                    let alt = alt.split_whitespace().collect::<Vec<_>>().join(" ");
                    self.inline_space();
                    self.put_str(&format!("[{alt}]"));
                }
            }
            ("p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "table", _) => {
                self.want(2);
                if name == "table" {
                    if start {
                        self.cells.push(0);
                    } else {
                        self.cells.pop();
                    }
                }
            }
            ("pre", true) => {
                self.want(2);
                self.pre += 1;
            }
            ("pre", false) => {
                self.pre = self.pre.saturating_sub(1);
                self.want(2);
            }
            ("blockquote", true) => {
                self.want(2);
                self.quote += 1;
            }
            ("blockquote", false) => {
                self.quote = self.quote.saturating_sub(1);
                self.want(2);
            }
            ("ul" | "ol", true) => {
                self.want(if self.lists.is_empty() { 2 } else { 1 });
                self.lists.push(if name == "ol" {
                    Some(attr(tag, "start").and_then(number).map_or(1, u64::from))
                } else {
                    None
                });
            }
            ("ul" | "ol", false) => {
                self.lists.pop();
                self.want(if self.lists.is_empty() { 2 } else { 1 });
            }
            ("li", true) => {
                self.want(1);
                let indent = "  ".repeat(self.lists.len().saturating_sub(1));
                let marker = match self.lists.last_mut() {
                    Some(Some(n)) => {
                        let m = format!("{n}. ");
                        *n += 1;
                        m
                    }
                    _ => "• ".to_owned(),
                };
                self.put_str(&format!("{indent}{marker}"));
                self.space = false;
            }
            ("li" | "div" | "thead" | "tbody" | "tfoot", _) => self.want(1),
            ("tr", _) => {
                self.want(1);
                if let Some(c) = self.cells.last_mut() {
                    *c = 0;
                }
            }
            ("td" | "th", true) => {
                if let Some(c) = self.cells.last_mut() {
                    if *c > 0 {
                        self.sep = true;
                        self.space = false;
                    }
                    *c += 1;
                }
            }
            ("a", true) => {
                let href = attr(tag, "href").and_then(link_href);
                self.links.push(href.map(|h| (h, self.out.len())));
            }
            ("a", false) => {
                if let Some(Some((href, from))) = self.links.pop() {
                    let text = self.out.get(from..).unwrap_or("").trim().to_owned();
                    if !text.is_empty() && !same_target(&text, &href) {
                        let shown = href.strip_prefix("mailto:").unwrap_or(&href).to_owned();
                        if self.nl == 0 {
                            self.out.push_str(" <");
                            self.out.push_str(&shown);
                            self.out.push('>');
                        } else {
                            self.put_str(&format!("<{shown}>"));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn text(&mut self, s: &str) {
        for c in s.chars() {
            if invisible(c) {
                continue;
            }
            if self.pre > 0 {
                match c {
                    '\n' => self.hard_newline(),
                    '\u{a0}' => self.put(' '),
                    _ => self.put(c),
                }
            } else if c.is_whitespace() {
                self.space = true;
            } else {
                self.inline_space();
                self.put(c);
            }
        }
    }

    /// Writes an owed collapsed space if we are mid-line.
    fn inline_space(&mut self) {
        if self.space && self.breaks == 0 && self.nl == 0 && !self.sep && !self.out.is_empty() {
            self.out.push(' ');
        }
        self.space = false;
    }

    fn want(&mut self, breaks: usize) {
        if self.breaks == 0 || self.quote < self.break_quote {
            self.break_quote = self.quote;
        }
        self.breaks = self.breaks.max(breaks);
        self.space = false;
    }

    fn flush(&mut self) {
        if self.out.is_empty() {
            self.breaks = 0;
            self.sep = false;
        } else if self.breaks > 0 {
            while self.nl < self.breaks {
                if self.nl >= 1 && self.break_quote > 0 {
                    self.out.push_str(&">".repeat(self.break_quote));
                }
                self.out.push('\n');
                self.nl += 1;
            }
            self.breaks = 0;
            self.sep = false;
        } else if self.sep {
            self.out.push('\t');
            self.sep = false;
        }
        if (self.nl > 0 || self.out.is_empty()) && self.quote > 0 {
            self.out.push_str(&">".repeat(self.quote));
            self.out.push(' ');
        }
    }

    fn put(&mut self, c: char) {
        // the one choke point for the text output: alt texts, markers and URLs come through
        // here too, and none of them may carry a control character (see `is_control`)
        if is_control(c) || c == '\r' {
            return;
        }
        self.flush();
        self.out.push(c);
        self.nl = 0;
    }

    fn put_str(&mut self, s: &str) {
        for c in s.chars() {
            self.put(c);
        }
    }

    fn hard_newline(&mut self) {
        if self.out.is_empty() {
            return;
        }
        if self.breaks > 0 {
            self.flush();
        }
        if self.nl >= 1 && self.quote > 0 {
            self.out.push_str(&">".repeat(self.quote));
        }
        self.out.push('\n');
        self.nl += 1;
        self.space = false;
        self.sep = false;
    }
}

/// The link text already says where the link goes (`https://x.example/` vs `x.example`).
fn same_target(text: &str, href: &str) -> bool {
    let norm = |s: &str| {
        let s = s.trim().to_ascii_lowercase();
        let s = ["mailto:", "https://", "http://"]
            .iter()
            .find_map(|p| s.strip_prefix(p).map(str::to_owned))
            .unwrap_or(s);
        s.trim_end_matches('/').to_owned()
    };
    norm(text) == norm(href)
}

// ---- output audit -------------------------------------------------------------------------

/// Re-tokenizes `html` (an output of [`sanitize`]) and reports the first thing outside the
/// allow-list: a tag, an attribute, a URL scheme, a comment or doctype, unbalanced tags. Used
/// by the tests and the `html_sanitize` fuzz target as an oracle; `Ok` for every output of
/// [`sanitize`].
#[doc(hidden)]
pub fn audit_safe_html(html: &str) -> Result<(), String> {
    let sink = tokenize(html, Audit::default());
    let st = sink.st.into_inner();
    if let Some(e) = st.error {
        return Err(e);
    }
    if !st.open.is_empty() {
        return Err(format!("unclosed elements {:?}", st.open));
    }
    Ok(())
}

#[derive(Default)]
struct Audit {
    st: RefCell<AuditState>,
}

#[derive(Default)]
struct AuditState {
    open: Vec<String>,
    error: Option<String>,
}

impl TokenSink for Audit {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<()> {
        let mut st = self.st.borrow_mut();
        if st.error.is_some() {
            return TokenSinkResult::Continue;
        }
        let err = match token {
            Token::TagToken(tag) => audit_tag(&mut st.open, &tag),
            Token::CommentToken(_) => Some("comment".to_owned()),
            Token::DoctypeToken(_) => Some("doctype".to_owned()),
            Token::NullCharacterToken => Some("NUL".to_owned()),
            _ => None,
        };
        st.error = err;
        TokenSinkResult::Continue
    }
}

fn audit_tag(open: &mut Vec<String>, tag: &Tag) -> Option<String> {
    let name: &str = &tag.name;
    let Some(name) = allowed_tag(name) else {
        return Some(format!("tag <{name}>"));
    };
    let void = VOID_TAGS.contains(&name);
    if tag.kind == TagKind::EndTag {
        if void {
            return Some(format!("end tag </{name}>"));
        }
        return match open.pop() {
            Some(o) if o == name => None,
            other => Some(format!("</{name}> closes {other:?}")),
        };
    }
    if tag.self_closing {
        return Some(format!("self-closing <{name}/>"));
    }
    let placeholder = name == "span" && attr(tag, "class") == Some(BLOCKED_IMAGE_CLASS);
    for a in &tag.attrs {
        let key: &str = &a.name.local;
        let value: &str = &a.value;
        let ok = match key {
            "class" | "data-src" if placeholder => {
                key == "class" || image_src(value).is_some_and(|s| s == value && is_remote(&s))
            }
            "class" | "data-src" => false,
            "rel" => name == "a" && value == LINK_REL,
            "style" | "hidden" => false,
            "href" => name == "a" && link_href(value).is_some_and(|s| s == value),
            "src" => name == "img" && image_src(value).is_some_and(|s| s == value),
            _ => {
                tag_allows(name, key)
                    && filter_attribute(name, key, value).is_some_and(|v| v == value)
            }
        };
        if !ok {
            return Some(format!("attribute {key}={value:?} on <{name}>"));
        }
    }
    match name {
        "a" if attr(tag, "href").is_none() || attr(tag, "rel").is_none() => {
            return Some("link without href/rel".to_owned());
        }
        "img" if attr(tag, "src").is_none() => return Some("image without src".to_owned()),
        "span" if attr(tag, "class").is_some() && attr(tag, "data-src").is_none() => {
            return Some("placeholder without data-src".to_owned());
        }
        _ => {}
    }
    if !void {
        open.push(name.to_owned());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use RemoteContent::{Allowed, Blocked};

    fn clean(html: &str) -> String {
        sanitize(html, Blocked).html
    }

    /// Substrings that must never survive sanitizing (lower-cased output). The vectors below
    /// are built so that none of these can legitimately appear in their visible text.
    const FORBIDDEN: &[&str] = &[
        "<script",
        "</script",
        "javascript:",
        "vbscript:",
        "onerror",
        "onload",
        "onclick",
        "onmouseover",
        "onfocus",
        "<iframe",
        "<object",
        "<embed",
        "<svg",
        "<math",
        "<form",
        "<input",
        "<button",
        "<textarea",
        "<select",
        "<base",
        "<meta",
        "<link",
        "<style",
        "style=",
        "expression(",
        "url(",
        "data:text",
        "data:image/svg",
        "<video",
        "<audio",
        "<source",
        "poster=",
        "srcset",
        "background=",
        "target=",
        "<noscript",
        "<template",
        "<xmp",
        "<!--",
        "ping=",
        "formaction",
        "<frame",
        "<applet",
        "<marquee",
        "<title",
        "http-equiv",
        "id=",
        "name=",
        "class=\"x",
    ];

    /// Sanitizes `input` both ways, checks the result with the output auditor and the
    /// forbidden-substring list, and returns the blocked rendering.
    fn assert_safe(input: &str) -> String {
        for remote in [Blocked, Allowed] {
            let out = sanitize(input, remote).html;
            if let Err(e) = audit_safe_html(&out) {
                panic!("{input:?} ({remote:?}) -> {out:?}: {e}");
            }
            let lower = out.to_ascii_lowercase();
            for bad in FORBIDDEN {
                assert!(
                    !lower.contains(bad),
                    "{input:?} ({remote:?}) -> {out:?} still contains {bad:?}"
                );
            }
        }
        clean(input)
    }

    // ---- the XSS corpus ---------------------------------------------------------------

    #[test]
    fn xss_script_elements_go_with_their_content() {
        for v in [
            "<script>alert(1)</script>hello",
            "<SCRIPT SRC=//evil.example/x.js></SCRIPT>hello",
            "<script\n>alert(1)</script\n>hello",
            "<svg><script>alert(1)</script></svg>hello",
            "<template><script>alert(1)</script></template>hello",
        ] {
            let out = assert_safe(v);
            assert!(!out.contains("alert(1)"), "{v:?} -> {out:?}");
            assert!(out.contains("hello"), "{v:?} -> {out:?}");
        }
        // `<scr<script>` is one start tag named "scr<script" (HTML allows `<` in tag names), so
        // what follows is text, not script: it stays visible and escaped
        let out = assert_safe("<scr<script>ipt>alert(1)</script>hello");
        assert_eq!(out, "ipt&gt;alert(1)hello");
    }

    #[test]
    fn xss_javascript_hrefs_in_every_spelling_are_dropped() {
        for v in [
            "<a href=\"javascript:alert(1)\">x</a>",
            "<a href=\"java\tscript:alert(1)\">x</a>",
            "<a href=\"java\nscript:alert(1)\">x</a>",
            "<a href=\"&#106;avascript:alert(1)\">x</a>",
            "<a href=\"&#x6A;&#x61;&#x76;&#x61;script:alert(1)\">x</a>",
            "<a href=\"jav&#x61;script:alert(1)\">x</a>",
            "<a href=\" JaVaScRiPt:alert(1)\">x</a>",
            "<a href=\"javascript&colon;alert(1)\">x</a>",
            "<a href=\"&#0000106&#0000097vascript:alert(1)\">x</a>",
            "<a href=\"\x01javascript:alert(1)\">x</a>",
            "<a href=\"vbscript:msgbox(1)\">x</a>",
            "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">x</a>",
            "<a href=\"cid:part1@example.com\">x</a>",
            "<a href=\"file:///etc/passwd\">x</a>",
            "<a href=\"//evil.example/path\">x</a>",
            "<a href=\"/relative\">x</a>",
        ] {
            let out = assert_safe(v);
            // the link has no usable target, so it is unwrapped: only its text is left
            assert_eq!(out, "x", "{v:?}");
        }
    }

    #[test]
    fn xss_event_handlers_are_dropped_everywhere() {
        for v in [
            "<img src=x onerror=alert(1)>",
            "<img src=\"cid:a@b\" onerror=\"alert(1)\" onload=alert(2)>",
            "<body onload=alert(1)>t</body>",
            "<div onclick=\"alert(1)\" onmouseover=alert(2)>t</div>",
            "<p ONCLICK=alert(1)>t</p>",
            "<a href=\"https://example.com/\" onfocus=alert(1) autofocus>t</a>",
            "<svg onload=alert(1)><circle r=1 /></svg>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>t</details>",
        ] {
            assert_safe(v);
        }
    }

    #[test]
    fn xss_dangerous_elements_are_gone() {
        for v in [
            "<base href=\"https://evil.example/\">t",
            "<meta http-equiv=\"refresh\" content=\"0;url=https://evil.example/\">t",
            "<form action=\"https://evil.example/steal\"><input name=pw type=password>\
             <button formaction=\"https://evil.example/\">Go</button></form>t",
            "<iframe src=\"https://evil.example/\"></iframe>t",
            "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>t",
            "<object data=\"https://evil.example/x.swf\"></object><embed src=x.swf>t",
            "<applet code=x></applet>t",
            "<link rel=stylesheet href=\"https://evil.example/x.css\">t",
            "<video poster=\"https://evil.example/p.png\" src=x></video><audio src=x>t",
            "<video><source src=\"https://evil.example/v.mp4\"></video>t",
            "<frameset><frame src=\"https://evil.example/\"></frameset>t",
            "<textarea>t</textarea><select><option>o</option></select>t",
            "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\"></noscript>t",
            "<xmp><script>alert(1)</script></xmp>t",
            "<title>phish</title>t",
            "<marquee>m</marquee>t",
        ] {
            assert_safe(v);
        }
    }

    #[test]
    fn control_characters_never_reach_either_output() {
        // the CLI prints html_to_text to a terminal: ESC sequences must not survive
        let input = "<p>clear:\u{1b}[2J title:\u{1b}]0;owned\u{7}\u{0}\u{8}\u{7f}\u{9b}2J</p>\
                     <a href=\"https://x.example/\" title=\"\u{1b}[31m\">l\u{1b}[0mink</a>\
                     <pre>keep\ttab\nand newline\u{1b}[1m</pre>";
        let out = assert_safe(input);
        let text = html_to_text(input);
        for s in [out.as_str(), text.as_str()] {
            assert!(
                !s.contains(|c: char| c.is_control() && !matches!(c, '\t' | '\n')),
                "control character left in {s:?}"
            );
        }
        assert!(text.contains("clear:[2J title:]0;owned2J"), "{text:?}");
        // …including attribute values that become text, such as an image's alt
        let alt = html_to_text("<img src=\"cid:a@b\" alt=\"a\u{1b}[31mb\u{1d}c\">");
        assert_eq!(alt, "[a[31mbc]", "the ESC is gone, the rest is inert text");
        assert!(text.contains("keep\ttab\nand newline"), "{text:?}");
    }

    #[test]
    fn xss_css_is_stripped_with_style_attributes_and_blocks() {
        for v in [
            "<div style=\"background:url(javascript:alert(1))\">t</div>",
            "<div style=\"width: expression(alert(1))\">t</div>",
            "<p style=\"background-image: url('https://tracker.example/p.png')\">t</p>",
            "<style>@import 'https://evil.example/x.css'; p{background:url(https://evil.example/t.png)}</style>t",
            "<table background=\"https://evil.example/bg.png\"><tr><td background=\"x\">t</td></tr></table>",
        ] {
            let out = assert_safe(v);
            assert!(out.contains('t'), "{v:?} -> {out:?}");
        }
    }

    /// For vectors whose attack text legitimately ends up as escaped text or as an escaped
    /// attribute value: the auditor (structure) only, not the substring list.
    fn assert_audited(input: &str) -> String {
        for remote in [Blocked, Allowed] {
            let out = sanitize(input, remote).html;
            if let Err(e) = audit_safe_html(&out) {
                panic!("{input:?} ({remote:?}) -> {out:?}: {e}");
            }
        }
        clean(input)
    }

    #[test]
    fn xss_attribute_values_cannot_break_out() {
        assert_eq!(
            assert_audited("<p title=\"<img src=x onerror=alert(1)>\">t</p>"),
            "<p title=\"&lt;img src=x onerror=alert(1)&gt;\">t</p>"
        );
        assert_eq!(
            assert_audited("<p title='a\" onclick=\"alert(1)'>t</p>"),
            "<p title=\"a&quot; onclick=&quot;alert(1)\">t</p>"
        );
        assert_eq!(
            assert_audited("<img src=\"cid:a@b\" alt=\"&quot;><script>alert(1)</script>\">"),
            "<img src=\"cid:a@b\" alt=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\">"
        );
        assert_eq!(
            assert_audited("<a href=\"https://example.com/?q=&quot;&gt;&lt;script&gt;\">t</a>"),
            "<a href=\"https://example.com/?q=%22%3E%3Cscript%3E\" rel=\"noopener noreferrer nofollow\">t</a>"
        );
        for v in [
            "\"><script>alert(1)</script>",
            "<!--<img src=x onerror=alert(1)>-->t",
            "<![CDATA[<script>alert(1)</script>]]>t",
            "<?xml version=\"1.0\"?><p>t</p>",
            "<!DOCTYPE html><p>t</p>",
        ] {
            assert_safe(v);
        }
        // the alt text survives, escaped
        let out = clean("<img src=\"cid:a@b\" alt=\"&quot;><b>x\">");
        assert!(out.contains("alt=\"&quot;&gt;&lt;b&gt;x\""), "{out}");
    }

    #[test]
    fn links_keep_safe_targets_with_a_fixed_rel_and_no_target() {
        let out = assert_safe(
            "<a href=\"https://example.com/a?b=1&amp;c=2\" target=\"_blank\" rel=\"opener\" \
             ping=\"https://tracker.example/\">site</a>",
        );
        assert_eq!(
            out,
            "<a href=\"https://example.com/a?b=1&amp;c=2\" rel=\"noopener noreferrer nofollow\">site</a>"
        );
        let out = assert_safe("<a href=\"mailto:bob@example.com?subject=Hi\">Bob</a>");
        assert_eq!(
            out,
            "<a href=\"mailto:bob@example.com?subject=Hi\" rel=\"noopener noreferrer nofollow\">Bob</a>"
        );
        // normalised: punycode host, credentials stripped (no "bank.com@evil" disguise)
        let out = clean("<a href=\"https://bank.example@evil.example/login\">bank</a>");
        assert!(out.contains("href=\"https://evil.example/login\""), "{out}");
        let out = clean("<a href=\"https://bücher.example/\">b</a>");
        assert!(
            out.contains("href=\"https://xn--bcher-kva.example/\""),
            "{out}"
        );
        let out = clean("<a href=\"HTTPS://EXAMPLE.com\">x</a>");
        assert!(out.contains("href=\"https://example.com/\""), "{out}");
    }

    #[test]
    fn images_cid_and_data_kept_svg_and_other_data_dropped() {
        let out = assert_safe(
            "<img src=\"cid:logo@example.com\" alt=\"Logo\" width=\"40\" height=\"20\">",
        );
        assert_eq!(
            out,
            "<img src=\"cid:logo@example.com\" alt=\"Logo\" width=\"40\" height=\"20\">"
        );
        let png = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
        let out = assert_safe(&format!("<img src=\"{png}\">"));
        assert_eq!(out, format!("<img src=\"{png}\">"));
        assert_eq!(
            sanitize(&format!("<img src=\"{png}\">"), Blocked).remote_images,
            0
        );
        for v in [
            "<img src=\"data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+\">t",
            "<img src=\"data:text/html,<script>alert(1)</script>\">t",
            "<img src=\"data:image/png,notbase64\">t",
            "<img src=\"data:image/png;base64,<script>\">t",
            "<img src=\"javascript:alert(1)\">t",
            "<img src=\"relative.png\">t",
            "<img src=\"//cdn.example/x.png\">t",
            "<img>t",
            "<image src=\"javascript:alert(1)\">t",
        ] {
            assert_eq!(assert_safe(v), "t", "{v:?}");
        }
    }

    #[test]
    fn remote_images_are_counted_blocked_and_allowed() {
        let input = "<p>Hi<img src=\"https://tracker.example/a.png\" alt=\"A\">\
                     <img src=\"HTTP://Example.COM/b.gif\"></p>\
                     <img src=\"cid:c@d\"><img srcset=\"https://evil.example/x.png 2x\" src=\"cid:e@f\">";
        let blocked = sanitize(input, Blocked);
        assert_eq!(blocked.remote_images, 2);
        assert!(
            !blocked.html.contains("<img src=\"http"),
            "{}",
            blocked.html
        );
        assert!(
            blocked.html.contains(
                "<span class=\"sealbox-blocked-image\" data-src=\"https://tracker.example/a.png\"></span>"
            ),
            "{}",
            blocked.html
        );
        assert!(
            blocked
                .html
                .contains("data-src=\"http://example.com/b.gif\""),
            "{}",
            blocked.html
        );
        assert!(
            blocked.html.contains("<img src=\"cid:c@d\">"),
            "{}",
            blocked.html
        );
        audit_safe_html(&blocked.html).expect("audit");

        let allowed = sanitize(input, Allowed);
        assert_eq!(allowed.remote_images, 2);
        assert!(
            allowed
                .html
                .contains("<img src=\"https://tracker.example/a.png\" alt=\"A\">"),
            "{}",
            allowed.html
        );
        assert!(
            !allowed.html.contains("sealbox-blocked-image"),
            "{}",
            allowed.html
        );
        audit_safe_html(&allowed.html).expect("audit");
    }

    #[test]
    fn tracking_pixels_and_hidden_elements_are_dropped_and_not_counted() {
        let out = sanitize(
            "<p>a</p><img src=\"https://t.example/o.gif\" width=\"1\" height=\"1\">\
             <img src=\"https://t.example/z.gif\" width=0 height=0>\
             <div style=\"display:none;max-height:0\">preheader <img src=\"https://t.example/h.png\"></div>\
             <span hidden>secret</span><div style=\"color: red; DISPLAY : None !important\">x</div><p>b</p>",
            Blocked,
        );
        assert_eq!(out.remote_images, 0, "{}", out.html);
        assert_eq!(out.html, "<p>a</p><p>b</p>");
    }

    #[test]
    fn a_placeholder_on_input_is_just_another_remote_image() {
        // the pair survives and counts, so sanitizing an output again is a no-op …
        let forged =
            "<span class=\"sealbox-blocked-image\" data-src=\"https://x.example/a.png\"></span>";
        let out = sanitize(forged, Blocked);
        assert_eq!(out.html, forged);
        assert_eq!(out.remote_images, 1);
        assert_eq!(sanitize(forged, Allowed).remote_images, 1);
        audit_safe_html(&out.html).expect("audit");
        // … but neither attribute survives alone, on another tag, or with an unusable target
        for v in [
            "<span class=\"sealbox-blocked-image\">t</span>",
            "<span data-src=\"https://x.example/a.png\">t</span>",
            "<span class=\"other\" data-src=\"https://x.example/a.png\">t</span>",
            "<span class=\"sealbox-blocked-image\" data-src=\"javascript:alert(1)\">t</span>",
            "<span class=\"sealbox-blocked-image\" data-src=\"cid:a@b\">t</span>",
            "<p class=\"sealbox-blocked-image\" data-src=\"https://x.example/a.png\">t</p>",
        ] {
            let out = sanitize(v, Blocked);
            assert_eq!(out.remote_images, 0, "{v:?} -> {:?}", out.html);
            assert!(!out.html.contains("data-src"), "{v:?} -> {:?}", out.html);
            assert!(!out.html.contains("class"), "{v:?} -> {:?}", out.html);
            audit_safe_html(&out.html).expect("audit");
        }
    }

    #[test]
    fn formatting_and_tables_survive() {
        let input = "<h1>T</h1><p dir=\"rtl\" align=\"center\" lang=\"he\" title=\"t\">p <b>b</b> \
                     <strong>s</strong> <i>i</i> <em>e</em> <u>u</u> <s>x</s> <small>m</small> \
                     H<sub>2</sub>O x<sup>2</sup> <code>c</code></p><pre>  a\n  b</pre>\
                     <blockquote>q</blockquote><ul><li>1</li></ul><ol start=\"3\"><li>3</li></ol><hr>\
                     <table><thead><tr><th colspan=\"2\">h</th></tr></thead><tbody><tr>\
                     <td rowspan=\"1\" valign=\"top\">a</td><td>b</td></tr></tbody><tfoot><tr><td>f</td></tr></tfoot></table>\
                     <div><span>s</span><br></div>";
        let out = assert_safe(input);
        assert_eq!(
            out, input,
            "every allowed tag and attribute survives unchanged"
        );
    }

    #[test]
    fn unknown_tags_are_unwrapped_and_attribute_values_validated() {
        assert_eq!(
            clean("<font color=red face=x><center>c</center></font><custom-el>k</custom-el>"),
            "ck"
        );
        assert_eq!(
            clean("<p align=\"javascript\" dir=\"sideways\" lang=\"&quot;x\">t</p>"),
            "<p>t</p>"
        );
        assert_eq!(
            clean("<td colspan=\"100000\">x</td>"),
            "x",
            "a td outside a table is not a cell"
        );
        assert_eq!(
            clean("<table><tr><td colspan=\"100000\" rowspan=\"-3\">x</td></tr></table>"),
            "<table><tbody><tr><td colspan=\"100\">x</td></tr></tbody></table>"
        );
        assert_eq!(
            clean("<img src=\"cid:a@b\" width=\"100%\" height=\"12px\">"),
            "<img src=\"cid:a@b\" width=\"100%\">"
        );
    }

    #[test]
    fn malformed_and_truncated_html_is_closed_and_safe() {
        for v in [
            "<p>unclosed <b>bold <a href=\"https://x.example/",
            "<p>unclosed <b>bold <a href=\"https://x.example/\">link",
            "<table><tr><td>a<td>b<tr><td>c",
            "</div></p></b>text</table>",
            "<b><i>mis</b>nested</i>",
            "<<<>>><p<<>>",
            "<a href=\"https://a.example/\"><a href=\"https://b.example/\">nested</a></a>",
            "<p>\u{0}nul\u{0}</p>",
            "<img src=\"cid:x\" alt=\"\u{0}\">",
            "&#0;&#xD800;&#x110000;&amp;&lt;&gt;&notanentity;",
            "<p",
            "<",
            "",
        ] {
            assert_safe(v);
        }
        assert_eq!(clean("<b>a<i>b</b>c</i>"), "<b>a<i>b</i></b><i>c</i>");
    }

    #[test]
    fn nested_tables_and_deep_nesting_do_not_overflow() {
        let nested = "<table><tr><td>".repeat(200) + "core" + &"</td></tr></table>".repeat(200);
        let out = assert_safe(&nested);
        assert!(out.contains("core"));
        let deep = "<div>".repeat(50_000) + "deep";
        let out = sanitize(&deep, Blocked).html;
        assert!(out.starts_with("<div><div>"));
        assert!(out.contains(&("deep".to_string() + &"</div>".repeat(10))));
        assert_eq!(
            out.matches("</div>").count(),
            MAX_DEPTH,
            "nesting is capped, text kept"
        );
        audit_safe_html(&out).expect("audit");
        let text = html_to_text(&deep);
        assert_eq!(text, "deep");
    }

    #[test]
    fn sanitizing_converges_where_one_round_would_not() {
        // unwrapping the <font> leaves <h1> inside <h1>; a re-parse splits those into siblings,
        // so one round would hand a renderer a tree it does not reproduce (the mXSS shape)
        let input = "<h1>a<font><h1>b</h1></font></h1>";
        assert_eq!(sanitize_once(input, Blocked).html, "<h1>a<h1>b</h1></h1>");
        let out = sanitize(input, Blocked);
        assert_eq!(out.html, "<h1>a</h1><h1>b</h1>");
        assert_eq!(sanitize(&out.html, Blocked).html, out.html);
        // the count survives the extra round (a placeholder counts like the image it replaced)
        let out = sanitize(
            "<h1><img src=\"https://a.example/x.png\"><font><h1>\
             <img src=\"https://b.example/y.png\"></h1></font></h1>",
            Blocked,
        );
        assert_eq!(out.remote_images, 2);
        assert_eq!(sanitize(&out.html, Blocked), out);
    }

    #[test]
    fn sanitizing_twice_changes_nothing() {
        let corpus = [
            "<p>Hello <b>world</b> <a href=\"https://example.com/\">link</a></p>",
            "<table><tr><td>a<td>b</table><ul><li>x<li>y</ul>",
            "<b>a<i>b</b>c</i>",
            "<pre>\n\nx</pre>",
            "<img src=\"https://x.example/a.png\" alt=\"a\"><img src=\"cid:b\">",
            "<a href=\"https://a.example/\"><table><tr><td><a href=\"https://b.example/\">x</a></td></tr></table></a>",
            "<p title=\"&lt;&gt;&amp;&quot;\">&lt;tag&gt; &amp;amp; \u{a0}</p>",
        ];
        for v in corpus {
            for remote in [Blocked, Allowed] {
                let once = sanitize(v, remote);
                let twice = sanitize(&once.html, remote);
                assert_eq!(once.html, twice.html, "{v:?} ({remote:?})");
                assert_eq!(
                    once.remote_images, twice.remote_images,
                    "{v:?} ({remote:?})"
                );
            }
        }
    }

    #[test]
    fn html_documents_are_told_apart_from_plain_text() {
        for html in [
            "<html><body><p>hi</p></body></html>",
            "<div style=\"x\">hello</div>",
            "<table><tr><td>a</td></tr></table>",
            "<p>one</p><p>two</p>",
            "<!DOCTYPE html>\n<p>t</p>",
            "<span>s</span>",
            "Dear customer,<br>your invoice is ready.",
            "<a href=\"https://e.example/\">link</a>",
        ] {
            assert!(looks_like_html_document(html), "{html:?}");
        }
        for text in [
            "",
            "Just a plain text mail.\n\nRegards,\nBob",
            "a < b and b > a",
            "Vec::<u8>::new() returns an empty vector",
            "the generic is Option<T>, see <https://doc.rust-lang.org/>",
            "diff: <<<<<<< HEAD",
            "5<6<7",
            "mail me at <bob@example.com>",
            "<notatag>",
        ] {
            assert!(!looks_like_html_document(text), "{text:?}");
        }
    }

    // ---- the structure clamp (a cost limit, see clamp_structure) ------------------------

    #[test]
    fn the_clamp_leaves_ordinary_mail_untouched() {
        for v in [
            "<p>Hello <b>world</b></p>",
            "<table><tr><td><a href=\"https://e.example/\">x</a></td></tr></table>",
            "<div><div><div>nested but shallow</div></div></div>",
            "<img src=\"cid:a@b\"><br><hr>",
            "<style>p{color:red}</style><p>t</p>",
            "<!-- c --><!DOCTYPE html><p>t</p>",
            "<b>a<i>b</b>c</i>",
            "text with < and <3 and a<b",
            "",
        ] {
            assert!(
                matches!(clamp_structure(v), Cow::Borrowed(_)),
                "{v:?} was rewritten: {:?}",
                clamp_structure(v)
            );
        }
    }

    #[test]
    fn the_clamp_caps_depth_drops_stray_end_tags_and_attribute_floods() {
        // beyond MAX_DEPTH the tags go, the content stays
        let deep = "<div>".repeat(MAX_DEPTH + 10) + "x";
        let clamped = clamp_structure(&deep);
        assert_eq!(clamped.matches("<div>").count(), MAX_DEPTH);
        assert!(clamped.ends_with('x'));
        // an unmatched end tag is still copied (the parser recovers, and the cap bounds its cost)
        assert!(matches!(
            clamp_structure("</x></div>a<p>b</p>"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            clamp_structure("<b><i>x</b></i>"),
            Cow::Borrowed(_)
        ));
        // …but it does not keep a level open, so a flood of them still hits the cap
        let drift = "<div></span>".repeat(MAX_DEPTH + 10) + "x";
        assert_eq!(clamp_structure(&drift).matches("<div>").count(), MAX_DEPTH);
        // attribute floods lose every attribute (the tag and its content stay)
        let flood: String = (0..MAX_ATTRS + 5).map(|i| format!("a{i}=1 ")).collect();
        assert_eq!(clamp_structure(&format!("<p {flood}>t</p>")), "<p>t</p>");
        let kept = format!(
            "<p {}>t</p>",
            (0..MAX_ATTRS)
                .map(|i| format!("a{i}=1 "))
                .collect::<String>()
        );
        assert!(matches!(clamp_structure(&kept), Cow::Borrowed(_)));
        // a value — quoted, bare or with spaces around the `=` — is not an attribute
        assert_eq!(count_attributes(" a=\"1 2 3\" b = 4 c d='e f'"), 4);
        // raw text is copied verbatim: `<b)` inside a script is not a tag, and the `</p>` in a
        // string does not close anything — so nothing in it reaches the depth counter
        let script = "<script>if (a<b) x=\"</p>\"</script>".repeat(MAX_DEPTH);
        assert!(matches!(clamp_structure(&script), Cow::Borrowed(_)));
        assert!(matches!(
            clamp_structure("<style>p{content:\"<div>\"}</style><p>t</p>"),
            Cow::Borrowed(_)
        ));
        // an unterminated tag ends the scan; the text is kept
        assert_eq!(
            clamp_structure("<p>a<b attr=\"unterminated"),
            "<p>a<b attr=\"unterminated"
        );
    }

    #[test]
    fn the_clamp_never_makes_output_unsafe() {
        // the clamp is a cost limit: these go through the full sanitizer afterwards
        for v in [
            &("<div>".repeat(MAX_DEPTH + 5) + "<script>alert(1)</script>x"),
            &format!(
                "<img {} src=\"cid:a@b\">",
                (0..MAX_ATTRS + 2)
                    .map(|i| format!("onx{i}=alert(1) "))
                    .collect::<String>()
            ),
            &("</script>".repeat(3) + "<svg onload=alert(1)>"),
            &("<table><tr><td>".repeat(MAX_DEPTH) + "<a href=javascript:alert(1)>x</a>"),
        ] {
            assert_safe(v);
        }
    }

    // ---- bounded time ------------------------------------------------------------------

    fn timed(label: &str, input: &str) -> Duration {
        let t = Instant::now();
        let out = sanitize(input, Blocked);
        let text = html_to_text(input);
        let d = t.elapsed();
        audit_safe_html(&out.html).unwrap_or_else(|e| panic!("{label}: {e}"));
        eprintln!(
            "{label}: {} KiB in -> {} KiB html, {} KiB text, {} remote, {d:?}",
            input.len() / 1024,
            out.html.len() / 1024,
            text.len() / 1024,
            out.remote_images
        );
        d
    }

    #[test]
    fn a_one_megabyte_mail_is_sanitized_in_under_two_seconds() {
        const MB: usize = 1 << 20;
        let cell = "<tr><td style=\"padding:4px\"><a href=\"https://example.com/item?id=12345\">\
                    Item</a> &amp; <b>bold</b> text <img src=\"https://cdn.example/i.png\" alt=\"i\"></td></tr>";
        let newsletter = format!(
            "<html><head><style>p{{color:red}}</style></head><body><table>{}</table></body></html>",
            cell.repeat(MB / cell.len())
        );
        let d = timed("newsletter", &newsletter);
        assert!(d < BUDGET, "1 MiB newsletter took {d:?}, budget {BUDGET:?}");
    }

    /// The budget per 1 MiB input: what the product must hold to (release), with room for the
    /// unoptimised build the gates run.
    const BUDGET: Duration = if cfg!(debug_assertions) {
        Duration::from_secs(20)
    } else {
        Duration::from_secs(2)
    };

    #[test]
    fn adversarial_one_megabyte_inputs_stay_bounded() {
        const MB: usize = 1 << 20;
        let shapes: Vec<(&str, String)> = vec![
            ("many attributes in one tag", {
                let mut s = String::from("<p ");
                let mut i = 0;
                while s.len() < MB {
                    s.push_str(&format!("a{i} "));
                    i += 1;
                }
                s + ">t</p>"
            }),
            (
                "open spans + stray end tags",
                "<span>".repeat(MB / 12) + &"</x>".repeat(MB / 8),
            ),
            (
                "open formatting elements",
                "<b a=1><i a=2><u a=3>".repeat(MB / 24) + "t",
            ),
            ("misnested formatting", "<b><i>x</b></i>".repeat(MB / 16)),
            ("nested tables", "<table><tr><td>".repeat(MB / 16)),
            (
                "unclosed anchors",
                "<a href=\"https://a.example/\">x".repeat(MB / 32),
            ),
            ("deep divs", "<div>".repeat(MB / 5)),
            ("foster parenting", "<table>x".repeat(MB / 8)),
            (
                "one huge data image",
                format!("<img src=\"data:image/png;base64,{}\">", "A".repeat(MB)),
            ),
            ("one huge text node", "x ".repeat(MB / 2)),
            ("entities", "&amp;&lt;&#x41;&nbsp;".repeat(MB / 20)),
            ("many paragraphs", "<p>p</p>".repeat(MB / 8)),
        ];
        let mut worst = Duration::ZERO;
        for (label, input) in &shapes {
            worst = worst.max(timed(label, input));
        }
        assert!(worst < BUDGET, "worst case {worst:?}, budget {BUDGET:?}");
    }

    // ---- html_to_text ------------------------------------------------------------------

    #[test]
    fn html_to_text_keeps_structure() {
        let html = "<html><head><title>T</title><style>p{color:red}</style></head><body>\
                    <h1>Heading</h1><p>First   paragraph\nwith <b>bold</b> &amp; &lt;angle&gt;&nbsp;text.</p>\
                    <p>Line<br>break</p><ul><li>one</li><li>two<ul><li>nested</li></ul></li></ul>\
                    <ol start=\"3\"><li>three</li><li>four</li></ol>\
                    <p>See <a href=\"https://example.com/x\">the site</a>, \
                    <a href=\"https://example.com/\">https://example.com/</a>, \
                    <a href=\"mailto:bob@example.com\">bob@example.com</a>.</p>\
                    <blockquote><p>quoted</p><p>twice</p></blockquote>\
                    <pre>  keep\n    spacing</pre><hr><table><tr><td>a</td><td>b</td></tr><tr><td>c</td></tr></table>\
                    <img src=\"cid:x\" alt=\"Logo\"><script>alert(1)</script><div style=\"display:none\">hidden</div>\
                    </body></html>";
        let text = html_to_text(html);
        assert_eq!(
            text,
            "Heading\n\nFirst paragraph with bold & <angle> text.\n\nLine\nbreak\n\n\
             • one\n• two\n  • nested\n\n3. three\n4. four\n\n\
             See the site <https://example.com/x>, https://example.com/, bob@example.com.\n\n\
             > quoted\n>\n> twice\n\n  keep\n    spacing\n\n———\n\na\tb\nc\n\n[Logo]"
        );
    }

    #[test]
    fn html_to_text_of_plain_fragments_and_garbage() {
        assert_eq!(html_to_text(""), "");
        assert_eq!(html_to_text("just text"), "just text");
        assert_eq!(
            html_to_text("a&nbsp;&nbsp;b &#x1F600; &unknown; &amp;amp;"),
            "a b 😀 &unknown; &amp;"
        );
        assert_eq!(html_to_text("<p>a</p>\n\n\n<p>b</p>"), "a\n\nb");
        assert_eq!(html_to_text("<div>x</div><div>y</div>"), "x\ny");
        assert_eq!(html_to_text("zero\u{200b}width\u{feff}"), "zerowidth");
        assert_eq!(html_to_text("<a href=\"javascript:alert(1)\">x</a>"), "x");
        assert_eq!(
            html_to_text("<a href=\"https://e.example/\"></a>after"),
            "after"
        );
    }
}
