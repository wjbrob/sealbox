//! Fuzz target `html_sanitize`: the display sanitizer for received HTML mail,
//! `sealbox_mail::html::{sanitize, html_to_text}` — what the UI and the CLI run on the HTML
//! part of every message that arrives over IMAP (`docs/HTML_MAIL.md`, gate G13). The input is
//! attacker-controlled: anyone can send HTML.
//!
//! Beyond "it must not panic" the harness checks the sanitizer's contract on every input:
//!
//! * the output passes `audit_safe_html` — only allow-listed tags, allow-listed attributes with
//!   values the attribute filter accepts, `http(s)`/`mailto` links with the fixed `rel`,
//!   `cid:`/`data:image/*`/remote images only, no comment, doctype or NUL, tags balanced;
//! * sanitizing the output again changes nothing (idempotence), and the second pass counts the
//!   same number of remote images;
//! * `Blocked` leaves no remote image in the output while `Allowed` keeps the same count;
//! * `html_to_text` is clean text: no NUL or other control character beyond newline and tab (the
//!   CLI prints it to a terminal), no blank first line and no trailing whitespace (a `<pre>`
//!   block may legitimately start a line with spaces). There is no sound
//!   forbidden-substring invariant for text: markup *spelled out* in the input (`&lt;p&gt;`)
//!   legitimately decodes to `<p>`, and an image's `alt` can say anything at all — what the
//!   sanitizer itself emits is checked by `audit_safe_html` above.
//!
//! Inputs are read as UTF-8 with the lossy replacement the MIME layer also applies, so every
//! input reaches the parser; the first byte picks the remote-content mode.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sealbox_mail::html::{audit_safe_html, html_to_text, sanitize, RemoteContent};

fuzz_target!(|data: &[u8]| {
    let (mode, payload) = match data.split_first() {
        Some((m, rest)) => (*m, rest),
        None => (0, &[][..]),
    };
    let remote = if mode % 2 == 0 {
        RemoteContent::Blocked
    } else {
        RemoteContent::Allowed
    };
    let input = String::from_utf8_lossy(payload);

    let once = sanitize(&input, remote);
    if let Err(e) = audit_safe_html(&once.html) {
        panic!("sanitize({remote:?}) left {e} in {:?}", once.html);
    }
    if remote == RemoteContent::Blocked {
        assert!(
            !once.html.contains("<img src=\"http"),
            "remote image survived Blocked: {:?}",
            once.html
        );
    }

    // Re-sanitizing output is a no-op, and the remote count does not change under it.
    let twice = sanitize(&once.html, remote);
    assert_eq!(once.html, twice.html, "not idempotent");
    assert_eq!(once.remote_images, twice.remote_images, "count not stable");

    // The other mode sees the same number of remote images (only the rendering differs).
    let other = sanitize(
        &input,
        match remote {
            RemoteContent::Blocked => RemoteContent::Allowed,
            RemoteContent::Allowed => RemoteContent::Blocked,
        },
    );
    assert_eq!(once.remote_images, other.remote_images, "count differs by mode");

    for text in [html_to_text(&input), html_to_text(&once.html)] {
        assert!(
            !text.contains(|c: char| c.is_control() && c != '\n' && c != '\t'),
            "control character in text: {text:?}"
        );
        assert!(
            !text.starts_with('\n') && text.trim_end() == text,
            "text is not trimmed: {text:?}"
        );
    }
});
