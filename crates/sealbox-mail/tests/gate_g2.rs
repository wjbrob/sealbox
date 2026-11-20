//! Gate G2 — PGP/MIME: build `multipart/encrypted` + `multipart/signed` per
//! RFC 3156 with protected headers, parse them back with our parser AND with
//! mail-parser, and fold a 3 KB Autocrypt header correctly.

use mail_parser::{MessageParser, MimeHeaders};
use sealbox_mail::mime::{
    autocrypt_gossip_header_value, autocrypt_header_value, build_pgp_mime_encrypted,
    build_pgp_mime_signed, build_plain, fold_header, parse, parse_autocrypt_header,
    parse_decrypted_inner, prepare_signed_part, render_inner_for_encryption, split_multipart,
    Attachment, InnerOptions, Mailbox, MessageDraft, MessageKind, OuterHeaders,
    PROTECTED_SUBJECT_PLACEHOLDER,
};

const FAKE_CIPHERTEXT: &str = "-----BEGIN PGP MESSAGE-----\n\nwV4DZ2VuZXJhdGVkEhIBCg0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n=abcd\n-----END PGP MESSAGE-----\n";

const FAKE_SIGNATURE: &str = "-----BEGIN PGP SIGNATURE-----\n\niHUEARYKAB0WIQQAAAAAAAAAAAAAAAAAAAAAAAAAAAUCZgAAAAAKCRAAAAAAAAAA\nAAAAAQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAA\n=zzzz\n-----END PGP SIGNATURE-----\n";

fn fake_keydata(len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s: String = (0..len)
        .map(|i| ALPHABET[(i * 7 + i / 13) % ALPHABET.len()] as char)
        .collect();
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    s
}

fn draft() -> MessageDraft {
    let mut d = MessageDraft::new(
        Mailbox::named("Alice Ärmel", "alice@sealbox.test"),
        vec![Mailbox::named("Bob", "bob@sealbox.test")],
        "Sécret subject — do not leak",
        "Hello Bob,\nthis is the body with ümlauts and a long line that goes on and on and on and on and on and on and on and on and on.\n",
    );
    d.cc = vec![Mailbox::new("carol@sealbox.test")];
    d.bcc = vec![Mailbox::new("hidden@sealbox.test")];
    d.in_reply_to = Some("prev@sealbox.test".into());
    d.references = vec!["root@sealbox.test".into(), "prev@sealbox.test".into()];
    d.html_body = Some("<p>Hello <b>Bob</b> — ümlauts too</p>".into());
    d.attachments.push(Attachment::new(
        "notes.txt",
        "text/plain",
        b"attached text\n".to_vec(),
    ));
    d.attachments.push(Attachment::new(
        "blob.bin",
        "application/octet-stream",
        (0u8..=255).collect(),
    ));
    d.extra_headers.push((
        "Autocrypt".into(),
        autocrypt_header_value("alice@sealbox.test", true, &fake_keydata(3000)),
    ));
    d
}

fn lf(s: &str) -> String {
    s.replace("\r\n", "\n")
}

fn assert_wire_format(raw: &[u8]) {
    let text = std::str::from_utf8(raw).expect("message is UTF-8");
    for (i, line) in text.split_inclusive('\n').enumerate() {
        assert!(
            line.ends_with("\r\n") || !line.ends_with('\n'),
            "line {i} is not CRLF terminated: {line:?}"
        );
        let body = line.trim_end_matches(['\r', '\n']);
        assert!(
            body.len() <= 998,
            "line {i} exceeds 998 octets ({})",
            body.len()
        );
        assert!(
            !body.ends_with(' ') && !body.ends_with('\t'),
            "line {i} has trailing whitespace: {body:?}"
        );
    }
}

fn header_lines(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let head = text.split("\r\n\r\n").next().unwrap_or("").to_owned();
    head.split("\r\n").map(str::to_owned).collect()
}

#[test]
fn plain_message_round_trip() {
    let d = draft();
    let raw = build_plain(&d).expect("build_plain");
    assert_wire_format(&raw);
    let head = header_lines(&raw).join("\r\n");
    assert!(
        !head.contains("hidden@sealbox.test"),
        "Bcc must not be written"
    );
    assert!(head.contains("MIME-Version: 1.0"));

    // Our parser.
    let parsed = parse(&raw).expect("parse");
    assert_eq!(parsed.headers.subject.as_deref(), Some(d.subject.as_str()));
    assert_eq!(parsed.headers.from, vec![d.from.clone()]);
    assert_eq!(parsed.headers.to, d.to);
    assert_eq!(parsed.headers.cc, d.cc);
    assert_eq!(
        parsed.headers.message_id.as_deref(),
        Some(d.message_id.as_str())
    );
    assert_eq!(
        parsed.headers.in_reply_to,
        vec!["prev@sealbox.test".to_owned()]
    );
    assert_eq!(parsed.headers.references, d.references);
    assert_eq!(
        parsed.headers.content_type.as_deref(),
        Some("multipart/mixed")
    );
    assert!(parsed.headers.date.is_some_and(|t| (t - d.date).abs() <= 1));
    let MessageKind::Plain(body) = parsed.kind else {
        panic!("expected Plain, got {:?}", parsed.kind);
    };
    assert_eq!(lf(body.text.as_deref().unwrap()), d.text_body);
    assert_eq!(
        lf(body.html.as_deref().unwrap()),
        d.html_body.clone().unwrap()
    );
    assert_eq!(body.attachments.len(), 2);
    assert_eq!(body.attachments[0].filename, "notes.txt");
    assert_eq!(body.attachments[0].content_type, "text/plain");
    assert_eq!(body.attachments[0].data, b"attached text\n");
    assert_eq!(body.attachments[1].filename, "blob.bin");
    assert_eq!(body.attachments[1].data, (0u8..=255).collect::<Vec<u8>>());

    // Independent check with mail-parser.
    let mp = MessageParser::default().parse(&raw).expect("mail-parser");
    assert_eq!(mp.subject(), Some(d.subject.as_str()));
    assert_eq!(
        mp.from().and_then(|f| f.first()).and_then(|a| a.address()),
        Some("alice@sealbox.test")
    );
    assert_eq!(
        mp.from().and_then(|f| f.first()).and_then(|a| a.name()),
        Some("Alice Ärmel")
    );
    assert_eq!(mp.attachment_count(), 2);
    assert_eq!(lf(&mp.body_text(0).unwrap()), d.text_body);
}

#[test]
fn encrypted_message_structure_and_protected_headers_round_trip() {
    let d = draft();
    let gossip = autocrypt_gossip_header_value("bob@sealbox.test", &fake_keydata(600));
    let inner = render_inner_for_encryption(
        &d,
        &InnerOptions {
            gossip_headers: vec![gossip],
            legacy_display: false,
        },
    )
    .expect("inner");
    assert_wire_format(&inner);
    let inner_head = header_lines(&inner).join("\r\n");
    assert!(
        inner_head.contains("protected-headers=\"v1\"")
            || inner_head.contains("protected-headers=v1"),
        "inner entity must be marked protected-headers=v1:\n{inner_head}"
    );
    assert!(inner_head.contains("Autocrypt-Gossip:"));
    assert!(!inner_head.contains("hidden@sealbox.test"));

    // The decrypting side recovers everything from the inner entity.
    let dec = parse_decrypted_inner(&inner).expect("parse inner");
    assert!(dec.headers.present);
    assert_eq!(dec.headers.subject.as_deref(), Some(d.subject.as_str()));
    assert_eq!(dec.headers.from, vec![d.from.clone()]);
    assert_eq!(dec.headers.to, d.to);
    assert_eq!(dec.headers.cc, d.cc);
    assert_eq!(
        dec.headers.message_id.as_deref(),
        Some(d.message_id.as_str())
    );
    assert_eq!(
        dec.headers.in_reply_to,
        vec!["prev@sealbox.test".to_owned()]
    );
    assert_eq!(dec.headers.references, d.references);
    assert_eq!(dec.headers.date, Some(d.date));
    assert_eq!(dec.headers.autocrypt_gossip.len(), 1);
    let g = parse_autocrypt_header(&dec.headers.autocrypt_gossip[0]).expect("gossip parses");
    assert_eq!(g.addr, "bob@sealbox.test");
    assert_eq!(g.keydata, fake_keydata(600));
    assert_eq!(lf(dec.body.text.as_deref().unwrap()), d.text_body);
    assert_eq!(
        lf(dec.body.html.as_deref().unwrap()),
        d.html_body.clone().unwrap()
    );
    assert_eq!(dec.body.attachments.len(), 2);
    assert_eq!(
        dec.body.attachments[1].data,
        (0u8..=255).collect::<Vec<u8>>()
    );

    // Wrap "ciphertext" in multipart/encrypted with the obscured subject outside.
    let outer = OuterHeaders::for_protected(&d);
    assert_eq!(outer.subject, PROTECTED_SUBJECT_PLACEHOLDER);
    let raw = build_pgp_mime_encrypted(&outer, FAKE_CIPHERTEXT).expect("build encrypted");
    assert_wire_format(&raw);
    let head = header_lines(&raw).join("\r\n");
    assert!(
        !head.contains("do not leak"),
        "real subject leaked into outer headers"
    );
    assert!(head.contains("Subject: ..."));
    assert!(head.contains("Autocrypt: addr=alice@sealbox.test;"));

    let parsed = parse(&raw).expect("parse encrypted");
    assert_eq!(parsed.headers.subject.as_deref(), Some("..."));
    assert_eq!(
        parsed.headers.message_id.as_deref(),
        Some(d.message_id.as_str())
    );
    assert_eq!(
        parsed.headers.content_type.as_deref(),
        Some("multipart/encrypted")
    );
    assert_eq!(parsed.headers.autocrypt.len(), 1);
    let ac = parse_autocrypt_header(&parsed.headers.autocrypt[0]).expect("autocrypt parses");
    assert_eq!(ac.addr, "alice@sealbox.test");
    assert!(ac.prefer_encrypt_mutual);
    assert_eq!(ac.keydata, fake_keydata(3000));
    let MessageKind::PgpMimeEncrypted { ciphertext } = parsed.kind else {
        panic!("expected PgpMimeEncrypted, got {:?}", parsed.kind);
    };
    assert_eq!(
        lf(std::str::from_utf8(&ciphertext).unwrap()),
        FAKE_CIPHERTEXT.trim_end()
    );

    // mail-parser agrees on the RFC 3156 structure.
    let mp = MessageParser::default().parse(&raw).expect("mail-parser");
    let ct = mp.content_type().expect("content type");
    assert_eq!(ct.ctype(), "multipart");
    assert_eq!(ct.subtype(), Some("encrypted"));
    assert_eq!(ct.attribute("protocol"), Some("application/pgp-encrypted"));
    let children = mp.root_part().sub_parts().expect("multipart children");
    assert_eq!(children.len(), 2);
    let first = mp.part(children[0]).unwrap();
    let fct = first.content_type().unwrap();
    assert_eq!(
        (fct.ctype(), fct.subtype()),
        ("application", Some("pgp-encrypted"))
    );
    assert_eq!(first.text_contents().map(str::trim), Some("Version: 1"));
    let second = mp.part(children[1]).unwrap();
    let sct = second.content_type().unwrap();
    assert_eq!(
        (sct.ctype(), sct.subtype()),
        ("application", Some("octet-stream"))
    );
    assert!(String::from_utf8_lossy(second.contents()).contains("BEGIN PGP MESSAGE"));
}

#[test]
fn signed_message_round_trip_preserves_signed_bytes() {
    let d = draft();
    let part = prepare_signed_part(&d).expect("signed part");
    assert!(part.is_ascii(), "signed part must be 7-bit");
    assert!(!part.contains(&0u8));
    assert_wire_format(&part);
    let head = header_lines(&part).join("\r\n");
    assert!(head.contains("protected-headers=\"v1\"") || head.contains("protected-headers=v1"));

    let outer = OuterHeaders::from_draft(&d);
    let raw =
        build_pgp_mime_signed(&outer, &part, FAKE_SIGNATURE, "pgp-sha256").expect("build signed");
    assert_wire_format(&raw);

    let parsed = parse(&raw).expect("parse signed");
    assert_eq!(parsed.headers.subject.as_deref(), Some(d.subject.as_str()));
    let MessageKind::PgpMimeSigned {
        signed_part,
        signature,
        micalg,
    } = parsed.kind
    else {
        panic!("expected PgpMimeSigned, got {:?}", parsed.kind);
    };
    assert_eq!(signed_part, part, "signed bytes must survive byte-for-byte");
    assert_eq!(
        lf(std::str::from_utf8(&signature).unwrap()),
        FAKE_SIGNATURE.trim_end()
    );
    assert_eq!(micalg.as_deref(), Some("pgp-sha256"));

    // The verifier can read the protected headers from the signed part.
    let inner = parse_decrypted_inner(&signed_part).expect("inner of signed");
    assert!(inner.headers.present);
    assert_eq!(inner.headers.subject.as_deref(), Some(d.subject.as_str()));
    assert_eq!(lf(inner.body.text.as_deref().unwrap()), d.text_body);

    // mail-parser agrees on the structure.
    let mp = MessageParser::default().parse(&raw).expect("mail-parser");
    let ct = mp.content_type().unwrap();
    assert_eq!((ct.ctype(), ct.subtype()), ("multipart", Some("signed")));
    assert_eq!(ct.attribute("protocol"), Some("application/pgp-signature"));
    assert_eq!(ct.attribute("micalg"), Some("pgp-sha256"));
    let children = mp.root_part().sub_parts().unwrap();
    assert_eq!(children.len(), 2);
    let sig = mp.part(children[1]).unwrap();
    let sct = sig.content_type().unwrap();
    assert_eq!(
        (sct.ctype(), sct.subtype()),
        ("application", Some("pgp-signature"))
    );
    assert_eq!(lf(&mp.body_text(0).unwrap()), d.text_body);
}

#[test]
fn signed_message_rejects_8bit_part() {
    let d = draft();
    let outer = OuterHeaders::from_draft(&d);
    let err = build_pgp_mime_signed(
        &outer,
        "Content-Type: text/plain\r\n\r\nümlaut".as_bytes(),
        FAKE_SIGNATURE,
        "pgp-sha256",
    );
    assert!(err.is_err());
}

#[test]
fn autocrypt_header_of_3kb_folds_within_limits() {
    let keydata = fake_keydata(3000);
    let value = autocrypt_header_value("alice@sealbox.test", true, &keydata);
    let folded = fold_header("Autocrypt", &value);
    assert!(folded.ends_with("\r\n"));
    for line in folded.trim_end().split("\r\n") {
        assert!(
            line.len() <= 78,
            "folded line too long ({}): {line}",
            line.len()
        );
    }
    let continuation = folded.split("\r\n").filter(|l| l.starts_with(' ')).count();
    assert!(
        continuation >= 35,
        "a 3 KB header must fold into many lines, got {continuation}"
    );
    let rejoined = sealbox_mail::mime::unfold_header_value(&folded["Autocrypt:".len()..]);
    let parsed = parse_autocrypt_header(&rejoined).expect("parses after unfolding");
    assert_eq!(parsed.keydata, keydata);
    assert!(parsed.prefer_encrypt_mutual);

    // Through the real builder + parser as well.
    let mut d = MessageDraft::new(
        Mailbox::new("alice@sealbox.test"),
        vec![Mailbox::new("bob@sealbox.test")],
        "autocrypt",
        "hi\n",
    );
    d.extra_headers.push(("Autocrypt".into(), value.clone()));
    let raw = build_plain(&d).unwrap();
    assert_wire_format(&raw);
    let longest = header_lines(&raw).iter().map(String::len).max().unwrap();
    assert!(longest <= 78, "longest header line {longest} > 78");
    let parsed = parse(&raw).unwrap();
    assert_eq!(parsed.headers.autocrypt.len(), 1);
    let ac = parse_autocrypt_header(&parsed.headers.autocrypt[0]).unwrap();
    assert_eq!(ac.keydata, keydata);
    assert_eq!(ac.addr, "alice@sealbox.test");

    // Gossip and the unknown-critical-attribute rule.
    let g = autocrypt_gossip_header_value("bob@sealbox.test", &keydata);
    assert_eq!(parse_autocrypt_header(&g).unwrap().addr, "bob@sealbox.test");
    assert!(parse_autocrypt_header("addr=a@b; foo=bar; keydata=AAAA").is_none());
    assert!(parse_autocrypt_header("addr=a@b; _foo=bar; keydata=AAAA").is_some());
}

#[test]
fn legacy_display_part_is_hidden_from_body() {
    let d = draft();
    let inner = render_inner_for_encryption(
        &d,
        &InnerOptions {
            gossip_headers: vec![],
            legacy_display: true,
        },
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&inner).contains("text/rfc822-headers"));
    let dec = parse_decrypted_inner(&inner).unwrap();
    assert_eq!(lf(dec.body.text.as_deref().unwrap()), d.text_body);
    assert_eq!(
        dec.body.attachments.len(),
        2,
        "legacy display part must not count as attachment"
    );
}

#[test]
fn inline_pgp_and_unknown_protected_markers() {
    let mut d = MessageDraft::new(
        Mailbox::new("a@sealbox.test"),
        vec![Mailbox::new("b@sealbox.test")],
        "inline",
        format!("some intro\n{FAKE_CIPHERTEXT}\n"),
    );
    d.extra_headers.clear();
    let raw = build_plain(&d).unwrap();
    let parsed = parse(&raw).unwrap();
    let MessageKind::InlinePgp { armored } = parsed.kind else {
        panic!("expected InlinePgp, got {:?}", parsed.kind);
    };
    assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----"));
    assert!(armored.ends_with("-----END PGP MESSAGE-----"));

    // An inner entity without protected headers reports present=false.
    let plain_inner = b"Content-Type: text/plain; charset=utf-8\r\n\r\nhello\r\n";
    let dec = parse_decrypted_inner(plain_inner).unwrap();
    assert!(!dec.headers.present);
    assert_eq!(dec.headers.subject, None);
    assert_eq!(dec.body.text.as_deref(), Some("hello\r\n"));
    // draft-ietf-lamps-header-protection marker is recognised too.
    let hp_inner =
        b"Content-Type: text/plain; charset=utf-8; hp=\"cipher\"\r\nSubject: real\r\n\r\nhello\r\n";
    let dec = parse_decrypted_inner(hp_inner).unwrap();
    assert!(dec.headers.present);
    assert_eq!(dec.headers.subject.as_deref(), Some("real"));
}

#[test]
fn multipart_splitting_is_byte_exact() {
    let body = b"preamble\r\n--B\r\nContent-Type: text/plain\r\n\r\nfirst part\r\nno trailing newline\r\n--B \r\nContent-Type: text/plain\r\n\r\nsecond\r\n\r\n--B--\r\nepilogue";
    let parts = split_multipart(body, "B");
    assert_eq!(parts.len(), 2);
    assert_eq!(
        parts[0],
        b"Content-Type: text/plain\r\n\r\nfirst part\r\nno trailing newline"
    );
    assert_eq!(parts[1], b"Content-Type: text/plain\r\n\r\nsecond\r\n");
    // Delimiter at the very start, LF-only line endings.
    let parts = split_multipart(b"--x\nA: 1\n\nbody\n--x--\n", "x");
    assert_eq!(parts, vec![&b"A: 1\n\nbody"[..]]);
    // A boundary-like string inside a line is not a delimiter.
    let parts = split_multipart(b"--q\r\n\r\nsee --q here\r\n--q--\r\n", "q");
    assert_eq!(parts, vec![&b"\r\nsee --q here"[..]]);
}

#[test]
fn mailbox_parsing() {
    assert_eq!(
        Mailbox::parse("Alice <alice@sealbox.test>").unwrap(),
        Mailbox::named("Alice", "alice@sealbox.test")
    );
    assert_eq!(
        Mailbox::parse("\"Bob B.\" <bob@sealbox.test>").unwrap(),
        Mailbox::named("Bob B.", "bob@sealbox.test")
    );
    assert_eq!(
        Mailbox::parse("<c@sealbox.test>").unwrap(),
        Mailbox::new("c@sealbox.test")
    );
    assert_eq!(
        Mailbox::parse(" d@sealbox.test ").unwrap(),
        Mailbox::new("d@sealbox.test")
    );
    assert!(Mailbox::parse("not an address").is_err());
    assert!(Mailbox::parse("a b@c").is_err());
    assert_eq!(Mailbox::named("Alice", "a@b").to_string(), "Alice <a@b>");
}
