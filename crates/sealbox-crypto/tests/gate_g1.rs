//! Gate G1 — OpenPGP core with **real GnuPG interop** in both directions.
//!
//! Every test gets its own isolated `GNUPGHOME` under the cargo target directory (never
//! `~/.gnupg`), runs gpg with `--batch --yes --pinentry-mode loopback`, and kills only the
//! agent that gpg spawned for that home (`gpgconf --homedir … --kill all`) when done.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use pgp::composed::Deserializable;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{LiteralData, PacketTrait, PublicKeyEncryptedSessionKey};
use sealbox_crypto::*;

const GPG: &str = "/usr/bin/gpg";
const GPGCONF: &str = "/usr/bin/gpgconf";

struct Gpg {
    home: PathBuf,
}

impl Gpg {
    fn new(tag: &str) -> Self {
        let home = target_dir()
            .join("gpg-g1")
            .join(format!("{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("create GNUPGHOME");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(home.join("gpg-agent.conf"), "allow-loopback-pinentry\n").unwrap();
        Self { home }
    }

    fn run(&self, args: &[&str], stdin: &[u8]) -> Output {
        let mut child = Command::new(GPG)
            .arg("--homedir")
            .arg(&self.home)
            .args([
                "--batch",
                "--yes",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
                "--trust-model",
                "always",
            ])
            .args(args)
            .env("GNUPGHOME", &self.home)
            .env("LC_ALL", "C")
            .env_remove("DISPLAY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn gpg");
        {
            let mut pipe = child.stdin.take().unwrap();
            // gpg may exit before reading all of stdin; a broken pipe is not a test failure.
            let _ = pipe.write_all(stdin);
        }
        child.wait_with_output().expect("gpg output")
    }

    fn ok(&self, args: &[&str], stdin: &[u8]) -> Vec<u8> {
        let out = self.run(args, stdin);
        assert!(
            out.status.success(),
            "gpg {:?} failed ({}):\n{}",
            args,
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    /// ed25519 certify-only primary + cv25519 encryption subkey + ed25519 signing subkey
    /// (gpg's own "cert" primary cannot sign, so signatures come from the subkey — which
    /// also exercises Sealbox's signing-subkey matching), no passphrase.
    fn gen_key(&self, uid: &str, email: &str) -> String {
        self.ok(
            &[
                "--passphrase",
                "",
                "--quick-gen-key",
                uid,
                "ed25519",
                "cert",
                "never",
            ],
            b"",
        );
        let fpr = self.fingerprint_of(email);
        self.ok(
            &[
                "--passphrase",
                "",
                "--quick-add-key",
                &fpr,
                "cv25519",
                "encr",
                "never",
            ],
            b"",
        );
        self.ok(
            &[
                "--passphrase",
                "",
                "--quick-add-key",
                &fpr,
                "ed25519",
                "sign",
                "never",
            ],
            b"",
        );
        fpr
    }

    /// Fingerprint of the first subkey of `id` whose capability field contains `cap`
    /// (`s` = sign, `e` = encrypt), from `--with-colons` output.
    fn subkey_fingerprint_with_cap(&self, id: &str, cap: char) -> String {
        let out = self.ok(&["--list-keys", "--with-colons", id], b"");
        let text = String::from_utf8(out).unwrap();
        let mut want_fpr = false;
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            match f[0] {
                "sub" => want_fpr = f.get(11).map(|c| c.contains(cap)).unwrap_or(false),
                "fpr" if want_fpr => return f[9].to_string(),
                _ => {}
            }
        }
        panic!("no subkey with capability {cap} for {id}:\n{text}");
    }

    fn fingerprint_of(&self, id: &str) -> String {
        let out = self.ok(&["--list-keys", "--with-colons", id], b"");
        let text = String::from_utf8(out).unwrap();
        text.lines()
            .find(|l| l.starts_with("fpr:"))
            .and_then(|l| l.split(':').nth(9))
            .expect("fpr line")
            .to_string()
    }

    fn export_pub(&self, id: &str) -> String {
        String::from_utf8(self.ok(&["--export", "--armor", id], b"")).unwrap()
    }

    fn import(&self, armored: &str) {
        self.ok(&["--import"], armored.as_bytes());
    }

    fn path(&self, name: &str) -> String {
        self.home.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Gpg {
    fn drop(&mut self) {
        // Kill only the agent belonging to this GNUPGHOME.
        let _ = Command::new(GPGCONF)
            .arg("--homedir")
            .arg(&self.home)
            .args(["--kill", "all"])
            .env("GNUPGHOME", &self.home)
            .output();
    }
}

fn target_dir() -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(t) => PathBuf::from(t),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"),
    }
}

fn status_lines(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn alice() -> Identity {
    Identity::generate("Alice Sealbox", "alice@sealbox.test").unwrap()
}

// (a) Sealbox encrypt+sign → gpg decrypts and reports a good signature.
#[test]
fn g1a_sealbox_encrypts_and_signs_gpg_decrypts_and_verifies() {
    let gpg = Gpg::new("a");
    let alice = alice();
    let bob_fpr = gpg.gen_key("Gpg Bob <bob@sealbox.test>", "bob@sealbox.test");
    let bob = PublicKey::from_armored(&gpg.export_pub("bob@sealbox.test")).unwrap();
    assert_eq!(bob.fingerprint(), bob_fpr);
    assert!(bob.encryption_capable());
    gpg.import(&alice.public().to_armored().unwrap());

    let plaintext = b"Hello Bob, this came from Sealbox.\n";
    let armored =
        encrypt_and_sign_armored(plaintext, &[&bob, &alice.public()], Some(&alice)).unwrap();
    let out = gpg.run(&["--status-fd", "2", "--decrypt"], armored.as_bytes());
    let status = status_lines(&out);
    assert!(out.status.success(), "gpg decrypt failed:\n{status}");
    assert_eq!(out.stdout, plaintext);
    assert!(status.contains("[GNUPG:] GOODSIG"), "no GOODSIG:\n{status}");
    assert!(
        status.contains(&format!("VALIDSIG {}", alice.fingerprint())),
        "no VALIDSIG for alice:\n{status}"
    );
    assert!(status.contains("[GNUPG:] DECRYPTION_OKAY"), "{status}");

    // binary form too
    let binary = encrypt_and_sign(plaintext, &[&bob], Some(&alice)).unwrap();
    let out = gpg.run(&["--status-fd", "2", "--decrypt"], &binary);
    assert!(out.status.success(), "{}", status_lines(&out));
    assert_eq!(out.stdout, plaintext);
    assert!(status_lines(&out).contains("GOODSIG"));
}

// (b) gpg generates a key → Sealbox encrypts to the exported gpg public key → gpg decrypts.
#[test]
fn g1b_sealbox_encrypts_to_gpg_key_gpg_decrypts() {
    let gpg = Gpg::new("b");
    gpg.gen_key("Gpg Carol <carol@sealbox.test>", "carol@sealbox.test");
    let carol = PublicKey::from_armored(&gpg.export_pub("carol@sealbox.test")).unwrap();
    assert_eq!(carol.emails(), vec!["carol@sealbox.test"]);

    let big: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let ct = encrypt_and_sign(&big, &[&carol], None).unwrap();
    let out = gpg.run(&["--status-fd", "2", "--decrypt"], &ct);
    assert!(out.status.success(), "{}", status_lines(&out));
    assert_eq!(out.stdout, big);
    assert!(status_lines(&out).contains("DECRYPTION_OKAY"));
}

// (c) gpg encrypts+signs to Sealbox's exported public key → Sealbox decrypts + Good signature.
#[test]
fn g1c_gpg_encrypts_and_signs_sealbox_decrypts_and_verifies() {
    let gpg = Gpg::new("c");
    let alice = alice();
    let other = Identity::generate("Other", "other@sealbox.test").unwrap();
    gpg.import(&alice.public().to_armored().unwrap());
    let dave_fpr = gpg.gen_key("Gpg Dave <dave@sealbox.test>", "dave@sealbox.test");
    let dave = PublicKey::from_armored(&gpg.export_pub("dave@sealbox.test")).unwrap();

    let plaintext = b"From gpg, with a signature.\n";
    let ct = gpg.ok(
        &[
            "--encrypt",
            "--sign",
            "--armor",
            "--recipient",
            &alice.fingerprint(),
            "--local-user",
            &dave_fpr,
            "--passphrase",
            "",
            "-o",
            "-",
        ],
        plaintext,
    );
    assert!(String::from_utf8_lossy(&ct).starts_with("-----BEGIN PGP MESSAGE-----"));

    let dec = decrypt_and_verify(&ct, &[&other, &alice], &[&dave]).unwrap();
    assert_eq!(dec.plaintext, plaintext);
    assert_eq!(
        dec.signatures,
        vec![SignatureStatus::Good {
            fingerprint: dave_fpr.clone()
        }]
    );
    assert!(dec.signed_by_known_key());

    // signer unknown → UnknownKey with the key id of gpg's *signing subkey*
    let signing_sub = gpg.subkey_fingerprint_with_cap("dave@sealbox.test", 's');
    assert_ne!(signing_sub, dave_fpr);
    let dec = decrypt_and_verify(&ct, &[&alice], &[]).unwrap();
    assert_eq!(dec.plaintext, plaintext);
    assert_eq!(
        dec.signatures,
        vec![SignatureStatus::UnknownKey {
            key_id: signing_sub[signing_sub.len() - 16..].to_string()
        }]
    );

    // wrong decryptor
    assert!(matches!(
        decrypt_and_verify(&ct, &[&other], &[&dave]),
        Err(Error::NoDecryptionKey)
    ));

    // gpg encrypt without signing, binary, no compression
    let ct2 = gpg.ok(
        &[
            "--encrypt",
            "--compress-level",
            "0",
            "--recipient",
            &alice.fingerprint(),
            "-o",
            "-",
        ],
        b"unsigned",
    );
    let dec = decrypt_and_verify(&ct2, &[&alice], &[&dave]).unwrap();
    assert_eq!(dec.plaintext, b"unsigned");
    assert!(dec.signatures.is_empty());
}

// (d) Detached signatures both directions.
#[test]
fn g1d_detached_signatures_both_directions() {
    let gpg = Gpg::new("d");
    let alice = alice();
    gpg.import(&alice.public().to_armored().unwrap());
    let data = b"Content-Type: text/plain\r\n\r\nSigned MIME part.\r\n";

    // Sealbox → gpg
    let sig = sign_detached(data, &alice).unwrap();
    std::fs::write(gpg.path("data.bin"), data).unwrap();
    std::fs::write(gpg.path("data.sig.asc"), &sig).unwrap();
    let out = gpg.run(
        &[
            "--status-fd",
            "2",
            "--verify",
            &gpg.path("data.sig.asc"),
            &gpg.path("data.bin"),
        ],
        b"",
    );
    let status = status_lines(&out);
    assert!(out.status.success(), "{status}");
    assert!(
        status.contains(&format!("VALIDSIG {}", alice.fingerprint())),
        "{status}"
    );
    assert_eq!(micalg(), "pgp-sha256");
    // gpg must see SHA-256 (hash algo 8) to match our micalg claim
    assert!(
        status.contains(" 8 "),
        "expected SHA-256 in VALIDSIG line:\n{status}"
    );

    // gpg → Sealbox
    let erin_fpr = gpg.gen_key("Gpg Erin <erin@sealbox.test>", "erin@sealbox.test");
    let erin = PublicKey::from_armored(&gpg.export_pub("erin@sealbox.test")).unwrap();
    let gsig = gpg.ok(
        &[
            "--detach-sign",
            "--armor",
            "--local-user",
            &erin_fpr,
            "--passphrase",
            "",
            "-o",
            "-",
        ],
        data,
    );
    assert_eq!(
        verify_detached(data, &gsig, &[&erin]).unwrap(),
        vec![SignatureStatus::Good {
            fingerprint: erin_fpr.clone()
        }]
    );
    assert_eq!(
        verify_detached(b"modified", &gsig, &[&erin]).unwrap(),
        vec![SignatureStatus::Bad {
            fingerprint: erin_fpr
        }]
    );
    assert!(matches!(
        verify_detached(data, &gsig, &[&alice.public()]).unwrap()[0],
        SignatureStatus::UnknownKey { .. }
    ));
}

// (e) Autocrypt header render → parse → import yields a key that encrypts (and gpg accepts it).
#[test]
fn g1e_autocrypt_header_roundtrip_yields_working_key() {
    let gpg = Gpg::new("e");
    let alice = alice();
    let header = AutocryptHeader::for_identity(&alice, None, PreferEncrypt::Mutual).unwrap();
    let rendered = header.render();
    assert_eq!(header.keydata, minimal_key_for_autocrypt(&alice).unwrap());
    for line in rendered.split("\r\n").skip(1) {
        assert!(line.len() <= 76 && line.starts_with(' '), "{line:?}");
    }
    let parsed = AutocryptHeader::parse_for_sender(&[&rendered], "alice@sealbox.test")
        .expect("one valid header");
    assert_eq!(parsed, header);
    let key = parsed.public_key().unwrap();
    assert_eq!(key.fingerprint(), alice.fingerprint());
    assert!(key.encryption_capable());

    // Sealbox encrypts to the imported minimal key; the original identity decrypts.
    let ct = encrypt_and_sign(b"autocrypt", &[&key], None).unwrap();
    assert_eq!(
        decrypt_and_verify(&ct, &[&alice], &[]).unwrap().plaintext,
        b"autocrypt"
    );

    // gpg imports the minimal key and can encrypt to it.
    gpg.import(&key.to_armored().unwrap());
    let ct = gpg.ok(
        &[
            "--encrypt",
            "--armor",
            "--recipient",
            &alice.fingerprint(),
            "-o",
            "-",
        ],
        b"gpg to minimal key",
    );
    assert_eq!(
        decrypt_and_verify(&ct, &[&alice], &[]).unwrap().plaintext,
        b"gpg to minimal key"
    );

    // peer state driven by the header
    let mut peer = PeerState::new("alice@sealbox.test");
    let now = chrono::Utc::now();
    assert!(peer.update_from_header(Some(&parsed), now));
    assert_eq!(recommendation(&peer, false), Recommendation::Encrypt);
    assert_eq!(
        peer.target_key().unwrap().fingerprint(),
        alice.fingerprint()
    );
}

// (f) Guest envelope: Sealbox → gpg symmetric decrypt, and gpg --symmetric → Sealbox.
#[test]
fn g1f_guest_envelope_interops_with_gpg_symmetric() {
    let gpg = Gpg::new("f");
    let pw = generate_passphrase();
    let body = b"Guest message: no PGP needed on your side.\n";
    let env = guest_encrypt(body, &pw).unwrap();
    let out = gpg.run(
        &["--status-fd", "2", "--decrypt", "--passphrase", &pw],
        env.as_bytes(),
    );
    let status = status_lines(&out);
    assert!(out.status.success(), "{status}");
    assert_eq!(out.stdout, body);
    assert!(status.contains("DECRYPTION_OKAY"), "{status}");
    // wrong passphrase on the gpg side fails
    let out = gpg.run(&["--decrypt", "--passphrase", "not-it"], env.as_bytes());
    assert!(!out.status.success());

    // gpg --symmetric → Sealbox
    let ct = gpg.ok(
        &[
            "--symmetric",
            "--armor",
            "--passphrase",
            "s3cret pass",
            "-o",
            "-",
        ],
        b"from gpg --symmetric\n",
    );
    let ct = String::from_utf8(ct).unwrap();
    assert_eq!(
        guest_decrypt(&ct, "s3cret pass").unwrap(),
        b"from gpg --symmetric\n"
    );
    assert!(matches!(
        guest_decrypt(&ct, "wrong"),
        Err(Error::BadPassphrase)
    ));
    // explicit modern S2K parameters on the gpg side
    let ct = gpg.ok(
        &[
            "--symmetric",
            "--cipher-algo",
            "AES256",
            "--s2k-digest-algo",
            "SHA256",
            "--s2k-count",
            "65011712",
            "--passphrase",
            &pw,
            "-o",
            "-",
        ],
        b"binary symmetric",
    );
    assert_eq!(guest_decrypt_bytes_compat(&ct, &pw), b"binary symmetric");
}

fn guest_decrypt_bytes_compat(ct: &[u8], pw: &str) -> Vec<u8> {
    // binary input: pass through the &str API via lossless armoring is not possible, so use the
    // bytes entry point exposed for this case.
    sealbox_crypto::guest_decrypt_bytes(ct, pw).unwrap()
}

// (g) Tampered ciphertext fails — on both sides.
#[test]
fn g1g_tampered_ciphertext_is_rejected() {
    let gpg = Gpg::new("g");
    let alice = alice();
    gpg.import(&alice.public().to_armored().unwrap());
    let ct = encrypt_and_sign(b"integrity matters", &[&alice.public()], Some(&alice)).unwrap();
    let mut tampered = ct.clone();
    let n = tampered.len();
    tampered[n - 6] ^= 0x01;
    let err = decrypt_and_verify(&tampered, &[&alice], &[&alice.public()]).unwrap_err();
    assert!(
        matches!(err, Error::IntegrityFailure | Error::Corrupt(_)),
        "unexpected error: {err:?}"
    );
    // the untampered one is fine
    assert!(decrypt_and_verify(&ct, &[&alice], &[&alice.public()])
        .unwrap()
        .signed_by_known_key());

    // gpg encrypts to alice; we flip a byte; Sealbox refuses
    let gct = gpg.ok(
        &["--encrypt", "--recipient", &alice.fingerprint(), "-o", "-"],
        b"gpg ciphertext",
    );
    let mut gt = gct.clone();
    let n = gt.len();
    gt[n - 3] ^= 0x80;
    assert!(decrypt_and_verify(&gt, &[&alice], &[]).is_err());
    assert_eq!(
        decrypt_and_verify(&gct, &[&alice], &[]).unwrap().plaintext,
        b"gpg ciphertext"
    );

    // guest envelope tamper
    let pw = generate_passphrase();
    let env = guest_encrypt(b"guest", &pw).unwrap();
    let bin = {
        // dearmor via gpg to get bytes we can flip
        gpg.ok(&["--dearmor"], env.as_bytes())
    };
    let mut bt = bin.clone();
    let n = bt.len();
    bt[n - 4] ^= 0x10;
    assert!(sealbox_crypto::guest_decrypt_bytes(&bt, &pw).is_err());
    assert_eq!(
        sealbox_crypto::guest_decrypt_bytes(&bin, &pw).unwrap(),
        b"guest"
    );
}

// (h) A message without integrity protection (legacy SED packet, tag 9) is rejected.
#[test]
fn g1h_missing_integrity_protection_is_rejected() {
    let gpg = Gpg::new("h");
    let alice = alice();
    gpg.import(&alice.public().to_armored().unwrap());

    // Build PKESK + SED by hand (rPGP refuses to *produce* SED, as it should).
    let (cert, _) = pgp::composed::SignedPublicKey::from_armor_single(
        alice.public().to_armored().unwrap().as_bytes(),
    )
    .unwrap();
    let enc_subkey = &cert.public_subkeys[0].key;
    let mut rng = rand::thread_rng();
    let session_key = SymmetricKeyAlgorithm::AES256.new_session_key(&mut rng);
    let pkesk = PublicKeyEncryptedSessionKey::from_session_key_v3(
        &mut rng,
        &session_key,
        SymmetricKeyAlgorithm::AES256,
        enc_subkey,
    )
    .unwrap();
    let literal =
        LiteralData::from_bytes("", pgp::bytes::Bytes::from_static(b"no mdc here")).unwrap();
    let mut inner = Vec::new();
    literal.to_writer_with_header(&mut inner).unwrap();
    let body = SymmetricKeyAlgorithm::AES256
        .encrypt(&mut rng, session_key.as_ref(), &inner)
        .unwrap();
    let mut msg = Vec::new();
    pkesk.to_writer_with_header(&mut msg).unwrap();
    msg.push(0xC0 | 9); // new-format header, tag 9 = Symmetrically Encrypted Data
    push_new_format_length(&mut msg, body.len());
    msg.extend_from_slice(&body);

    assert!(matches!(
        decrypt_and_verify(&msg, &[&alice], &[]),
        Err(Error::MissingIntegrityProtection)
    ));
    // gpg refuses it as well (no MDC with a modern cipher → decryption forced to fail)
    let out = gpg.run(&["--status-fd", "2", "--decrypt"], &msg);
    assert!(
        !out.status.success(),
        "gpg accepted a non-MDC message:\n{}",
        status_lines(&out)
    );

    // A symmetric SED is refused by the guest path too.
    let pw = "pw";
    let skesk_msg = {
        use pgp::packet::SymKeyEncryptedSessionKey;
        use pgp::types::{Password, StringToKey};
        let s2k = StringToKey::new_iterated(&mut rng, pgp::crypto::hash::HashAlgorithm::Sha256, 96);
        let skesk = SymKeyEncryptedSessionKey::encrypt_v4(
            &Password::from(pw),
            &session_key,
            s2k,
            SymmetricKeyAlgorithm::AES256,
        )
        .unwrap();
        let mut m = Vec::new();
        skesk.to_writer_with_header(&mut m).unwrap();
        m.push(0xC0 | 9);
        push_new_format_length(&mut m, body.len());
        m.extend_from_slice(&body);
        m
    };
    assert!(matches!(
        sealbox_crypto::guest_decrypt_bytes(&skesk_msg, pw),
        Err(Error::MissingIntegrityProtection)
    ));
}

fn push_new_format_length(out: &mut Vec<u8>, len: usize) {
    if len < 192 {
        out.push(len as u8);
    } else if len < 8384 {
        let l = len - 192;
        out.push(((l >> 8) + 192) as u8);
        out.push((l & 0xff) as u8);
    } else {
        out.push(0xff);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

// Capability report (always passes; prints what rPGP offers for the gate log).
#[test]
fn g1_capabilities_report() {
    eprintln!(
        "rPGP {} — v6 keys: {}, SEIPDv2: {}, Argon2 S2K: {}, PQC: {}, GnuPG AEAD read: {}",
        capabilities::RPGP_VERSION,
        capabilities::V6_KEYS,
        capabilities::SEIPD_V2,
        capabilities::ARGON2_S2K,
        capabilities::PQC,
        capabilities::GNUPG_AEAD_READ
    );
    // A tripwire for the API line the capability flags above were checked against: patch releases
    // (security fixes) pass, a move to 0.22 must re-check them first.
    assert!(
        capabilities::RPGP_VERSION.starts_with("0.21."),
        "rPGP {} is outside the reviewed 0.21 line",
        capabilities::RPGP_VERSION
    );
}
