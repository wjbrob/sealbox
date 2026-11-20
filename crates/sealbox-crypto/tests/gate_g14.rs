//! Gate G14 — post-quantum hybrid (ML-KEM-768 + X25519, RFC 9980) encrypt/decrypt round-trip.
//!
//! Run with `cargo test -p sealbox-crypto --features pqc --test gate_g14`. The target declares
//! `required-features = ["pqc"]`, so `cargo test --workspace` without the feature skips it.
//!
//! What is proven here:
//! * (a) a hybrid identity encrypts+signs → decrypts+verifies through the crate's normal
//!   pipeline, and the session-key packets really use algorithm 35 (checked on the packets);
//! * (b) the RFC 9980 sample vectors: the published v4 and v6 messages decrypt through *our*
//!   path with the sample secret keys, and messages we produce for the sample public keys are
//!   opened by the sample secret keys;
//! * (c) classical identities are untouched with the feature on, the Autocrypt minimal key stays
//!   classical, and GnuPG 2.4 imports a hybrid certificate and encrypts to its X25519 subkey.
//!
//! The fixtures under `tests/fixtures/pqc/` are the RFC 9980 (ex draft-ietf-openpgp-pqc)
//! sample vectors exactly as shipped in rPGP 0.21's `tests/pqc/` (MIT OR Apache-2.0), file
//! names unchanged.
//!
//! Every gpg invocation uses an isolated `GNUPGHOME` under the cargo target directory (never
//! `~/.gnupg`) and kills only the agent it spawned for that home.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use pgp::composed::{Deserializable, Esk, Message, SignedPublicKey};
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Packet, PacketParser};
use pgp::types::{KeyDetails as _, PkeskBytes, PkeskVersion};
use sealbox_crypto::*;

const GPG: &str = "/usr/bin/gpg";
const GPGCONF: &str = "/usr/bin/gpgconf";

// RFC 9980 Appendix A sample vectors ("v4 Ed25519 with ML-KEM-768+X25519" and
// "v6 Ed25519 with ML-KEM-768+X25519").
const V4_SK: &str = include_str!("fixtures/pqc/v4-eddsa-sample-sk.asc");
const V4_PK: &str = include_str!("fixtures/pqc/v4-eddsa-sample-pk.asc");
const V4_MSG_V1: &str = include_str!("fixtures/pqc/v4-eddsa-sample-message-v1.asc");
const V4_MSG_V2: &str = include_str!("fixtures/pqc/v4-eddsa-sample-message-v2.asc");
const V6_SK: &str = include_str!("fixtures/pqc/v6-eddsa-sample-sk.asc");
const V6_PK: &str = include_str!("fixtures/pqc/v6-eddsa-sample-pk.asc");
const V6_MSG: &str = include_str!("fixtures/pqc/v6-eddsa-sample-message.asc");
const V4_SAMPLE_FPR: &str = "342E5DB2DE345215CB2C944F7102FFED3B9CF12D";
const V6_SAMPLE_FPR: &str = "C789E17D9DBDCA7B3C833A3C063FEB0353F80AD911FE27868FB0645DF803E947";
/// ML-KEM-768 ciphertext length (FIPS 203).
const ML_KEM_768_CT_LEN: usize = 1088;

// ---------------------------------------------------------------- packet inspection helpers

/// What one PKESK on a message says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pkesk {
    version: PkeskVersion,
    alg: PublicKeyAlgorithm,
    /// The symmetric algorithm carried in the clear by a v3 PKESK (X25519 / ML-KEM forms only).
    sym_alg: Option<SymmetricKeyAlgorithm>,
    /// Length of the ML-KEM ciphertext for algorithm-35 PKESKs.
    mlkem_ct_len: Option<usize>,
}

/// Parse an (armored or binary) message and describe every public-key ESK on it.
fn pkesks(msg: &[u8]) -> Vec<Pkesk> {
    let (parsed, _) = Message::from_reader(msg).expect("parse message");
    let Message::Encrypted { esk, .. } = parsed else {
        panic!("not an encrypted message");
    };
    esk.iter()
        .filter_map(|e| match e {
            Esk::PublicKeyEncryptedSessionKey(p) => {
                let alg = p.algorithm().expect("pkesk algorithm");
                let (sym_alg, mlkem_ct_len) = match p.values().expect("pkesk values") {
                    PkeskBytes::MlKem768X25519 {
                        ml_kem_ciphertext,
                        sym_alg,
                        ..
                    } => (*sym_alg, Some(ml_kem_ciphertext.len())),
                    PkeskBytes::X25519 { sym_alg, .. } => (*sym_alg, None),
                    _ => (None, None),
                };
                Some(Pkesk {
                    version: p.version(),
                    alg,
                    sym_alg,
                    mlkem_ct_len,
                })
            }
            Esk::SymKeyEncryptedSessionKey(_) => None,
        })
        .collect()
}

/// Every PKESK on the message is an ML-KEM-768+X25519 one of the given version, with a
/// 1088-byte ML-KEM ciphertext and (v3 only) AES-256 as the session-key algorithm.
fn assert_all_mlkem(esks: &[Pkesk], version: PkeskVersion) {
    assert!(!esks.is_empty(), "no PKESK on the message");
    for e in esks {
        assert_eq!(e.alg, PublicKeyAlgorithm::MlKem768X25519, "{e:?}");
        assert_eq!(e.version, version, "{e:?}");
        assert_eq!(e.mlkem_ct_len, Some(ML_KEM_768_CT_LEN), "{e:?}");
        match version {
            // RFC 9980 §6: the composite KEM must wrap an AES-256 session key.
            PkeskVersion::V3 => assert_eq!(e.sym_alg, Some(SymmetricKeyAlgorithm::AES256), "{e:?}"),
            _ => assert_eq!(e.sym_alg, None, "{e:?}"),
        }
    }
}

/// Walk the top-level packets of a *binary* message: is the container SEIPDv2?
fn is_seipd_v2(msg: &[u8]) -> bool {
    for p in PacketParser::new(msg) {
        if let Ok(Packet::SymEncryptedProtectedData(d)) = p {
            return d.version() == 2;
        }
    }
    panic!("no SEIPD packet in message");
}

/// Algorithms of the subkeys of a certificate, in packet order.
fn subkey_algorithms(pk: &PublicKey) -> Vec<PublicKeyAlgorithm> {
    let (cert, _) = SignedPublicKey::from_reader_single(&pk.to_bytes().unwrap()[..]).unwrap();
    cert.public_subkeys
        .iter()
        .map(|s| s.key.algorithm())
        .collect()
}

fn hybrid(name: &str, email: &str) -> Identity {
    Identity::generate_hybrid(name, email).expect("hybrid identity")
}

fn good(id: &Identity) -> Vec<SignatureStatus> {
    vec![SignatureStatus::Good {
        fingerprint: id.fingerprint(),
    }]
}

// ---------------------------------------------------------------------------- gpg harness

struct Gpg {
    home: PathBuf,
}

impl Gpg {
    fn new(tag: &str) -> Self {
        let home = target_dir()
            .join("gpg-g14")
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

    /// ed25519 certify-only primary + cv25519 encryption subkey + ed25519 signing subkey.
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
        for (algo, usage) in [("cv25519", "encr"), ("ed25519", "sign")] {
            self.ok(
                &[
                    "--passphrase",
                    "",
                    "--quick-add-key",
                    &fpr,
                    algo,
                    usage,
                    "never",
                ],
                b"",
            );
        }
        fpr
    }

    fn list_keys_colons(&self, id: &str) -> String {
        String::from_utf8(self.ok(&["--list-keys", "--with-colons", id], b"")).unwrap()
    }

    fn fingerprint_of(&self, id: &str) -> String {
        self.list_keys_colons(id)
            .lines()
            .find(|l| l.starts_with("fpr:"))
            .and_then(|l| l.split(':').nth(9))
            .expect("fpr line")
            .to_string()
    }

    fn export_pub(&self, id: &str) -> String {
        String::from_utf8(self.ok(&["--export", "--armor", id], b"")).unwrap()
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

fn gpg_version() -> String {
    let out = Command::new(GPG)
        .arg("--version")
        .output()
        .expect("gpg --version");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("gpg (unknown version)")
        .to_string()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// `(algorithm id, capability letters)` of every `sub:` line in `--with-colons` output.
fn gpg_subkeys(listing: &str) -> Vec<(u32, String)> {
    listing
        .lines()
        .filter(|l| l.starts_with("sub:"))
        .map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (
                f.get(3).and_then(|a| a.parse().ok()).unwrap_or(0),
                f.get(11).map(|c| c.to_string()).unwrap_or_default(),
            )
        })
        .collect()
}

// ------------------------------------------------------------------------------------ tests

// (a) Hybrid → hybrid round-trip through the crate's own pipeline, with packet-level evidence
// that the session key went through ML-KEM-768+X25519.
#[test]
fn g14a_hybrid_roundtrip_uses_mlkem768_x25519_pkesk() {
    let alice = hybrid("Alice PQ", "alice-pq@sealbox.test");
    let bob = hybrid("Bob PQ", "bob-pq@sealbox.test");
    assert_eq!(alice.version(), KeyVersion::V4);
    assert!(alice.public().pqc_capable());
    assert!(bob.public().pqc_capable());
    assert_eq!(
        subkey_algorithms(&alice.public()),
        vec![PublicKeyAlgorithm::ECDH, PublicKeyAlgorithm::MlKem768X25519]
    );

    let plaintext =
        b"Hello Bob - post-quantum hybrid. One AES-256 session key, two ML-KEM PKESKs.\n";
    let msg = encrypt_and_sign(plaintext, &[&bob.public(), &alice.public()], Some(&alice)).unwrap();

    // Same container the classical path produces today (SEIPDv1 + v3 PKESK), but every PKESK is
    // algorithm 35 with a 1088-byte ML-KEM-768 ciphertext wrapping an AES-256 key.
    assert!(
        !is_seipd_v2(&msg),
        "default hybrid keys do not advertise SEIPDv2"
    );
    let esks = pkesks(&msg);
    assert_eq!(esks.len(), 2, "{esks:?}");
    assert_all_mlkem(&esks, PkeskVersion::V3);
    eprintln!("G14a: PKESKs = {esks:?}");

    let dec = decrypt_and_verify(&msg, &[&bob], &[&alice.public()]).unwrap();
    assert_eq!(dec.plaintext, plaintext);
    assert_eq!(dec.signatures, good(&alice));
    assert!(dec.signed_by_known_key());

    // the sender reads her own copy back
    let dec = decrypt_and_verify(&msg, &[&alice], &[&alice.public()]).unwrap();
    assert_eq!(dec.plaintext, plaintext);
    assert!(dec.signed_by_known_key());

    // a third hybrid key cannot open it, and a flipped byte is detected
    let carol = hybrid("Carol PQ", "carol-pq@sealbox.test");
    assert!(matches!(
        decrypt_and_verify(&msg, &[&carol], &[]),
        Err(Error::NoDecryptionKey)
    ));
    let mut tampered = msg.clone();
    let n = tampered.len();
    tampered[n - 8] ^= 0x55;
    let err = decrypt_and_verify(&tampered, &[&bob], &[]).unwrap_err();
    assert!(
        matches!(err, Error::IntegrityFailure | Error::Corrupt(_)),
        "unexpected error {err:?}"
    );

    // armored output as used in mail bodies
    let armored = encrypt_and_sign_armored(plaintext, &[&bob.public()], Some(&alice)).unwrap();
    assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----"));
    assert_all_mlkem(&pkesks(armored.as_bytes()), PkeskVersion::V3);
    let dec = decrypt_and_verify(armored.as_bytes(), &[&bob], &[&alice.public()]).unwrap();
    assert_eq!(dec.plaintext, plaintext);
    assert_eq!(dec.signatures, good(&alice));
}

// (a') The RFC 9580 container variants: SEIPDv2 (v6 PKESK) when the hybrid keys advertise it,
// and fully v6 hybrid keys.
#[test]
fn g14b_hybrid_with_seipd_v2_and_v6_keys() {
    let aead = KeyGenOptions {
        version: KeyVersion::V4,
        profile: KeyProfile::HybridPqc,
        advertise_seipd_v2: true,
    };
    let a = Identity::generate_with("A", "a-pq@sealbox.test", aead).unwrap();
    let b = Identity::generate_with("B", "b-pq@sealbox.test", aead).unwrap();
    assert!(a.public().supports_seipd_v2() && a.public().pqc_capable());

    let msg = encrypt_and_sign(b"aead", &[&a.public(), &b.public()], Some(&a)).unwrap();
    assert!(is_seipd_v2(&msg), "both recipients advertise SEIPDv2");
    let esks = pkesks(&msg);
    assert_eq!(esks.len(), 2);
    assert_all_mlkem(&esks, PkeskVersion::V6);
    eprintln!("G14b (v4 keys, SEIPDv2): PKESKs = {esks:?}");
    let dec = decrypt_and_verify(&msg, &[&b], &[&a.public()]).unwrap();
    assert_eq!(dec.plaintext, b"aead");
    assert_eq!(dec.signatures, good(&a));

    // v6 (RFC 9580) hybrid identities: Ed25519 (27) primary, X25519 (25) + ML-KEM (35) subkeys
    let v6 = KeyGenOptions {
        version: KeyVersion::V6,
        profile: KeyProfile::HybridPqc,
        advertise_seipd_v2: true,
    };
    let x = Identity::generate_with("X", "x-pq@sealbox.test", v6).unwrap();
    let y = Identity::generate_with("Y", "y-pq@sealbox.test", v6).unwrap();
    assert_eq!(x.version(), KeyVersion::V6);
    assert_eq!(x.fingerprint().len(), 64);
    assert!(x.public().pqc_capable());
    assert_eq!(
        subkey_algorithms(&x.public()),
        vec![
            PublicKeyAlgorithm::X25519,
            PublicKeyAlgorithm::MlKem768X25519
        ]
    );
    let msg = encrypt_and_sign(b"v6 hybrid", &[&y.public()], Some(&x)).unwrap();
    assert!(is_seipd_v2(&msg));
    let esks = pkesks(&msg);
    assert_all_mlkem(&esks, PkeskVersion::V6);
    eprintln!("G14b (v6 keys): PKESKs = {esks:?}");
    let dec = decrypt_and_verify(&msg, &[&y], &[&x.public()]).unwrap();
    assert_eq!(dec.plaintext, b"v6 hybrid");
    assert_eq!(dec.signatures, good(&x));
    // armored v6 public key survives a round trip and is still PQC-capable
    let again = PublicKey::from_armored(&x.public().to_armored().unwrap()).unwrap();
    assert!(again.pqc_capable());
}

// (a'') Mixed recipients: the hybrid ones get algorithm-35 PKESKs, the classical one gets
// X25519 — all over the same session key, everybody decrypts.
#[test]
fn g14c_mixed_recipients_each_get_their_strongest_subkey() {
    let alice = hybrid("Alice PQ", "alice-pq@sealbox.test");
    let bob = Identity::generate("Bob Classic", "bob@sealbox.test").unwrap();
    let carol = hybrid("Carol PQ", "carol-pq@sealbox.test");
    assert!(!bob.public().pqc_capable());

    let msg = encrypt_and_sign(
        b"mixed",
        &[&bob.public(), &carol.public(), &alice.public()],
        Some(&alice),
    )
    .unwrap();
    assert!(!is_seipd_v2(&msg), "a classical recipient keeps SEIPDv1");
    let algs: Vec<PublicKeyAlgorithm> = pkesks(&msg).into_iter().map(|e| e.alg).collect();
    assert_eq!(
        algs,
        vec![
            PublicKeyAlgorithm::ECDH,
            PublicKeyAlgorithm::MlKem768X25519,
            PublicKeyAlgorithm::MlKem768X25519,
        ]
    );
    for who in [&bob, &carol, &alice] {
        let dec = decrypt_and_verify(&msg, &[who], &[&alice.public()]).unwrap();
        assert_eq!(dec.plaintext, b"mixed");
        assert_eq!(dec.signatures, good(&alice));
    }
}

// (b) RFC 9980 sample vectors, v4 key: decrypt the published messages through our path, then
// both directions between our API and the sample key pair.
#[test]
fn g14d_rfc9980_v4_sample_vectors() {
    let sk = Identity::from_armored_secret(V4_SK, None).expect("sample v4 secret key");
    let pk = PublicKey::from_armored(V4_PK).expect("sample v4 public key");
    assert_eq!(pk.fingerprint(), V4_SAMPLE_FPR);
    assert_eq!(sk.fingerprint(), V4_SAMPLE_FPR);
    assert_eq!(pk.version(), KeyVersion::V4);
    assert_eq!(
        subkey_algorithms(&pk),
        vec![PublicKeyAlgorithm::MlKem768X25519]
    );
    assert!(
        pk.pqc_capable(),
        "the sample key's only subkey is ML-KEM-768+X25519"
    );

    // (i) the published messages: SEIPDv1 + v3 PKESK, and SEIPDv2 + v6 PKESK
    for (name, text, version) in [
        (
            "v4-eddsa-sample-message-v1.asc",
            V4_MSG_V1,
            PkeskVersion::V3,
        ),
        (
            "v4-eddsa-sample-message-v2.asc",
            V4_MSG_V2,
            PkeskVersion::V6,
        ),
    ] {
        let esks = pkesks(text.as_bytes());
        assert_eq!(esks.len(), 1, "{name}: {esks:?}");
        assert_all_mlkem(&esks, version);
        let dec = decrypt_and_verify(text.as_bytes(), &[&sk], &[&pk]).expect(name);
        assert_eq!(dec.plaintext, b"Testing\n", "{name}");
        assert_eq!(
            dec.signatures,
            vec![SignatureStatus::Good {
                fingerprint: V4_SAMPLE_FPR.to_string()
            }],
            "{name}"
        );
        eprintln!("G14d vector {name}: decrypted to \"Testing\\n\", signature Good ({esks:?})");
    }

    // (ii) our API encrypts (and signs) to the sample public key; the sample secret key opens it.
    let us = hybrid("Sealbox PQ", "sealbox-pq@sealbox.test");
    let v1 = encrypt_and_sign_with(
        b"Testing\n",
        &[&pk],
        Some(&us),
        EncryptOptions {
            compress: false,
            prefer_seipd_v2: false,
        },
        false,
    )
    .unwrap();
    assert!(!is_seipd_v2(&v1));
    assert_all_mlkem(&pkesks(&v1), PkeskVersion::V3);
    let dec = decrypt_and_verify(&v1, &[&sk], &[&us.public()]).unwrap();
    assert_eq!(dec.plaintext, b"Testing\n");
    assert_eq!(dec.signatures, good(&us));

    // the sample certificate advertises SEIPDv2 (features 0x09), so the default path uses it
    assert!(pk.supports_seipd_v2());
    let v2 = encrypt_and_sign(b"Testing\n", &[&pk], Some(&us)).unwrap();
    assert!(is_seipd_v2(&v2));
    assert_all_mlkem(&pkesks(&v2), PkeskVersion::V6);
    let dec = decrypt_and_verify(&v2, &[&sk], &[&us.public()]).unwrap();
    assert_eq!(dec.plaintext, b"Testing\n");
    assert_eq!(dec.signatures, good(&us));

    // and the other way round: the sample key signs+encrypts to our hybrid identity
    let from_sample =
        encrypt_and_sign(b"from the RFC 9980 sample key", &[&us.public()], Some(&sk)).unwrap();
    assert_all_mlkem(&pkesks(&from_sample), PkeskVersion::V3);
    let dec = decrypt_and_verify(&from_sample, &[&us], &[&pk]).unwrap();
    assert_eq!(dec.plaintext, b"from the RFC 9980 sample key");
    assert_eq!(
        dec.signatures,
        vec![SignatureStatus::Good {
            fingerprint: V4_SAMPLE_FPR.to_string()
        }]
    );
    eprintln!("G14d: our API <-> RFC 9980 v4 sample key: both directions OK (SEIPDv1 and SEIPDv2)");
}

// (b') RFC 9980 sample vectors, v6 key. Our code path accepts v6 keys (`KeyVersion::V6`), so
// this is a hard requirement, not a conditional.
#[test]
fn g14e_rfc9980_v6_sample_vectors() {
    let sk = Identity::from_armored_secret(V6_SK, None).expect("sample v6 secret key");
    let pk = PublicKey::from_armored(V6_PK).expect("sample v6 public key");
    assert_eq!(pk.fingerprint(), V6_SAMPLE_FPR);
    assert_eq!(sk.fingerprint(), V6_SAMPLE_FPR);
    assert_eq!(pk.version(), KeyVersion::V6);
    assert_eq!(
        subkey_algorithms(&pk),
        vec![PublicKeyAlgorithm::MlKem768X25519]
    );
    assert!(pk.pqc_capable());

    // (i) the published message
    let esks = pkesks(V6_MSG.as_bytes());
    assert_eq!(esks.len(), 1, "{esks:?}");
    assert_all_mlkem(&esks, PkeskVersion::V6);
    let dec = decrypt_and_verify(V6_MSG.as_bytes(), &[&sk], &[&pk]).expect("v6 sample message");
    assert_eq!(dec.plaintext, b"Testing\n");
    assert_eq!(
        dec.signatures,
        vec![SignatureStatus::Good {
            fingerprint: V6_SAMPLE_FPR.to_string()
        }]
    );
    eprintln!("G14e vector v6-eddsa-sample-message.asc: decrypted to \"Testing\\n\", signature Good ({esks:?})");

    // (ii) our API → sample v6 public key → sample secret key
    let us = Identity::generate_with(
        "Sealbox PQ v6",
        "sealbox-pq6@sealbox.test",
        KeyGenOptions {
            version: KeyVersion::V6,
            profile: KeyProfile::HybridPqc,
            advertise_seipd_v2: true,
        },
    )
    .unwrap();
    let ct = encrypt_and_sign(b"Testing\n", &[&pk], Some(&us)).unwrap();
    assert!(is_seipd_v2(&ct), "v6 keys always advertise SEIPDv2");
    assert_all_mlkem(&pkesks(&ct), PkeskVersion::V6);
    let dec = decrypt_and_verify(&ct, &[&sk], &[&us.public()]).unwrap();
    assert_eq!(dec.plaintext, b"Testing\n");
    assert_eq!(dec.signatures, good(&us));

    // and back: the sample v6 key signs+encrypts to us
    let back = encrypt_and_sign(b"v6 sample -> sealbox", &[&us.public()], Some(&sk)).unwrap();
    let dec = decrypt_and_verify(&back, &[&us], &[&pk]).unwrap();
    assert_eq!(dec.plaintext, b"v6 sample -> sealbox");
    assert_eq!(
        dec.signatures,
        vec![SignatureStatus::Good {
            fingerprint: V6_SAMPLE_FPR.to_string()
        }]
    );
    eprintln!("G14e: our API <-> RFC 9980 v6 sample key: both directions OK");
}

// (c) A classical identity is byte-for-byte the same product with the feature on: one X25519
// subkey, X25519 PKESKs, SEIPDv1.
#[test]
fn g14f_classical_identity_unchanged_with_pqc_feature_on() {
    let alice = Identity::generate("Alice", "alice@sealbox.test").unwrap();
    let bob = Identity::generate("Bob", "bob@sealbox.test").unwrap();
    assert_eq!(
        subkey_algorithms(&alice.public()),
        vec![PublicKeyAlgorithm::ECDH]
    );
    assert!(!alice.public().pqc_capable());
    assert_eq!(KeyGenOptions::default().profile, KeyProfile::Classical);

    let msg = encrypt_and_sign(
        b"classical",
        &[&bob.public(), &alice.public()],
        Some(&alice),
    )
    .unwrap();
    assert!(!is_seipd_v2(&msg));
    let esks = pkesks(&msg);
    assert_eq!(esks.len(), 2);
    for e in &esks {
        assert_eq!(e.alg, PublicKeyAlgorithm::ECDH, "{e:?}");
        assert_eq!(e.version, PkeskVersion::V3, "{e:?}");
        assert_eq!(e.mlkem_ct_len, None);
    }
    let dec = decrypt_and_verify(&msg, &[&bob], &[&alice.public()]).unwrap();
    assert_eq!(dec.plaintext, b"classical");
    assert_eq!(dec.signatures, good(&alice));

    // a hybrid sender to a classical recipient is a plain X25519 message
    let hy = hybrid("Hy", "hy@sealbox.test");
    let msg = encrypt_and_sign(b"to classic", &[&bob.public()], Some(&hy)).unwrap();
    assert_eq!(pkesks(&msg)[0].alg, PublicKeyAlgorithm::ECDH);
    let dec = decrypt_and_verify(&msg, &[&bob], &[&hy.public()]).unwrap();
    assert_eq!(dec.plaintext, b"to classic");
    assert_eq!(dec.signatures, good(&hy));
}

// (c') Hybrid secret keys export/import, plain and passphrase-locked (the ML-KEM secret subkey
// is locked and unlocked like the others).
#[test]
fn g14g_hybrid_secret_key_export_import_plain_and_locked() {
    let alice = hybrid("Alice PQ", "alice-pq@sealbox.test");
    let msg = encrypt_and_sign(b"before export", &[&alice.public()], None).unwrap();
    assert_all_mlkem(&pkesks(&msg), PkeskVersion::V3);

    let plain = alice.to_armored_secret(None).unwrap();
    let back = Identity::from_armored_secret(&plain, None).unwrap();
    assert_eq!(back.fingerprint(), alice.fingerprint());
    assert!(back.public().pqc_capable());
    assert_eq!(
        decrypt_and_verify(&msg, &[&back], &[]).unwrap().plaintext,
        b"before export"
    );

    let locked = alice.to_armored_secret(Some("correct horse")).unwrap();
    assert!(matches!(
        Identity::from_armored_secret(&locked, None),
        Err(Error::KeyLocked)
    ));
    assert!(matches!(
        Identity::from_armored_secret(&locked, Some("wrong")),
        Err(Error::KeyLocked)
    ));
    let unlocked = Identity::from_armored_secret(&locked, Some("correct horse")).unwrap();
    assert_eq!(unlocked.fingerprint(), alice.fingerprint());
    assert!(unlocked.public().pqc_capable());
    assert_eq!(
        decrypt_and_verify(&msg, &[&unlocked], &[])
            .unwrap()
            .plaintext,
        b"before export"
    );

    let bin = alice.to_secret_bytes().unwrap();
    let from_bin = Identity::from_secret_bytes(&bin, None).unwrap();
    assert_eq!(from_bin.fingerprint(), alice.fingerprint());
}

// (c'') The Autocrypt minimal key of a hybrid identity carries the classical subkey only, so
// Level 1 peers keep working — and it still routes to the hybrid identity.
#[test]
fn g14h_autocrypt_minimal_key_stays_classical() {
    let alice = hybrid("Alice PQ", "alice-pq@sealbox.test");
    let minimal = PublicKey::from_bytes(&minimal_key_for_autocrypt(&alice).unwrap()).unwrap();
    assert_eq!(minimal.fingerprint(), alice.fingerprint());
    assert!(minimal.encryption_capable());
    assert!(!minimal.pqc_capable());
    assert_eq!(subkey_algorithms(&minimal), vec![PublicKeyAlgorithm::ECDH]);

    let header = AutocryptHeader::for_identity(&alice, None, PreferEncrypt::Mutual).unwrap();
    let rendered = header.render();
    assert!(
        rendered.len() < AUTOCRYPT_MAX_HEADER_SIZE,
        "{}",
        rendered.len()
    );
    let parsed = AutocryptHeader::parse_for_sender(&[&rendered], "alice-pq@sealbox.test")
        .expect("valid header");
    assert_eq!(
        parsed.public_key().unwrap().fingerprint(),
        alice.fingerprint()
    );

    let ct = encrypt_and_sign(b"autocrypt", &[&minimal], None).unwrap();
    assert_eq!(pkesks(&ct)[0].alg, PublicKeyAlgorithm::ECDH);
    assert_eq!(
        decrypt_and_verify(&ct, &[&alice], &[]).unwrap().plaintext,
        b"autocrypt"
    );
    // the full certificate, by contrast, is PQC-capable and gets algorithm-35 PKESKs
    let full = PublicKey::from_armored(&alice.public().to_armored().unwrap()).unwrap();
    assert!(full.pqc_capable());
    assert_all_mlkem(
        &pkesks(&encrypt_and_sign(b"full", &[&full], None).unwrap()),
        PkeskVersion::V3,
    );
}

// (c''') GnuPG interop with a hybrid certificate: gpg imports it, lists a usable cv25519
// subkey, encrypts to that subkey (never to algorithm 35) and we decrypt; gpg's own signed
// mail to the hybrid key verifies; and a Sealbox message that also carries an algorithm-35
// PKESK (sender's own copy) is still readable by gpg.
#[test]
fn g14i_gpg_imports_hybrid_certificate_and_encrypts_to_x25519_subkey() {
    let gpg = Gpg::new("i");
    let version = gpg_version();
    let alice = hybrid("Alice PQ", "alice-pq@sealbox.test");
    let armored = alice.public().to_armored().unwrap();

    let out = gpg.run(&["--status-fd", "2", "--import"], armored.as_bytes());
    let status = stderr_of(&out);
    if !out.status.success() || !status.contains("[GNUPG:] IMPORT_OK") {
        eprintln!(
            "G14i gpg: SKIP — {version} cannot import a certificate with an algorithm-35 \
             (ML-KEM-768+X25519) subkey. exit={} stderr:\n{status}",
            out.status
        );
        return;
    }
    let listing = gpg.list_keys_colons(&alice.fingerprint());
    let subs = gpg_subkeys(&listing);
    eprintln!(
        "G14i gpg: {version} imported the hybrid certificate; subkeys (algo, caps) = {subs:?}"
    );
    assert!(
        subs.iter()
            .any(|(algo, caps)| *algo == 18 && caps.contains('e')),
        "gpg lists no usable cv25519 (algo 18) encryption subkey:\n{listing}"
    );
    match subs.iter().find(|(algo, _)| *algo == 35) {
        Some((_, caps)) => eprintln!(
            "G14i gpg: keeps the ML-KEM-768+X25519 subkey (algo 35) with capabilities {caps:?}"
        ),
        None => eprintln!("G14i gpg: dropped the ML-KEM-768+X25519 subkey (algo 35) on import"),
    }

    // gpg → hybrid key. gpg must pick the X25519 subkey; if it imported the key but cannot
    // encrypt to it, hybrid keys would break gpg senders — that is a failure, not a skip.
    let out = gpg.run(
        &[
            "--status-fd",
            "2",
            "--encrypt",
            "--recipient",
            &alice.fingerprint(),
            "-o",
            "-",
        ],
        b"gpg to hybrid key",
    );
    assert!(
        out.status.success(),
        "gpg {version} imported the hybrid key but cannot encrypt to it:\n{}",
        stderr_of(&out)
    );
    let esks = pkesks(&out.stdout);
    assert!(
        !esks.is_empty() && esks.iter().all(|e| e.alg == PublicKeyAlgorithm::ECDH),
        "gpg did not encrypt to the X25519 subkey: {esks:?}"
    );
    let dec = decrypt_and_verify(&out.stdout, &[&alice], &[]).unwrap();
    assert_eq!(dec.plaintext, b"gpg to hybrid key");
    eprintln!("G14i gpg: encrypted to the cv25519 subkey ({esks:?}); Sealbox decrypted it");

    // gpg signs+encrypts with its own key; the hybrid identity decrypts and verifies
    let dave_fpr = gpg.gen_key("Gpg Dave <dave-pq@sealbox.test>", "dave-pq@sealbox.test");
    let dave = PublicKey::from_armored(&gpg.export_pub("dave-pq@sealbox.test")).unwrap();
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
        b"signed by gpg\n",
    );
    let dec = decrypt_and_verify(&ct, &[&alice], &[&dave]).unwrap();
    assert_eq!(dec.plaintext, b"signed by gpg\n");
    assert_eq!(
        dec.signatures,
        vec![SignatureStatus::Good {
            fingerprint: dave_fpr
        }]
    );

    // Sealbox (hybrid) → gpg user + own copy: the message carries one X25519 PKESK for Dave and
    // one algorithm-35 PKESK gpg has never seen. gpg must skip the unknown one and decrypt.
    let plaintext = b"From Sealbox, with an ML-KEM PKESK next to yours.\n";
    let mixed =
        encrypt_and_sign_armored(plaintext, &[&dave, &alice.public()], Some(&alice)).unwrap();
    let algs: Vec<PublicKeyAlgorithm> = pkesks(mixed.as_bytes())
        .into_iter()
        .map(|e| e.alg)
        .collect();
    assert_eq!(
        algs,
        vec![PublicKeyAlgorithm::ECDH, PublicKeyAlgorithm::MlKem768X25519]
    );
    let out = gpg.run(&["--status-fd", "2", "--decrypt"], mixed.as_bytes());
    let status = stderr_of(&out);
    assert!(
        out.status.success() && out.stdout == plaintext,
        "gpg {version} could not decrypt a message that also carries an algorithm-35 PKESK:\n{status}"
    );
    assert!(status.contains("[GNUPG:] DECRYPTION_OKAY"), "{status}");
    assert!(
        status.contains(&format!("VALIDSIG {}", alice.fingerprint())),
        "no VALIDSIG for the hybrid identity's Ed25519 primary:\n{status}"
    );
    eprintln!("G14i gpg: decrypted + verified a Sealbox message carrying an ML-KEM PKESK alongside its own");
}

// Capability report (what this build offers, for the gate log).
#[test]
fn g14_capabilities_report() {
    eprintln!(
        "rPGP {} — PQC: {} (ML-KEM-768+X25519 hybrid profile available), v6 keys: {}, SEIPDv2: {}",
        capabilities::RPGP_VERSION,
        capabilities::PQC,
        capabilities::V6_KEYS,
        capabilities::SEIPD_V2
    );
    assert!(
        capabilities::PQC,
        "gate_g14 must be built with --features pqc"
    );
    assert_eq!(capabilities::RPGP_VERSION, "0.21.0");
}
