//! Interop with two more independent OpenPGP implementations beyond gate G1's GnuPG:
//! **RNP** (the OpenPGP engine inside Thunderbird) and **Sequoia** (`sq`). Both directions
//! for each: Sealbox encrypts + signs → the other implementation decrypts and verifies the
//! signature; the other implementation encrypts + signs → Sealbox decrypts and verifies.
//!
//! Run by gate G1 with `-- --ignored` (host tools: `/usr/bin/rnp`, `/usr/bin/rnpkeys`,
//! `/usr/bin/sq`; `sudo apt-get install rnp sq`). Every case gets its own home directory under
//! the cargo target dir — never `~/.rnp` or `~/.local/share/sequoia`. The tests fail loudly
//! when a tool is missing: a skipped interop proof is not a proof.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sealbox_crypto::*;

const RNP: &str = "/usr/bin/rnp";
const RNPKEYS: &str = "/usr/bin/rnpkeys";
const SQ: &str = "/usr/bin/sq";

fn target_dir() -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(t) => PathBuf::from(t),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"),
    }
}

fn require_tools() {
    for t in [RNP, RNPKEYS, SQ] {
        assert!(
            Path::new(t).exists(),
            "{t} is missing — install the interop oracles with `sudo apt-get install rnp sq`"
        );
    }
}

/// A private, throw-away working directory (0700) for one case.
struct Home {
    dir: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Self {
        let dir = target_dir()
            .join("interop-tools")
            .join(format!("{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create interop home");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn write(&self, name: &str, data: impl AsRef<[u8]>) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, data).expect("write fixture");
        p
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.path(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
    }
}

fn run(bin: &str, args: &[&str], cwd: &Path) -> Output {
    Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .env("LC_ALL", "C")
        .env_remove("DISPLAY")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("spawn {bin}: {e}"))
}

fn ok(bin: &str, args: &[&str], cwd: &Path) -> Output {
    let out = run(bin, args, cwd);
    assert!(
        out.status.success(),
        "{bin} {args:?} failed ({}):\n--- stdout\n{}\n--- stderr\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn s(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

// ---- RNP (Thunderbird's engine) -----------------------------------------------------------

struct Rnp {
    home: Home,
}

impl Rnp {
    fn new(tag: &str) -> Self {
        Self {
            home: Home::new(&format!("rnp-{tag}")),
        }
    }

    fn homedir(&self) -> PathBuf {
        let d = self.home.path("rnphome");
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn import(&self, key_file: &Path) {
        let hd = self.homedir();
        ok(
            RNPKEYS,
            &["--homedir", s(&hd), "--import-keys", s(key_file)],
            &self.home.dir,
        );
    }

    /// Generates RNP's own default key pair (RSA-2048, no passphrase).
    fn generate(&self, userid: &str) {
        let hd = self.homedir();
        ok(
            RNPKEYS,
            &[
                "--homedir",
                s(&hd),
                "--generate-key",
                "--userid",
                userid,
                "--notty",
                "--password",
                "",
            ],
            &self.home.dir,
        );
    }

    fn export_public(&self, userid: &str, out: &Path) {
        let hd = self.homedir();
        ok(
            RNPKEYS,
            &[
                "--homedir",
                s(&hd),
                "--export-key",
                userid,
                "--output",
                s(out),
                "--overwrite",
            ],
            &self.home.dir,
        );
    }

    fn decrypt(&self, input: &Path, out: &Path) -> Output {
        let hd = self.homedir();
        run(
            RNP,
            &[
                "--homedir",
                s(&hd),
                "--decrypt",
                s(input),
                "--output",
                s(out),
                "--overwrite",
                "--notty",
            ],
            &self.home.dir,
        )
    }

    /// `rnp -c`: passphrase-only (SKESK + SEIPD) armored message, as an Autocrypt Setup
    /// Message carries its key.
    fn symmetric_encrypt(&self, passphrase: &str, input: &Path, out: &Path) {
        let hd = self.homedir();
        ok(
            RNP,
            &[
                "--homedir",
                s(&hd),
                "-c",
                "--password",
                passphrase,
                "--armor",
                "--output",
                s(out),
                "--overwrite",
                "--notty",
                s(input),
            ],
            &self.home.dir,
        );
    }

    fn decrypt_with_password(&self, passphrase: &str, input: &Path, out: &Path) -> Output {
        let hd = self.homedir();
        run(
            RNP,
            &[
                "--homedir",
                s(&hd),
                "--decrypt",
                "--password",
                passphrase,
                s(input),
                "--output",
                s(out),
                "--overwrite",
                "--notty",
            ],
            &self.home.dir,
        )
    }

    fn list_secret_keys(&self) -> String {
        let hd = self.homedir();
        let out = ok(
            RNPKEYS,
            &["--homedir", s(&hd), "--list-keys", "--secret"],
            &self.home.dir,
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn encrypt_and_sign(&self, recipient: &str, signer: &str, input: &Path, out: &Path) {
        let hd = self.homedir();
        ok(
            RNP,
            &[
                "--homedir",
                s(&hd),
                "--encrypt",
                "--sign",
                "-r",
                recipient,
                "-u",
                signer,
                "--armor",
                "--output",
                s(out),
                "--overwrite",
                "--notty",
                "--password",
                "",
                s(input),
            ],
            &self.home.dir,
        );
    }
}

// ---- Sequoia (sq) --------------------------------------------------------------------------

struct Sq {
    home: Home,
}

impl Sq {
    fn new(tag: &str) -> Self {
        Self {
            home: Home::new(&format!("sq-{tag}")),
        }
    }

    fn base(&self) -> Vec<String> {
        let sqhome = self.home.path("sqhome");
        std::fs::create_dir_all(&sqhome).unwrap();
        vec![
            "--home".into(),
            sqhome.to_string_lossy().into_owned(),
            "--batch".into(),
        ]
    }

    fn sq(&self, args: &[&str]) -> Output {
        let mut all: Vec<String> = self.base();
        all.extend(args.iter().map(|a| a.to_string()));
        let refs: Vec<&str> = all.iter().map(String::as_str).collect();
        ok(SQ, &refs, &self.home.dir)
    }

    fn sq_may_fail(&self, args: &[&str]) -> Output {
        let mut all: Vec<String> = self.base();
        all.extend(args.iter().map(|a| a.to_string()));
        let refs: Vec<&str> = all.iter().map(String::as_str).collect();
        run(SQ, &refs, &self.home.dir)
    }

    /// Generates sq's default key (Ed25519 + X25519, v4 profile), unprotected, and returns
    /// `(key file, cert file)`.
    fn generate(&self, name: &str, email: &str) -> (PathBuf, PathBuf) {
        let key = self.home.path("sq-key.pgp");
        let rev = self.home.path("sq-key.rev");
        let cert = self.home.path("sq-cert.pgp");
        self.sq(&[
            "key",
            "generate",
            "--name",
            name,
            "--email",
            email,
            "--own-key",
            "--without-password",
            "--output",
            s(&key),
            "--rev-cert",
            s(&rev),
        ]);
        // `key delete` strips the secret material from a key file → the certificate.
        self.sq(&[
            "key",
            "delete",
            "--cert-file",
            s(&key),
            "--output",
            s(&cert),
        ]);
        (key, cert)
    }

    fn encrypt_and_sign(&self, for_cert: &Path, signer_key: &Path, input: &Path, out: &Path) {
        self.sq(&[
            "encrypt",
            "--for-file",
            s(for_cert),
            "--signer-file",
            s(signer_key),
            "--output",
            s(out),
            s(input),
        ]);
    }

    fn decrypt(&self, key: &Path, signer_cert: &Path, input: &Path, out: &Path) -> Output {
        self.sq_may_fail(&[
            "decrypt",
            "--recipient-file",
            s(key),
            "--signer-file",
            s(signer_cert),
            "--signatures",
            "1",
            "--output",
            s(out),
            s(input),
        ])
    }
}

// ---- Sealbox side ----------------------------------------------------------------------------

fn alice() -> Identity {
    Identity::generate("Alice Sealbox", "alice@sealbox.test").unwrap()
}

fn bob() -> Identity {
    Identity::generate("Bob Sealbox", "bob@sealbox.test").unwrap()
}

fn key_id_tail(fingerprint: &str) -> String {
    fingerprint[fingerprint.len() - 16..].to_ascii_lowercase()
}

fn assert_good_from(d: &Decrypted, expected_fpr: &str) {
    assert!(
        d.signed_by_known_key(),
        "expected a Good signature, got {:?}",
        d.signatures
    );
    assert!(
        d.signatures.iter().any(|st| matches!(
            st,
            SignatureStatus::Good { fingerprint } if fingerprint.eq_ignore_ascii_case(expected_fpr)
        )),
        "signature not attributed to {expected_fpr}: {:?}",
        d.signatures
    );
}

// ---- cases: RNP ----------------------------------------------------------------------------

/// Sealbox (Alice) → Sealbox key (Bob), read by RNP with Bob's key: the Thunderbird case of a
/// user importing their Sealbox key into Thunderbird and opening mail from another Sealbox
/// user. Also proves the default profile stays on SEIPDv1 (RNP 0.17 reads it).
#[test]
#[ignore = "needs /usr/bin/rnp (gate G1 runs it)"]
fn rnp_decrypts_and_verifies_a_sealbox_message() {
    require_tools();
    let (alice, bob) = (alice(), bob());
    let rnp = Rnp::new("sealbox-to-rnp");
    let plaintext = format!("hello Thunderbird, nonce {}\n", std::process::id());

    let armored = encrypt_and_sign_armored(
        plaintext.as_bytes(),
        &[&bob.public(), &alice.public()],
        Some(&alice),
    )
    .unwrap();
    let msg = rnp.home.write("msg.asc", &armored);
    let bob_secret = rnp
        .home
        .write("bob-secret.asc", bob.to_armored_secret(None).unwrap());
    let alice_pub = rnp
        .home
        .write("alice-pub.asc", alice.public().to_armored().unwrap());
    rnp.import(&bob_secret);
    rnp.import(&alice_pub);

    let out = rnp.home.path("out.txt");
    let res = rnp.decrypt(&msg, &out);
    let log = stderr_of(&res);
    assert!(res.status.success(), "rnp --decrypt failed:\n{log}");
    assert_eq!(
        rnp.home.read("out.txt"),
        plaintext.as_bytes(),
        "plaintext differs"
    );
    assert!(
        log.contains("Good signature"),
        "rnp did not report a good signature:\n{log}"
    );
    assert!(
        !log.contains("BAD signature"),
        "rnp reported a bad signature:\n{log}"
    );
    let alice_key_id = key_id_tail(&alice.public().fingerprint());
    assert!(
        log.to_ascii_lowercase().contains(&alice_key_id),
        "signature not attributed to Alice's key {alice_key_id}:\n{log}"
    );
}

/// RNP (its default RSA key) → Sealbox: Thunderbird user writes to a Sealbox user.
#[test]
#[ignore = "needs /usr/bin/rnp (gate G1 runs it)"]
fn sealbox_decrypts_and_verifies_an_rnp_message() {
    require_tools();
    let bob = bob();
    let rnp = Rnp::new("rnp-to-sealbox");
    let plaintext = format!("hello Sealbox from RNP, nonce {}\n", std::process::id());

    rnp.generate("RNP Peer <rnp-peer@sealbox.test>");
    let bob_pub = rnp
        .home
        .write("bob-pub.asc", bob.public().to_armored().unwrap());
    rnp.import(&bob_pub);
    let peer_pub_file = rnp.home.path("rnp-peer-pub.asc");
    rnp.export_public("rnp-peer@sealbox.test", &peer_pub_file);
    let peer_pub =
        PublicKey::from_armored(&String::from_utf8(rnp.home.read("rnp-peer-pub.asc")).unwrap())
            .expect("parse RNP's public key");

    let input = rnp.home.write("plain.txt", &plaintext);
    let cipher = rnp.home.path("rnp-to-bob.asc");
    rnp.encrypt_and_sign("bob@sealbox.test", "rnp-peer@sealbox.test", &input, &cipher);

    let d = decrypt_and_verify(&rnp.home.read("rnp-to-bob.asc"), &[&bob], &[&peer_pub])
        .expect("Sealbox decrypts RNP's message");
    assert_eq!(d.plaintext, plaintext.as_bytes());
    assert_good_from(&d, &peer_pub.fingerprint());

    // Unknown signer → reported as such, never as Good.
    let d2 = decrypt_and_verify(&rnp.home.read("rnp-to-bob.asc"), &[&bob], &[]).unwrap();
    assert!(!d2.signed_by_known_key());
    assert!(
        matches!(
            d2.signatures.as_slice(),
            [SignatureStatus::UnknownKey { .. }]
        ),
        "{:?}",
        d2.signatures
    );
}

// ---- cases: Sequoia --------------------------------------------------------------------------

/// Sealbox (Alice) → sq's key, read by sq with Alice's cert as the required signer.
#[test]
#[ignore = "needs /usr/bin/sq (gate G1 runs it)"]
fn sequoia_decrypts_and_verifies_a_sealbox_message() {
    require_tools();
    let alice = alice();
    let sq = Sq::new("sealbox-to-sq");
    let plaintext = format!("hello Sequoia, nonce {}\n", std::process::id());

    let (sq_key, sq_cert) = sq.generate("SQ Peer", "sq-peer@sealbox.test");
    let sq_pub =
        PublicKey::from_armored(&String::from_utf8(std::fs::read(&sq_cert).unwrap()).unwrap())
            .expect("parse sq's cert");
    let armored = encrypt_and_sign_armored(
        plaintext.as_bytes(),
        &[&sq_pub, &alice.public()],
        Some(&alice),
    )
    .unwrap();
    let msg = sq.home.write("msg.asc", &armored);
    let alice_pub = sq
        .home
        .write("alice-pub.asc", alice.public().to_armored().unwrap());

    let out = sq.home.path("out.txt");
    let res = sq.decrypt(&sq_key, &alice_pub, &msg, &out);
    let log = stderr_of(&res);
    assert!(res.status.success(), "sq decrypt failed:\n{log}");
    assert_eq!(
        sq.home.read("out.txt"),
        plaintext.as_bytes(),
        "plaintext differs"
    );
    let alice_fpr = alice.public().fingerprint().to_ascii_uppercase();
    assert!(
        log.to_ascii_uppercase()
            .contains(&format!("AUTHENTICATED SIGNATURE MADE BY {alice_fpr}")),
        "sq did not authenticate Alice's signature:\n{log}"
    );
    // sq separates digit and word with a non-breaking space in some builds; match loosely.
    let flat: String = log
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    assert!(
        flat.contains("1 authenticated signature"),
        "sq did not count exactly one authenticated signature:\n{log}"
    );

    // With the wrong signer cert sq must refuse (it requires one authenticated signature).
    let other = sq
        .home
        .write("other-pub.asc", bob().public().to_armored().unwrap());
    let res = sq.decrypt(&sq_key, &other, &msg, &sq.home.path("out2.txt"));
    assert!(
        !res.status.success(),
        "sq accepted a message without the required signer"
    );
}

/// sq → Sealbox (Bob): Sealbox decrypts and attributes the signature to sq's cert.
#[test]
#[ignore = "needs /usr/bin/sq (gate G1 runs it)"]
fn sealbox_decrypts_and_verifies_a_sequoia_message() {
    require_tools();
    let bob = bob();
    let sq = Sq::new("sq-to-sealbox");
    let plaintext = format!("hello Sealbox from Sequoia, nonce {}\n", std::process::id());

    let (sq_key, sq_cert) = sq.generate("SQ Peer", "sq-peer@sealbox.test");
    let sq_pub =
        PublicKey::from_armored(&String::from_utf8(std::fs::read(&sq_cert).unwrap()).unwrap())
            .expect("parse sq's cert");
    let bob_pub = sq
        .home
        .write("bob-pub.asc", bob.public().to_armored().unwrap());
    let input = sq.home.write("plain.txt", &plaintext);
    let cipher = sq.home.path("sq-to-bob.asc");
    sq.encrypt_and_sign(&bob_pub, &sq_key, &input, &cipher);

    let d = decrypt_and_verify(&sq.home.read("sq-to-bob.asc"), &[&bob], &[&sq_pub])
        .expect("Sealbox decrypts sq's message");
    assert_eq!(d.plaintext, plaintext.as_bytes());
    assert_good_from(&d, &sq_pub.fingerprint());

    // Tampering with the ciphertext must be an integrity failure, not partial plaintext.
    // Flip a base64 character near the END of the armored body: that is inside the
    // encrypted-data packet (the session-key packets come first), so decryption proceeds
    // and the MDC / AEAD check must catch it.
    let mut tampered = sq.home.read("sq-to-bob.asc");
    let end = tampered
        .windows(2)
        .position(|w| w == b"\n=")
        .or_else(|| tampered.windows(10).position(|w| w == b"\n-----END "))
        .expect("armor tail");
    let idx = end - 30;
    tampered[idx] = if tampered[idx] == b'A' { b'B' } else { b'A' };
    let err = decrypt_and_verify(&tampered, &[&bob], &[&sq_pub]).expect_err("tampered message");
    assert!(
        matches!(err, Error::IntegrityFailure | Error::Corrupt(_)),
        "unexpected error for tampered ciphertext: {err:?}"
    );
}

// ---- cases: Autocrypt Setup Message (key transfer to / from Thunderbird) --------------------

/// Thunderbird imports an Autocrypt Setup Message by decrypting it with the setup code in RNP.
/// RNP must open ours with the code alone and the payload must be the account's secret key,
/// which RNP then accepts into its keyring.
#[test]
#[ignore = "needs /usr/bin/rnp (gate G1 runs it)"]
fn rnp_opens_a_sealbox_setup_message_with_the_setup_code() {
    require_tools();
    let alice = alice();
    let rnp = Rnp::new("setup-sealbox-to-rnp");
    let code = setup_code_generate();
    let armored = setup_message_create(&alice, &code).unwrap();
    assert!(
        armored.contains("Passphrase-Format: numeric9x4"),
        "{armored}"
    );
    let msg = rnp.home.write("setup.asc", &armored);

    // Wrong code: refused, nothing written.
    let wrong = "0000-0000-0000-0000-0000-0000-0000-0000-0000";
    let res = rnp.decrypt_with_password(wrong, &msg, &rnp.home.path("wrong.asc"));
    assert!(
        !res.status.success(),
        "rnp opened the setup message with a wrong code"
    );

    let out = rnp.home.path("inner.asc");
    let res = rnp.decrypt_with_password(&code, &msg, &out);
    assert!(
        res.status.success(),
        "rnp --decrypt --password failed:\n{}",
        stderr_of(&res)
    );
    let inner = String::from_utf8(rnp.home.read("inner.asc")).unwrap();
    assert!(
        inner.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        "{inner}"
    );
    assert!(
        inner.contains("Autocrypt-Prefer-Encrypt: mutual"),
        "{inner}"
    );
    let recovered = Identity::from_armored_secret(&inner, None).unwrap();
    assert_eq!(recovered.fingerprint(), alice.fingerprint());

    rnp.import(&out);
    let listing = rnp.list_secret_keys().to_ascii_lowercase();
    assert!(
        listing.contains(&alice.fingerprint().to_ascii_lowercase()),
        "RNP keyring does not list Alice's secret key:\n{listing}"
    );
}

/// The reverse transfer: a setup message produced by RNP's symmetric encryption (what a
/// Thunderbird-side export amounts to) opens in Sealbox with the same code, text around the
/// armor and all.
#[test]
#[ignore = "needs /usr/bin/rnp (gate G1 runs it)"]
fn sealbox_opens_an_rnp_made_setup_message() {
    require_tools();
    let alice = alice();
    let rnp = Rnp::new("setup-rnp-to-sealbox");
    let code = setup_code_generate();
    let inner = rnp
        .home
        .write("inner.asc", alice.to_armored_secret(None).unwrap());
    let setup = rnp.home.path("setup.asc");
    rnp.symmetric_encrypt(&code, &inner, &setup);
    let body = format!(
        "This is the Autocrypt Setup Message.\r\n\r\n{}\r\n-- \r\nsent by RNP\r\n",
        String::from_utf8(rnp.home.read("setup.asc")).unwrap()
    );
    let recovered = setup_message_open(&body, &code).expect("open RNP-made setup message");
    assert_eq!(recovered.fingerprint(), alice.fingerprint());
    assert!(setup_message_open(&body, "1111-1111-1111-1111-1111-1111-1111-1111-1111").is_err());
}
