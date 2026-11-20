//! Recipient resolution and the send policy. Pure functions, unit tested without I/O.

use chrono::{DateTime, Utc};
use sealbox_crypto::{recommendation, PeerState, PreferEncrypt, PublicKey, Recommendation};

use crate::error::{Error, Result};
use crate::types::{KeySource, RecipientStatus, SendMode, SendPolicy};

/// A key from the `keys` table (imported or directory) with its import time.
#[derive(Clone, Debug)]
pub(crate) struct ExtraKey {
    pub source: KeySource,
    pub key: PublicKey,
    pub imported_at: DateTime<Utc>,
}

/// A recipient resolved to a key (or not).
#[derive(Clone, Debug)]
pub(crate) struct ResolvedRecipient {
    pub status: RecipientStatus,
    /// The key we would encrypt to.
    pub key: Option<PublicKey>,
}

/// Resolve one recipient from the available evidence, in order of preference:
/// one of our own accounts → an explicitly imported key that is newer than the peer's last
/// Autocrypt header → Autocrypt peer state (announced key, then gossip) → older imported
/// keys → directory keys. `reply_to_encrypted` applies the Level 1 rule that a reply to an
/// encrypted message defaults to encryption.
pub(crate) fn resolve(
    address: &str,
    own: Option<&PublicKey>,
    peer: Option<&PeerState>,
    extra_keys: &[ExtraKey],
    reply_to_encrypted: bool,
) -> ResolvedRecipient {
    let address = address.trim().to_string();
    if let Some(k) = own {
        return ResolvedRecipient {
            status: RecipientStatus {
                address,
                recommendation: Recommendation::Encrypt,
                fingerprint: Some(k.fingerprint()),
                source: KeySource::Own,
            },
            key: Some(k.clone()),
        };
    }
    // "Newest evidence wins": a `key import` done after the peer's last Autocrypt header
    // beats it; a later Autocrypt header from the peer takes over again.
    let announced_at = peer.and_then(|p| p.public_key().map(|_| p.autocrypt_timestamp));
    if let Some(ek) = extra_keys
        .iter()
        .filter(|e| e.source == KeySource::Imported && e.key.encryption_capable())
        .find(|e| match announced_at {
            Some(Some(at)) => e.imported_at > at,
            _ => true,
        })
    {
        let rec = if reply_to_encrypted
            || peer.is_some_and(|p| p.prefer_encrypt == PreferEncrypt::Mutual)
        {
            Recommendation::Encrypt
        } else {
            Recommendation::Available
        };
        return ResolvedRecipient {
            status: RecipientStatus {
                address,
                recommendation: rec,
                fingerprint: Some(ek.key.fingerprint()),
                source: KeySource::Imported,
            },
            key: Some(ek.key.clone()),
        };
    }
    if let Some(p) = peer {
        let rec = recommendation(p, reply_to_encrypted);
        if rec != Recommendation::Disable {
            let (key, source) = match p.public_key() {
                Some(k) => (Some(k), KeySource::Autocrypt),
                None => (p.gossip_public_key(), KeySource::Gossip),
            };
            if let Some(k) = key {
                return ResolvedRecipient {
                    status: RecipientStatus {
                        address,
                        recommendation: rec,
                        fingerprint: Some(k.fingerprint()),
                        source,
                    },
                    key: Some(k),
                };
            }
        }
    }
    if let Some(ek) = extra_keys.iter().find(|e| e.key.encryption_capable()) {
        let rec = if reply_to_encrypted {
            Recommendation::Encrypt
        } else {
            Recommendation::Available
        };
        return ResolvedRecipient {
            status: RecipientStatus {
                address,
                recommendation: rec,
                fingerprint: Some(ek.key.fingerprint()),
                source: ek.source,
            },
            key: Some(ek.key.clone()),
        };
    }
    ResolvedRecipient {
        status: RecipientStatus {
            address,
            recommendation: Recommendation::Disable,
            fingerprint: None,
            source: KeySource::None,
        },
        key: None,
    }
}

/// Recipients that cannot be encrypted to.
pub fn missing_keys(recipients: &[RecipientStatus]) -> Vec<String> {
    recipients
        .iter()
        .filter(|r| !r.has_key())
        .map(|r| r.address.clone())
        .collect()
}

/// Decide how a message goes out. Never downgrades silently: `Auto` and `RequireEncryption`
/// refuse with [`Error::RecipientsWithoutKeys`] when anybody lacks a key; `GuestLink` falls
/// back to a guest link for the whole message; `AllowPlaintext` always sends plaintext.
pub fn decide(policy: SendPolicy, recipients: &[RecipientStatus]) -> Result<SendMode> {
    if recipients.is_empty() {
        return Err(Error::InvalidInput("no recipients".into()));
    }
    let missing = missing_keys(recipients);
    match policy {
        SendPolicy::Auto | SendPolicy::RequireEncryption => {
            if missing.is_empty() {
                Ok(SendMode::Encrypted)
            } else {
                Err(Error::RecipientsWithoutKeys { missing })
            }
        }
        SendPolicy::GuestLink => {
            if missing.is_empty() {
                Ok(SendMode::Encrypted)
            } else {
                Ok(SendMode::GuestLink)
            }
        }
        SendPolicy::AllowPlaintext => Ok(SendMode::Plaintext),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};
    use sealbox_crypto::{AutocryptGossip, AutocryptHeader, Identity};

    fn status(addr: &str, key: bool) -> RecipientStatus {
        RecipientStatus {
            address: addr.into(),
            recommendation: if key {
                Recommendation::Available
            } else {
                Recommendation::Disable
            },
            fingerprint: key.then(|| "FP".to_string()),
            source: if key {
                KeySource::Autocrypt
            } else {
                KeySource::None
            },
        }
    }

    fn extra(source: KeySource, key: PublicKey, at: DateTime<Utc>) -> ExtraKey {
        ExtraKey {
            source,
            key,
            imported_at: at,
        }
    }

    #[test]
    fn all_keys_encrypt_any_missing_refuses() {
        let all = [status("a@x", true), status("b@x", true)];
        let some = [status("a@x", true), status("c@x", false)];
        assert_eq!(decide(SendPolicy::Auto, &all).unwrap(), SendMode::Encrypted);
        assert_eq!(
            decide(SendPolicy::RequireEncryption, &all).unwrap(),
            SendMode::Encrypted
        );
        for p in [SendPolicy::Auto, SendPolicy::RequireEncryption] {
            match decide(p, &some) {
                Err(Error::RecipientsWithoutKeys { missing }) => {
                    assert_eq!(missing, vec!["c@x".to_string()])
                }
                other => panic!("expected refusal, got {other:?}"),
            }
        }
        assert_eq!(
            decide(SendPolicy::AllowPlaintext, &some).unwrap(),
            SendMode::Plaintext
        );
        assert_eq!(
            decide(SendPolicy::AllowPlaintext, &all).unwrap(),
            SendMode::Plaintext
        );
        assert_eq!(
            decide(SendPolicy::GuestLink, &some).unwrap(),
            SendMode::GuestLink
        );
        assert_eq!(
            decide(SendPolicy::GuestLink, &all).unwrap(),
            SendMode::Encrypted
        );
        assert!(matches!(
            decide(SendPolicy::Auto, &[]),
            Err(Error::InvalidInput(_))
        ));
        let err = decide(SendPolicy::Auto, &some).unwrap_err();
        assert!(err.is_policy_refusal());
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn reply_to_encrypted_raises_available_to_encrypt() {
        let bob = Identity::generate("Bob", "bob@example.org").unwrap();
        let header =
            AutocryptHeader::for_identity(&bob, None, PreferEncrypt::NoPreference).unwrap();
        let t0 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut peer = PeerState::new("bob@example.org");
        peer.update_from_header(Some(&header), t0);

        let plain = resolve("bob@example.org", None, Some(&peer), &[], false);
        assert_eq!(plain.status.recommendation, Recommendation::Available);
        assert_eq!(plain.status.source, KeySource::Autocrypt);
        assert_eq!(
            plain.status.fingerprint.as_deref(),
            Some(bob.fingerprint().as_str())
        );
        let reply = resolve("bob@example.org", None, Some(&peer), &[], true);
        assert_eq!(reply.status.recommendation, Recommendation::Encrypt);
        assert!(reply.key.is_some());

        // mutual + mutual → Encrypt even without a reply
        let mutual = AutocryptHeader::for_identity(&bob, None, PreferEncrypt::Mutual).unwrap();
        peer.update_from_header(Some(&mutual), t0 + Duration::days(1));
        assert_eq!(
            resolve("bob@example.org", None, Some(&peer), &[], false)
                .status
                .recommendation,
            Recommendation::Encrypt
        );

        // gossip only → Discourage, still usable
        let carol = Identity::generate("Carol", "carol@example.org").unwrap();
        let mut gp = PeerState::new("carol@example.org");
        gp.update_from_gossip(
            &AutocryptGossip::new("carol@example.org", &carol.public()).unwrap(),
            t0,
        );
        let g = resolve("carol@example.org", None, Some(&gp), &[], false);
        assert_eq!(g.status.recommendation, Recommendation::Discourage);
        assert_eq!(g.status.source, KeySource::Gossip);
        assert!(g.status.has_key());

        // no evidence at all → Disable
        let none = resolve("dave@example.org", None, None, &[], true);
        assert_eq!(none.status.recommendation, Recommendation::Disable);
        assert!(!none.status.has_key());
        assert_eq!(none.status.source, KeySource::None);

        // imported key → Available (Encrypt when replying), own key → Own/Encrypt
        let imported = resolve(
            "dave@example.org",
            None,
            None,
            &[extra(KeySource::Imported, carol.public(), t0)],
            false,
        );
        assert_eq!(imported.status.recommendation, Recommendation::Available);
        assert_eq!(imported.status.source, KeySource::Imported);
        assert_eq!(
            resolve(
                "dave@example.org",
                None,
                None,
                &[extra(KeySource::Imported, carol.public(), t0)],
                true,
            )
            .status
            .recommendation,
            Recommendation::Encrypt
        );
        let own = resolve(
            "bob@example.org",
            Some(&bob.public()),
            Some(&peer),
            &[],
            false,
        );
        assert_eq!(own.status.source, KeySource::Own);
        assert_eq!(own.status.recommendation, Recommendation::Encrypt);
    }

    #[test]
    fn imported_key_precedence_is_newest_evidence_wins() {
        let bob = Identity::generate("Bob", "bob@example.org").unwrap();
        let bob2 = Identity::generate("Bob", "bob@example.org").unwrap();
        let t0 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut peer = PeerState::new("bob@example.org");
        peer.update_from_header(
            Some(&AutocryptHeader::for_identity(&bob, None, PreferEncrypt::Mutual).unwrap()),
            t0,
        );

        // An import newer than the Autocrypt header wins and inherits Encrypt from the
        // peer's prefer-encrypt=mutual.
        let newer = resolve(
            "bob@example.org",
            None,
            Some(&peer),
            &[extra(
                KeySource::Imported,
                bob2.public(),
                t0 + Duration::days(2),
            )],
            false,
        );
        assert_eq!(newer.status.source, KeySource::Imported);
        assert_eq!(
            newer.status.fingerprint.as_deref(),
            Some(bob2.fingerprint().as_str())
        );
        assert_eq!(newer.status.recommendation, Recommendation::Encrypt);

        // An older import loses to the Autocrypt key.
        let older = resolve(
            "bob@example.org",
            None,
            Some(&peer),
            &[extra(
                KeySource::Imported,
                bob2.public(),
                t0 - Duration::days(2),
            )],
            false,
        );
        assert_eq!(older.status.source, KeySource::Autocrypt);
        assert_eq!(
            older.status.fingerprint.as_deref(),
            Some(bob.fingerprint().as_str())
        );

        // A directory key never beats an Autocrypt key, but fills in when there is none.
        let dir = resolve(
            "bob@example.org",
            None,
            Some(&peer),
            &[extra(
                KeySource::Directory,
                bob2.public(),
                t0 + Duration::days(2),
            )],
            false,
        );
        assert_eq!(dir.status.source, KeySource::Autocrypt);
        let dir_only = resolve(
            "bob@example.org",
            None,
            None,
            &[extra(KeySource::Directory, bob2.public(), t0)],
            false,
        );
        assert_eq!(dir_only.status.source, KeySource::Directory);
        assert_eq!(dir_only.status.recommendation, Recommendation::Available);

        // Gossip-only peer: an import at any time wins over gossip.
        let carol = Identity::generate("Carol", "carol@example.org").unwrap();
        let carol2 = Identity::generate("Carol", "carol@example.org").unwrap();
        let mut gp = PeerState::new("carol@example.org");
        gp.update_from_gossip(
            &AutocryptGossip::new("carol@example.org", &carol.public()).unwrap(),
            t0 + Duration::days(5),
        );
        let g = resolve(
            "carol@example.org",
            None,
            Some(&gp),
            &[extra(KeySource::Imported, carol2.public(), t0)],
            false,
        );
        assert_eq!(g.status.source, KeySource::Imported);
        assert_eq!(
            g.status.fingerprint.as_deref(),
            Some(carol2.fingerprint().as_str())
        );
    }
}
