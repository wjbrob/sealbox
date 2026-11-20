//! Loopback simulators that imitate one named mail provider — IMAP, submission and an OAuth2
//! identity provider sharing one mailbox, so a conformance run can exercise the quirks in
//! `providers.rs` without a real account.
//!
//! Start one with [`ProviderSim::start`]:
//!
//! ```no_run
//! # use sealbox_core::providers::ProviderId;
//! # use sealbox_fakeprov::ProviderSim;
//! # async fn demo() {
//! let sim = ProviderSim::start(ProviderId::Gmail).await.unwrap();
//! sim.seed_inbox(5);
//! // sim.imap_port / sim.smtp_port / sim.idp.auth_url() point a client at it.
//! # }
//! ```
//!
//! The honest limit, stated once here because it governs how the results may be reported: **a
//! simulator encodes our beliefs.** A conformance run that passes against it proves the engine
//! handles what `providers.rs` claims a provider does — not that the claim is true. Only a real
//! account can do that, and for Yahoo there will never be one.
pub mod idp;
pub mod imap;
pub mod quirks;
pub mod smtp;
pub mod state;

use std::sync::{Arc, Mutex};

use sealbox_core::providers::ProviderId;

pub use quirks::{Quirks, SimAuth, SimFolder};
pub use state::{Shared, SimMailbox, SimMessage, SimState};

/// One running fake provider: IMAP, submission and an identity provider over one mailbox.
pub struct ProviderSim {
    pub state: Shared,
    pub imap_port: u16,
    pub smtp_port: u16,
    pub idp: idp::MockIdp,
}

impl ProviderSim {
    /// Start a fake of `id` with its profile's quirks.
    pub async fn start(id: ProviderId) -> std::io::Result<Self> {
        Self::start_with(Quirks::for_provider(id)).await
    }

    /// Start a fake with quirks a caller has adjusted.
    pub async fn start_with(quirks: Quirks) -> std::io::Result<Self> {
        let state: Shared = Arc::new(Mutex::new(SimState::new(quirks)));
        let imap_port = imap::start(state.clone()).await?;
        let smtp_port = smtp::start(state.clone()).await?;
        let idp = idp::start(state.clone()).await?;
        Ok(Self {
            state,
            imap_port,
            smtp_port,
            idp,
        })
    }

    /// Put `n` messages in INBOX and return their UIDs.
    pub fn seed_inbox(&self, n: u32) -> Vec<u32> {
        self.state.lock().unwrap().seed("INBOX", n)
    }

    /// The provider being imitated.
    pub fn id(&self) -> ProviderId {
        self.state.lock().unwrap().quirks.id
    }

    /// Accept this access token on IMAP and submission without running the OAuth flow, for a
    /// test that is not about the flow.
    pub fn grant_token(&self, token: &str) {
        imap::grant_token(&self.state, token);
    }

    /// How many messages a folder holds.
    pub fn count(&self, folder: &str) -> usize {
        self.state.lock().unwrap().count(folder)
    }

    /// Every IMAP command the client sent, in order.
    pub fn imap_commands(&self) -> Vec<String> {
        self.state.lock().unwrap().imap_commands()
    }
}
