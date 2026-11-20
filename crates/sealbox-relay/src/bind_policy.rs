//! May the relay start on this listen address (R9)? An API token is mandatory as soon as the
//! API is reachable from beyond the host.
//!
//! | bind | API token | `--allow-open-relay` | outcome |
//! |---|---|---|---|
//! | any | set | any | start, every `/v1/push/*` call authenticated |
//! | loopback only | unset | any | start with a warning (development) |
//! | not loopback | unset | no | **refuse to start** |
//! | not loopback | unset | yes | start with a loud warning |
//!
//! "Loopback" means every address the bind resolves to is loopback (`127.0.0.0/8`, `::1`, or
//! their IPv4-mapped form). `0.0.0.0` and `::` are not loopback: they listen on every interface.

use std::net::SocketAddr;

/// How exposed the API will be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exposure {
    /// A token is configured.
    Authenticated,
    /// No token, but only loopback can reach the API.
    OpenLoopback,
    /// No token on a non-loopback bind, explicitly allowed with `--allow-open-relay`.
    OpenOverride,
}

/// Every address is loopback (and there is at least one).
pub fn is_loopback_only(addrs: &[SocketAddr]) -> bool {
    !addrs.is_empty() && addrs.iter().all(|a| a.ip().to_canonical().is_loopback())
}

/// Decide whether to start. `addrs` are what `--bind` resolved to; the error is the message
/// the binary exits with.
pub fn decide(
    addrs: &[SocketAddr],
    api_token_set: bool,
    allow_open_relay: bool,
) -> Result<Exposure, String> {
    if addrs.is_empty() {
        return Err("refusing to start: --bind resolved to no address".to_owned());
    }
    if api_token_set {
        return Ok(Exposure::Authenticated);
    }
    if is_loopback_only(addrs) {
        return Ok(Exposure::OpenLoopback);
    }
    if allow_open_relay {
        return Ok(Exposure::OpenOverride);
    }
    let list = addrs
        .iter()
        .map(SocketAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "refusing to start: --bind {list} is not a loopback address and no API token is set, \
         so anyone who can reach it could register mailboxes. Set SEALBOX_RELAY_API_TOKEN \
         (or --api-token), bind to 127.0.0.1, or pass --allow-open-relay to run an open relay \
         anyway"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|a| a.parse().expect("addr")).collect()
    }

    #[test]
    fn token_flag_and_bind_decide_start_or_refuse() {
        let loopback = addrs(&["127.0.0.1:8090"]);
        let loopback_both = addrs(&["127.0.0.1:8090", "[::1]:8090"]);
        let other_loopback = addrs(&["127.0.0.53:8090"]);
        let mapped = addrs(&["[::ffff:127.0.0.1]:8090"]);
        let any_v4 = addrs(&["0.0.0.0:8090"]);
        let any_v6 = addrs(&["[::]:8090"]);
        let lan = addrs(&["192.168.1.20:8090"]);
        let mixed = addrs(&["127.0.0.1:8090", "192.168.1.20:8090"]);

        for bind in [&loopback, &loopback_both, &other_loopback, &mapped] {
            assert_eq!(decide(bind, true, false), Ok(Exposure::Authenticated));
            assert_eq!(decide(bind, false, false), Ok(Exposure::OpenLoopback));
            assert_eq!(decide(bind, false, true), Ok(Exposure::OpenLoopback));
        }
        for bind in [&any_v4, &any_v6, &lan, &mixed] {
            assert_eq!(decide(bind, true, false), Ok(Exposure::Authenticated));
            assert_eq!(decide(bind, true, true), Ok(Exposure::Authenticated));
            assert_eq!(decide(bind, false, true), Ok(Exposure::OpenOverride));
            let err = decide(bind, false, false).expect_err("must refuse");
            assert!(err.starts_with("refusing to start"), "{err}");
            assert!(err.contains("--allow-open-relay"), "{err}");
            assert!(err.contains("SEALBOX_RELAY_API_TOKEN"), "{err}");
        }
        assert!(decide(&[], true, true).is_err());
        assert!(!is_loopback_only(&[]));
    }
}
