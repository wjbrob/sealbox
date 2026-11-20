//! Address and host-name classes for the relay's destination policies (threat-model R9).
//!
//! Two questions are answered here, both without touching the network:
//!
//! * [`classify`]: what kind of address is this (public, loopback, RFC 1918 …)? The webhook
//!   guard ([`crate::webhook_guard`]) asks it for every address a webhook host resolves to.
//! * [`plain_imap_allowed`]: may a registration use `security: "plain"` for this IMAP host?
//!   Decided on the literal host string only, never by DNS.
//!
//! `sealbox-mail` is getting an equivalent helper for the client side (R12) from another
//! workstream. The two are deliberately not shared yet; `docs/PUSH_RELAY.md` records the
//! duplication so they can be merged later. The plain-IMAP rule here accepts a subset of what
//! that client-side rule accepts (it has no `SEALBOX_ALLOW_PLAIN_HOSTS` override and refuses
//! scoped `fe80::1%eth0` literals), so a registration the relay accepts is never refused again
//! by the IMAP client.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What kind of destination an IP address is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpClass {
    /// Globally routable unicast.
    Public,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// RFC 1918: `10/8` (which holds the Android emulator's host alias `10.0.2.2`),
    /// `172.16/12`, `192.168/16`.
    Private,
    /// `169.254/16` (which holds the cloud metadata address `169.254.169.254`), `fe80::/10`.
    LinkLocal,
    /// `fc00::/7` (unique local addresses).
    UniqueLocal,
    /// `100.64/10`, RFC 6598 carrier-grade NAT space (Alibaba Cloud's metadata service is
    /// `100.100.100.200`).
    SharedAddressSpace,
    /// `224/4`, `ff00::/8`.
    Multicast,
    /// `0.0.0.0`, `::`. On Linux a connection to these reaches the local host.
    Unspecified,
    /// Not globally routable for another reason: `0/8`, `192.0.0/24`, the documentation and
    /// benchmarking ranges, `240/4` and broadcast, deprecated IPv6 forms (IPv4-compatible,
    /// site-local), `64:ff9b:1::/48`, `100::/64`, `2001::/23`, `2001:db8::/32`, `3fff::/20`,
    /// and everything outside `2000::/3`.
    Reserved,
}

impl IpClass {
    /// Globally routable unicast.
    pub fn is_public(self) -> bool {
        self == IpClass::Public
    }

    /// Loopback, RFC 1918, link-local or unique-local: the classes for which plain IMAP is
    /// accepted.
    pub fn is_local_network(self) -> bool {
        matches!(
            self,
            IpClass::Loopback | IpClass::Private | IpClass::LinkLocal | IpClass::UniqueLocal
        )
    }
}

/// Classify `ip`. IPv4-mapped IPv6 (`::ffff:a.b.c.d`), NAT64 (`64:ff9b::/96`) and 6to4
/// (`2002::/16`) addresses are classified by the IPv4 address they carry, because that address
/// is where a connection to them ends up.
pub fn classify(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> IpClass {
    let o = ip.octets();
    if ip.is_unspecified() {
        IpClass::Unspecified
    } else if ip.is_loopback() {
        IpClass::Loopback
    } else if ip.is_private() {
        IpClass::Private
    } else if ip.is_link_local() {
        IpClass::LinkLocal
    } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
        IpClass::SharedAddressSpace
    } else if ip.is_multicast() {
        IpClass::Multicast
    } else if o[0] == 0
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || ip.is_documentation()
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        || o[0] >= 240
    {
        // 0/8, 192.0.0/24, TEST-NET-1/2/3, 198.18/15, the deprecated 6to4 relay anycast
        // 192.88.99/24, and 240/4 including 255.255.255.255.
        IpClass::Reserved
    } else {
        IpClass::Public
    }
}

fn v4_from_segments(hi: u16, lo: u16) -> Ipv4Addr {
    let [a, b] = hi.to_be_bytes();
    let [c, d] = lo.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

fn classify_v6(ip: Ipv6Addr) -> IpClass {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let s = ip.segments();
    if ip.is_unspecified() {
        IpClass::Unspecified
    } else if ip.is_loopback() {
        IpClass::Loopback
    } else if (s[0] & 0xffc0) == 0xfe80 {
        IpClass::LinkLocal
    } else if (s[0] & 0xfe00) == 0xfc00 {
        IpClass::UniqueLocal
    } else if (s[0] & 0xff00) == 0xff00 {
        IpClass::Multicast
    } else if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        // NAT64 well-known prefix: the gateway connects to the embedded IPv4 address.
        classify_v4(v4_from_segments(s[6], s[7]))
    } else if s[0] == 0x2002 {
        // 6to4: the embedded IPv4 address is the tunnel endpoint.
        classify_v4(v4_from_segments(s[1], s[2]))
    } else if (s[0] & 0xffc0) == 0xfec0
        || s[0..6] == [0, 0, 0, 0, 0, 0]
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001)
        || (s[0] == 0x0100 && s[1..4] == [0, 0, 0])
        || (s[0] == 0x2001 && s[1] < 0x0200)
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x3fff && s[1] < 0x1000)
        || (s[0] & 0xe000) != 0x2000
    {
        // Site-local, IPv4-compatible, local-use NAT64, discard-only, IETF protocol
        // assignments (Teredo, ORCHID …), documentation, and anything outside 2000::/3.
        IpClass::Reserved
    } else {
        IpClass::Public
    }
}

/// Top-level labels whose names never belong to a public mail provider: RFC 6761 special-use
/// names (`test`, `localhost`, `invalid`), mDNS `local`, the ICANN private-use `internal` and
/// the customary home-router `lan` / `home`. The same list as `sealbox-mail`'s client-side
/// policy, so a host the relay accepts for plain IMAP is one its IMAP client accepts too.
pub const LOCAL_TLDS: &[&str] = &[
    "test",
    "local",
    "localhost",
    "internal",
    "lan",
    "home",
    "invalid",
];

/// Is `name` local by its spelling: `localhost`, or a name with at least one label in front
/// of one of [`LOCAL_TLDS`] (`mail.sealbox.test` is, `mailtest`, bare `test` and
/// `test.example.com` are not)? Case-insensitive; one trailing dot is ignored. Every label must
/// be 1–63 characters of `[A-Za-z0-9_-]`, otherwise the name is not local.
pub fn is_local_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let labels: Vec<&str> = name.split('.').collect();
    let well_formed = !name.is_empty()
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if !well_formed {
        return false;
    }
    match labels.as_slice() {
        [.., "localhost"] => true,
        // A bare special label (`test`) would be completed with the resolver's search domains.
        [_, .., tld] => LOCAL_TLDS.contains(tld),
        _ => false,
    }
}

/// Parse `host` as an IP literal (`192.0.2.1`, `::1`, `[::1]`). Only the strict textual forms
/// count: `127.1` or `2130706433` are names here, which keeps every decision on the safe side
/// (such a host is never considered local).
pub fn ip_literal(host: &str) -> Option<IpAddr> {
    let inner = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    inner.parse().ok()
}

/// May a registration use `security: "plain"` (no TLS, credentials in clear) for this IMAP
/// host? Only when the host is local by its literal form: a loopback, RFC 1918, link-local or
/// unique-local address (IPv4-mapped forms included), or a local name ([`is_local_name`]).
/// No DNS is involved, so a public name never qualifies, whatever it resolves to.
pub fn plain_imap_allowed(host: &str) -> bool {
    let host = host.trim();
    match ip_literal(host) {
        Some(ip) => classify(ip).is_local_network(),
        None => is_local_name(host),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(s: &str) -> IpClass {
        classify(s.parse().expect("ip"))
    }

    #[test]
    fn ipv4_classes() {
        for (ip, want) in [
            ("8.8.8.8", IpClass::Public),
            ("93.184.216.34", IpClass::Public),
            ("100.63.255.255", IpClass::Public),
            ("100.128.0.0", IpClass::Public),
            ("172.15.255.255", IpClass::Public),
            ("172.32.0.0", IpClass::Public),
            ("127.0.0.1", IpClass::Loopback),
            ("127.255.255.254", IpClass::Loopback),
            ("10.0.0.1", IpClass::Private),
            ("10.0.2.2", IpClass::Private),
            ("172.16.0.1", IpClass::Private),
            ("172.31.255.255", IpClass::Private),
            ("192.168.1.10", IpClass::Private),
            ("169.254.169.254", IpClass::LinkLocal),
            ("169.254.0.1", IpClass::LinkLocal),
            ("100.64.0.1", IpClass::SharedAddressSpace),
            ("100.100.100.200", IpClass::SharedAddressSpace),
            ("224.0.0.1", IpClass::Multicast),
            ("239.255.255.250", IpClass::Multicast),
            ("0.0.0.0", IpClass::Unspecified),
            ("0.1.2.3", IpClass::Reserved),
            ("192.0.0.170", IpClass::Reserved),
            ("192.0.2.1", IpClass::Reserved),
            ("198.18.0.1", IpClass::Reserved),
            ("198.19.255.255", IpClass::Reserved),
            ("198.51.100.7", IpClass::Reserved),
            ("203.0.113.9", IpClass::Reserved),
            ("192.88.99.1", IpClass::Reserved),
            ("240.0.0.1", IpClass::Reserved),
            ("255.255.255.255", IpClass::Reserved),
        ] {
            assert_eq!(class(ip), want, "{ip}");
        }
    }

    #[test]
    fn ipv6_classes_including_embedded_ipv4() {
        for (ip, want) in [
            ("2606:4700:4700::1111", IpClass::Public),
            ("2a00:1450:4001:80b::200e", IpClass::Public),
            ("::1", IpClass::Loopback),
            ("::", IpClass::Unspecified),
            ("fe80::1", IpClass::LinkLocal),
            ("febf::1", IpClass::LinkLocal),
            ("fc00::1", IpClass::UniqueLocal),
            ("fd12:3456:789a::1", IpClass::UniqueLocal),
            ("ff02::1", IpClass::Multicast),
            // IPv4-mapped: the IPv4 address decides.
            ("::ffff:127.0.0.1", IpClass::Loopback),
            ("::ffff:169.254.169.254", IpClass::LinkLocal),
            ("::ffff:10.1.2.3", IpClass::Private),
            ("::ffff:8.8.8.8", IpClass::Public),
            // NAT64 and 6to4 carry the IPv4 destination.
            ("64:ff9b::a9fe:a9fe", IpClass::LinkLocal),
            ("64:ff9b::7f00:1", IpClass::Loopback),
            ("64:ff9b::808:808", IpClass::Public),
            ("2002:c0a8:0101::1", IpClass::Private),
            ("2002:0808:0808::1", IpClass::Public),
            // Deprecated / special.
            ("::127.0.0.1", IpClass::Reserved),
            ("fec0::1", IpClass::Reserved),
            ("64:ff9b:1::1", IpClass::Reserved),
            ("100::1", IpClass::Reserved),
            ("2001::1", IpClass::Reserved),
            ("2001:db8::1", IpClass::Reserved),
            ("3fff::1", IpClass::Reserved),
            ("4000::1", IpClass::Reserved),
        ] {
            assert_eq!(class(ip), want, "{ip}");
        }
    }

    #[test]
    fn local_names_need_a_domain_boundary() {
        for name in [
            "localhost",
            "LOCALHOST",
            "localhost.",
            "imap.localhost",
            "sealbox.test",
            "mail.sealbox.test",
            "Mail.Sealbox.TEST.",
            "nas.local",
            "imap.corp.internal",
            "router.lan",
            "box.home",
            "nothing.invalid",
            "x_y-z.test",
        ] {
            assert!(is_local_name(name), "{name}");
        }
        for name in [
            "",
            ".",
            "test",
            "local",
            "mailtest",
            "sealboxtest",
            "test.example.com",
            "imap.gmail.com",
            "local.example.org",
            "evil-localhost",
            "localhost.evil.com",
            ".test",
            "a..test",
            "home.arpa",
            "box.home.arpa",
            "mail!.test",
            "mail .test",
        ] {
            assert!(!is_local_name(name), "{name}");
        }
    }

    #[test]
    fn plain_imap_only_for_local_literal_hosts() {
        for host in [
            "127.0.0.1",
            "127.0.0.53",
            "::1",
            "[::1]",
            "::ffff:127.0.0.1",
            "10.0.2.2",
            "10.1.2.3",
            "172.20.0.5",
            "192.168.1.10",
            "169.254.10.20",
            "fe80::1",
            "fd00::25",
            "localhost",
            "mail.sealbox.test",
            "greenmail.internal",
            " 127.0.0.1 ",
        ] {
            assert!(plain_imap_allowed(host), "{host}");
        }
        for host in [
            "imap.gmail.com",
            "outlook.office365.com",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "100.64.0.1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            // Not strict IP literals: treated as names, and not local ones.
            "127.1",
            "2130706433",
            "0x7f000001",
            "127.0.0.1.nip.io",
            "fe80::1%eth0",
            "",
        ] {
            assert!(!plain_imap_allowed(host), "{host}");
        }
    }
}
