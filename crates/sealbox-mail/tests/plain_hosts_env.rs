//! `SEALBOX_ALLOW_PLAIN_HOSTS` through the real, read-once environment path. This file holds a
//! single test so it owns its process: the variable is set before anything in `sealbox-mail`
//! reads it (the policy reads it once, on first use).

use sealbox_mail::net_policy::{
    self, allowed_plain_hosts, check_transport, PlainAllowance, ENV_ALLOW_PLAIN_HOSTS,
};
use sealbox_mail::smtp::SmtpClient;
use sealbox_mail::{Security, SmtpError, TransportPolicyError};

#[test]
fn override_hosts_are_read_once_and_matched_exactly() {
    std::env::set_var(
        ENV_ALLOW_PLAIN_HOSTS,
        " Lab-Mail.Example.COM. ,192.0.2.25,, [2001:db8::25]",
    );

    // Listed hosts: allowed, whatever the case / trailing dot / brackets.
    for host in [
        "lab-mail.example.com",
        "LAB-MAIL.EXAMPLE.COM",
        "lab-mail.example.com.",
        "192.0.2.25",
        "2001:db8::25",
        "[2001:db8::25]",
    ] {
        check_transport(host, 143, Security::Plain).unwrap_or_else(|e| panic!("{host}: {e}"));
        assert_eq!(
            net_policy::plain_allowance(host),
            Some(PlainAllowance::Override),
            "{host}"
        );
    }
    assert_eq!(
        allowed_plain_hosts(),
        ["lab-mail.example.com", "192.0.2.25", "2001:db8::25"]
    );

    // Exact match only: no subdomain, parent or neighbour.
    for host in [
        "x.lab-mail.example.com",
        "example.com",
        "lab-mail.example.org",
        "192.0.2.26",
    ] {
        assert_eq!(
            check_transport(host, 143, Security::Plain),
            Err(TransportPolicyError::InsecureTransportRefused {
                host: host.into(),
                port: 143
            }),
            "{host}"
        );
    }

    // The SMTP client (lazy: nothing is dialled here) follows the same list.
    SmtpClient::connect("lab-mail.example.com", 25, Security::Plain, None).expect("listed host");
    let err =
        SmtpClient::connect("smtp.example.com", 25, Security::Plain, None).expect_err("not listed");
    assert!(matches!(err, SmtpError::Policy(_)), "{err:?}");

    // Read once: changing the variable later has no effect in this process.
    std::env::set_var(ENV_ALLOW_PLAIN_HOSTS, "smtp.example.com");
    assert!(check_transport("smtp.example.com", 25, Security::Plain).is_err());
    check_transport("lab-mail.example.com", 25, Security::Plain).expect("still the first list");

    // Local hosts never needed the list.
    check_transport("127.0.0.1", 3143, Security::Plain).expect("loopback");
    assert!(matches!(
        net_policy::plain_allowance("10.0.2.2"),
        Some(PlainAllowance::Local(_))
    ));
}
