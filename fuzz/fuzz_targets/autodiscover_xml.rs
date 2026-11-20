//! Fuzz target `autodiscover_xml`: the Mozilla autoconfig (`clientConfig` v1.1) parser,
//! `sealbox_mail::autodiscover::parse_autoconfig_xml` — fed by the ISPDB and by
//! `https://autoconfig.<domain>/…` / `.well-known` responses during account setup (the latter
//! are controlled by whoever controls the domain or its web server). The real fetch path
//! rejects non-UTF-8 bodies; here invalid bytes are replaced so every input reaches the parser.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sealbox_fuzz::AUTOCONFIG_DOMAIN;
use sealbox_mail::autodiscover::parse_autoconfig_xml;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = parse_autoconfig_xml(&text, AUTOCONFIG_DOMAIN);
});
