//! Small text / network helpers shared by the feature extractor and the rules:
//! stable token hashing, tokenisation, HTML stripping, URL and IP extraction, domain
//! helpers, confusable-character skeletons and edit distance.

use std::net::{IpAddr, Ipv4Addr};

/// FNV-1a 64-bit — a stable hash (unlike `SipHash` with random keys) so persisted models
/// keep meaning across processes and versions.
pub fn fnv1a64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Remove header folding and collapse whitespace runs to one space.
pub fn unfold(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut space = false;
    for c in raw.chars() {
        if c.is_whitespace() {
            space = true;
        } else {
            if space && !out.is_empty() {
                out.push(' ');
            }
            space = false;
            out.push(c);
        }
    }
    out
}

/// Lower-cased word tokens. Letters, digits, `'`, `$` and inner `-`/`.` form words;
/// pure numbers collapse to `#num`; tokens shorter than 2 or longer than 25 chars are dropped.
pub fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        let t = cur.trim_matches(|c: char| c == '-' || c == '.' || c == '\'');
        if !t.is_empty() {
            let n = t.chars().count();
            if (2..=25).contains(&n) {
                if t.chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == ',')
                {
                    out.push("#num".to_string());
                } else {
                    out.push(t.to_lowercase());
                }
            }
        }
        cur.clear();
    };
    for c in text.chars() {
        if c.is_alphanumeric() || c == '\'' || c == '$' || c == '-' || c == '.' || c == '_' {
            cur.push(c);
        } else {
            flush(&mut cur, &mut out);
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// What the HTML body looks like beyond its text: tricks spammers use to hide tokens from
/// filters or to show different text than the recipient reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HtmlTricks {
    /// `display:none`, `visibility:hidden` or white-on-white text.
    pub hidden_text: bool,
    /// `font-size:0` / `font-size:1px` / `<font size=0>`.
    pub tiny_font: bool,
    /// HTML comments splitting words (`vi<!-- x -->agra`).
    pub comment_obfuscation: u32,
    /// Images but (almost) no text.
    pub image_only: bool,
    /// Number of `<a href>` / `<img src>` links.
    pub links: u32,
}

/// Strip tags, scripts, styles and comments; decode the common entities; put a space where
/// block elements were. Also reports the tricks found on the way.
pub fn html_to_text(html: &str) -> (String, HtmlTricks) {
    let mut out = String::with_capacity(html.len());
    let mut tricks = HtmlTricks::default();
    let lower = html.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut i = 0;
    let mut skip_until: Option<&str> = None;
    let mut last_was_word = false;
    while i < bytes.len() {
        if let Some(end_tag) = skip_until {
            match lower[i..].find(end_tag) {
                Some(p) => {
                    i += p + end_tag.len();
                    skip_until = None;
                    continue;
                }
                None => break,
            }
        }
        if lower[i..].starts_with("<!--") {
            let end = lower[i..]
                .find("-->")
                .map(|p| i + p + 3)
                .unwrap_or(bytes.len());
            // A comment glued between word characters is an obfuscation trick.
            let next_is_word = html[end..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric());
            if last_was_word && next_is_word {
                tricks.comment_obfuscation += 1;
            }
            i = end;
            continue;
        }
        if bytes[i] == b'<' {
            let end = lower[i..]
                .find('>')
                .map(|p| i + p + 1)
                .unwrap_or(bytes.len());
            let tag = &lower[i + 1..end.saturating_sub(1).max(i + 1)];
            let name: String = tag
                .trim_start_matches('/')
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            if tag.starts_with("script") {
                skip_until = Some("</script>");
            } else if tag.starts_with("style") {
                skip_until = Some("</style>");
            }
            if !tag.starts_with('/') && (name == "a" || name == "img") {
                tricks.links += 1;
            }
            inspect_tag(tag, &mut tricks);
            // Inline formatting tags glue their text to the surroundings; everything else
            // is a word boundary.
            if !matches!(
                name.as_str(),
                "b" | "i"
                    | "u"
                    | "em"
                    | "strong"
                    | "font"
                    | "span"
                    | "sup"
                    | "sub"
                    | "small"
                    | "big"
                    | "tt"
                    | "s"
                    | "strike"
                    | "del"
                    | "ins"
                    | "mark"
                    | "abbr"
                    | "code"
            ) {
                out.push(' ');
            }
            last_was_word = false;
            i = end;
            continue;
        }
        if bytes[i] == b'&' {
            let end = lower[i..]
                .find(';')
                .map(|p| i + p + 1)
                .filter(|e| *e - i <= 10);
            if let Some(end) = end {
                let ent = &lower[i + 1..end - 1];
                let decoded = match ent {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" | "#39" => Some('\''),
                    "nbsp" | "#160" => Some(' '),
                    _ if ent.starts_with('#') => ent
                        .trim_start_matches('#')
                        .trim_start_matches('x')
                        .parse::<u32>()
                        .ok()
                        .and_then(char::from_u32),
                    _ => None,
                };
                if let Some(c) = decoded {
                    out.push(c);
                    last_was_word = c.is_alphanumeric();
                    i = end;
                    continue;
                }
            }
        }
        // Copy the original (not lower-cased) character; both strings share byte offsets.
        let ch = html[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        last_was_word = ch.is_alphanumeric();
        i += ch.len_utf8();
    }
    let text = unfold(&out);
    let words = text.split_whitespace().count();
    if tricks.links > 0 && words < 5 && lower.contains("<img") {
        tricks.image_only = true;
    }
    (text, tricks)
}

fn inspect_tag(tag: &str, tricks: &mut HtmlTricks) {
    let compact: String = tag.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("display:none") || compact.contains("visibility:hidden") {
        tricks.hidden_text = true;
    }
    if compact.contains("font-size:0")
        || compact.contains("font-size:1px")
        || compact.contains("font-size:0.")
        || compact.contains("size=\"0\"")
        || compact.contains("size=0")
        || compact.contains("size='0'")
    {
        tricks.tiny_font = true;
    }
    // White text: only a trick when it is explicitly white on an unstyled background.
    if (compact.contains("color:#fff")
        || compact.contains("color:white")
        || compact.contains("color=\"#ffffff\""))
        && !compact.contains("background")
        && !compact.contains("bgcolor")
    {
        tricks.hidden_text = true;
    }
}

/// Every IPv4 address literal in `s`.
pub fn extract_ipv4s(s: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let cand = s[start..i].trim_end_matches('.');
            if cand.split('.').count() == 4 {
                if let Ok(ip) = cand.parse::<Ipv4Addr>() {
                    if !(i < bytes.len() && bytes[i].is_ascii_alphanumeric()) {
                        out.push(ip);
                    }
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Not loopback / private / link-local / reserved / multicast.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && (18..=19).contains(&o[1]))
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// URLs (`http://`, `https://`, `www.`) found in free text or HTML attributes.
pub fn extract_urls(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();
    let mut pos = 0;
    while pos < lower.len() {
        let next = ["http://", "https://", "www."]
            .iter()
            .filter_map(|p| lower[pos..].find(p).map(|i| (pos + i, *p)))
            .min_by_key(|(i, _)| *i);
        let Some((start, prefix)) = next else { break };
        if prefix == "www." && start > 0 {
            let prev = lower.as_bytes()[start - 1];
            if prev.is_ascii_alphanumeric() || prev == b'.' || prev == b'/' || prev == b'@' {
                pos = start + prefix.len();
                continue;
            }
        }
        let mut end = start;
        for (i, c) in text[start..].char_indices() {
            if c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | ')' | ']' | '}' | '|') {
                break;
            }
            end = start + i + c.len_utf8();
        }
        let url = text[start..end].trim_end_matches(['.', ',', ';', ':', '!', '?', ')', '\'']);
        if url.len() > prefix.len() + 2 {
            out.push(url.to_string());
        }
        pos = end.max(start + prefix.len());
    }
    out
}

/// Host part of a URL, lower-cased, without userinfo, port or brackets.
pub fn url_host(url: &str) -> Option<String> {
    let rest = url
        .trim()
        .trim_start_matches(|c: char| c.is_whitespace())
        .splitn(2, "://")
        .collect::<Vec<_>>();
    let after_scheme = if rest.len() == 2 { rest[1] } else { rest[0] };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let host = if authority.starts_with('[') {
        authority
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == ':')
    {
        return None;
    }
    Some(host)
}

const SECOND_LEVEL: &[&str] = &[
    "co", "com", "org", "net", "gov", "edu", "ac", "ne", "or", "go", "gr", "ltd", "plc", "me",
    "nom",
];

/// `www.shop.example.co.uk` → `example.co.uk`; `mail.example.com` → `example.com`.
/// IP literals are returned unchanged.
pub fn registrable_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() {
        return host;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host;
    }
    let n = labels.len();
    let take = if labels[n - 1].len() == 2
        && SECOND_LEVEL.contains(&labels[n - 2])
        && labels[n - 2].len() <= 3
    {
        3
    } else {
        2
    };
    labels[n - take.min(n)..].join(".")
}

/// Last label of a host name (`com`, `ru`, …); `None` for IP literals.
pub fn tld(host: &str) -> Option<String> {
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    host.trim_end_matches('.')
        .rsplit('.')
        .next()
        .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_alphabetic()))
        .map(str::to_ascii_lowercase)
}

/// Domain of an e-mail address, lower-cased.
pub fn address_domain(addr: &str) -> Option<String> {
    addr.trim()
        .rsplit_once('@')
        .map(|(_, d)| {
            d.trim_matches(|c| c == '>' || c == '<' || c == ' ')
                .to_ascii_lowercase()
        })
        .filter(|d| !d.is_empty())
}

/// Confusable-character skeleton (a small, pragmatic subset of UTS #39): lower-case,
/// strip diacritics of common Latin letters, map Cyrillic/Greek homoglyphs and digit/letter
/// lookalikes to one canonical form, and collapse `rn`→`m`, `vv`→`w`, `cl`→`d`.
pub fn skeleton(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars().flat_map(|c| c.to_lowercase()) {
        let mapped = match c {
            '0' | 'о' | 'ο' | 'ö' | 'ò' | 'ó' | 'ô' | 'õ' | 'ø' | 'ɵ' => 'o',
            '1' | 'l' | '|' | 'i' | 'í' | 'ì' | 'î' | 'ï' | 'ı' | 'і' | 'ӏ' | 'ⅼ' | 'ǀ' | 'ι' => {
                'l'
            }
            'а' | 'α' | 'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ạ' | 'ā' => 'a',
            'е' | 'ε' | 'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ė' | 'ę' => 'e',
            'р' | 'ρ' => 'p',
            'с' | 'ϲ' | 'ç' | 'ć' | 'č' => 'c',
            'у' | 'ý' | 'ÿ' | 'γ' => 'y',
            'х' | 'χ' => 'x',
            'ј' => 'j',
            'ѕ' | 'ś' | 'š' | 'ş' => 's',
            'һ' => 'h',
            'ԁ' | 'ď' | 'đ' => 'd',
            'ɡ' | 'ğ' | 'ģ' => 'g',
            'ν' => 'v',
            'κ' => 'k',
            'т' | 'τ' => 't',
            'ñ' | 'ń' | 'ň' | 'η' => 'n',
            'ü' | 'ù' | 'ú' | 'û' | 'ū' | 'µ' => 'u',
            'ß' => 'b',
            'ž' | 'ź' | 'ż' => 'z',
            'ŵ' | 'ω' => 'w',
            'ĸ' => 'k',
            other => other,
        };
        out.push(mapped);
    }
    out.replace("rn", "m").replace("vv", "w").replace("cl", "d")
}

/// Optimal string alignment distance (Levenshtein + adjacent transposition).
pub fn osa_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[n][m]
}

/// True when `candidate` imitates `genuine` (both registrable domains, lower-cased) without
/// being equal: identical confusable skeleton, one edit/transposition away (length ≥ 5), or
/// the genuine domain used as a leading sub-domain / hyphenated label of another domain.
pub fn is_lookalike_domain(candidate: &str, genuine: &str) -> bool {
    let c = candidate.trim_end_matches('.').to_ascii_lowercase();
    let g = genuine.trim_end_matches('.').to_ascii_lowercase();
    if c.is_empty() || g.is_empty() || c == g {
        return false;
    }
    if c.ends_with(&format!(".{g}")) {
        return false; // a real sub-domain of the genuine domain
    }
    if skeleton(&c) == skeleton(&g) {
        return true;
    }
    let (cr, gr) = (registrable_domain(&c), registrable_domain(&g));
    if cr == gr {
        return false;
    }
    if gr.chars().count() >= 5 && osa_distance(&skeleton(&cr), &skeleton(&gr)) <= 1 {
        return true;
    }
    // `sealbox.test.evil.com` or `sealbox-test.com` / `secure-sealbox.test`
    if c.starts_with(&format!("{g}.")) {
        return true;
    }
    let brand = gr.split('.').next().unwrap_or("");
    if brand.chars().count() >= 5 {
        let labels: Vec<&str> = cr.split('.').collect();
        let sld = labels.first().copied().unwrap_or("");
        if sld != brand && sld.split('-').any(|part| skeleton(part) == skeleton(brand)) {
            return true;
        }
    }
    false
}

/// Case-insensitive ASCII `contains`.
pub fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashing_is_stable() {
        assert_eq!(fnv1a64(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64("a"), 0xaf63_dc4c_8601_ec8c);
        assert_ne!(fnv1a64("spam"), fnv1a64("ham"));
    }

    #[test]
    fn tokenizer_basics() {
        assert_eq!(
            tokenize("Hello, World! It's $1,000 for 2 e-mails."),
            vec!["hello", "world", "it's", "$1", "#num", "for", "e-mails"]
        );
        assert_eq!(tokenize("x 12345 2002"), vec!["#num", "#num"]);
        assert!(tokenize("a").is_empty());
    }

    #[test]
    fn html_stripping_and_tricks() {
        let (t, tr) = html_to_text(
            "<html><body><p>Hello&nbsp;<b>there</b></p><script>var x=1;</script>\
             <span style=\"display:none\">hidden</span> vi<!-- x -->agra<a href=\"http://x\">l</a></body></html>",
        );
        assert_eq!(t, "Hello there hidden viagra l");
        assert!(tr.hidden_text);
        assert_eq!(tr.comment_obfuscation, 1);
        assert_eq!(tr.links, 1);
        let (_, tr) = html_to_text("<font size=\"0\">x</font><p style=\"font-size: 0px\">y</p>");
        assert!(tr.tiny_font);
    }

    #[test]
    fn ipv4_extraction_and_classification() {
        let ips = extract_ipv4s(
            "from a.b (c [194.125.145.45]) by d (8.11.6/8.11.6) 127.0.0.1 x1.2.3.4 999.1.1.1",
        );
        assert_eq!(
            ips,
            vec![
                "194.125.145.45".parse::<Ipv4Addr>().unwrap(),
                "127.0.0.1".parse::<Ipv4Addr>().unwrap()
            ]
        );
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_public_ip("10.1.2.3".parse().unwrap()));
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("169.254.6.22".parse().unwrap()));
        assert!(!is_public_ip("100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn url_extraction_and_hosts() {
        let urls = extract_urls("see http://www.adclick.ws/p.cfm?o=315&s=pk007. and https://user@Example.COM:8080/x) or www.foo.org!");
        assert_eq!(
            urls,
            vec![
                "http://www.adclick.ws/p.cfm?o=315&s=pk007",
                "https://user@Example.COM:8080/x",
                "www.foo.org"
            ]
        );
        assert_eq!(url_host(&urls[0]).as_deref(), Some("www.adclick.ws"));
        assert_eq!(url_host(&urls[1]).as_deref(), Some("example.com"));
        assert_eq!(url_host("http://[::1]/x").as_deref(), Some("::1"));
        assert_eq!(url_host("http://1.2.3.4/x").as_deref(), Some("1.2.3.4"));
        assert_eq!(
            registrable_domain("www.shop.example.co.uk"),
            "example.co.uk"
        );
        assert_eq!(registrable_domain("mail.example.com"), "example.com");
        assert_eq!(registrable_domain("1.2.3.4"), "1.2.3.4");
        assert_eq!(tld("mail.example.com").as_deref(), Some("com"));
        assert_eq!(tld("1.2.3.4"), None);
        assert_eq!(
            address_domain("Bob <Bob@Example.ORG>").as_deref(),
            Some("example.org")
        );
    }

    #[test]
    fn skeletons_and_lookalikes() {
        assert_eq!(skeleton("PayPa1"), skeleton("paypal"));
        assert_eq!(skeleton("rnicrosoft"), skeleton("microsoft"));
        assert_eq!(skeleton("аpple"), skeleton("apple")); // Cyrillic а
        assert_ne!(skeleton("apple"), skeleton("orange"));
        assert!(is_lookalike_domain("sea1box.test", "sealbox.test"));
        assert!(is_lookalike_domain("sealb0x.test", "sealbox.test"));
        assert!(is_lookalike_domain("saelbox.test", "sealbox.test"));
        assert!(is_lookalike_domain("sealbox.test.evil.com", "sealbox.test"));
        assert!(is_lookalike_domain("secure-sealbox.com", "sealbox.test"));
        assert!(!is_lookalike_domain("sealbox.test", "sealbox.test"));
        assert!(!is_lookalike_domain("mail.sealbox.test", "sealbox.test"));
        assert!(!is_lookalike_domain("example.org", "sealbox.test"));
        assert!(!is_lookalike_domain("a.io", "b.io"));
        assert_eq!(osa_distance("kitten", "sitting"), 3);
        assert_eq!(osa_distance("ab", "ba"), 1);
    }
}
