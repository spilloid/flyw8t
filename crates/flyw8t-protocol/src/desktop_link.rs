//! Host values accepted in browser links to the Windows technician.
//! This module is also compiled directly into the standalone technician client.

/// Accept a bare DNS name or canonical dotted IPv4 address exactly as supplied.
pub fn host(value: &str) -> Option<&str> {
    if value.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(value);
    }
    let name = value.strip_suffix('.').unwrap_or(value);
    let valid_label = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    // Some resolvers interpret these as alternate IPv4 spellings, including
    // single integers, octal and mixed hexadecimal/decimal components.
    let numeric_label = |label: &str| match label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
    {
        Some(digits) => digits.bytes().all(|b| b.is_ascii_hexdigit()),
        None => label.bytes().all(|b| b.is_ascii_digit()),
    };
    (name.len() <= 253 && name.split('.').all(valid_label) && !name.split('.').all(numeric_label))
        .then_some(value)
}

#[cfg(test)]
mod tests {
    use super::host;

    #[test]
    fn accepts_exact_dns_names_and_canonical_ipv4() {
        for value in [
            "WS-07",
            "ws-07.lab.",
            "face.cafe",
            "0xff.example",
            "192.0.2.8",
        ] {
            assert_eq!(host(value), Some(value));
        }
        let longest = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(host(&longest), Some(longest.as_str()));
        assert!(host(&format!("{longest}e")).is_none());
        assert!(host(&"a".repeat(64)).is_none());
    }

    #[test]
    fn rejects_alternate_addresses_and_uri_syntax() {
        for value in [
            "",
            ".",
            "0x7f000001",
            "0X7f.0.0.1",
            "127.1",
            "010.0.0.1",
            "192.0.2.8.",
            "1.2.3.256",
            "12",
            "user@host",
            "host:3389",
            "host%20",
            "host&key=value",
            "host#foo",
            "host/path",
            "::1",
            " ws",
            "ws\n",
            "-host",
            "host-",
            "host..lab",
            "example..",
        ] {
            assert_eq!(host(value), None, "{value:?}");
        }
    }
}
