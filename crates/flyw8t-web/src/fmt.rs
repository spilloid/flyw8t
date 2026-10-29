//! Formatting helpers shared by pages.

use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Absolute UTC timestamp, second precision: `2026-10-29 01:20:33 UTC`.
pub fn timestamp(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

pub fn iso(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// Relative age: `just now`, `42 s ago`, `5 min ago`, `3 h ago`, `2 d ago`.
pub fn ago(now: OffsetDateTime, t: OffsetDateTime) -> String {
    let secs = (now - t).whole_seconds();
    match secs {
        s if s < -5 => "in the future (clock skew)".into(),
        s if s < 5 => "just now".into(),
        s if s < 60 => format!("{s} s ago"),
        s if s < 3600 => format!("{} min ago", s / 60),
        s if s < 86_400 => format!("{} h ago", s / 3600),
        s => format!("{} d ago", s / 86_400),
    }
}

pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub fn duration_secs(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        format!("{d} d {h} h")
    } else if h > 0 {
        format!("{h} h {m} min")
    } else {
        format!("{m} min {} s", secs % 60)
    }
}

pub fn short_id(id: uuid::Uuid) -> String {
    id.to_string()[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[test]
    fn ago_reads_naturally() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(10);
        assert_eq!(ago(now, now), "just now");
        assert_eq!(ago(now, now - Duration::seconds(42)), "42 s ago");
        assert_eq!(ago(now, now - Duration::minutes(5)), "5 min ago");
        assert_eq!(ago(now, now - Duration::hours(3)), "3 h ago");
        assert_eq!(
            ago(now, now + Duration::minutes(1)),
            "in the future (clock skew)"
        );
    }

    #[test]
    fn byte_units() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(16 * 1024 * 1024 * 1024), "16.0 GiB");
    }
}
