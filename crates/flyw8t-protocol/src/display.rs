//! Showing attacker-influenced text to someone about to sign (ADR-0015 section 8): every string is quoted, and
//! anything that could hide, reorder or overwrite what is shown is escaped. What is shown is then what is signed.

/// Characters that change how text around them looks without being visible themselves: bidirectional controls,
/// zero-width and joiner characters, invisible operators, tag characters, the byte-order mark and the like.
fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x180B..=0x180F
        | 0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x206F | 0x3164 | 0xFE00..=0xFE0F
        | 0xFEFF | 0xFFA0 | 0xFFF0..=0xFFFB | 0x1D173..=0x1D17A | 0xE0000..=0xE0FFF)
}

/// One string, in double quotes, with `"`, `\`, control characters and invisible characters escaped.
pub fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() || is_invisible(c) => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A block of text such as a script's source: each line numbered and escaped as [`quoted`] would, without the
/// quotes, so a carriage return or escape sequence cannot rewrite an earlier line.
pub fn block(s: &str) -> String {
    let lines: Vec<&str> = s.split('\n').collect();
    let width = lines.len().to_string().len();
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        let q = quoted(line);
        out.push_str(&format!("{:>width$} | {}\n", i + 1, &q[1..q.len() - 1]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_hides_or_rewrites_what_is_shown() {
        assert_eq!(quoted("plain"), "\"plain\"");
        assert_eq!(quoted("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quoted("ok\rEVIL"), "\"ok\\rEVIL\"");
        assert_eq!(quoted("\u{1b}[2K"), "\"\\u{1b}[2K\"");
        assert_eq!(quoted("abc\u{202e}fed"), "\"abc\\u{202e}fed\"");
        assert_eq!(quoted("a\u{200b}b"), "\"a\\u{200b}b\"");
        assert_eq!(quoted("\u{e0041}"), "\"\\u{e0041}\"");
        assert_eq!(quoted("héllo 日本"), "\"héllo 日本\"");
        assert_eq!(block("a\nb\u{1b}c"), "1 | a\n2 | b\\u{1b}c\n");
    }
}
