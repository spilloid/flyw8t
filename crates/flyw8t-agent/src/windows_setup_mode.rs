use std::ffi::OsString;

pub const FINISH: &str = "--finish-windows-setup";

#[derive(Debug, PartialEq, Eq)]
pub enum SetupMode {
    Interactive,
    Elevated,
    Quiet,
}

impl SetupMode {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Option<Self> {
        let mut args = args.into_iter();
        match (args.next(), args.next()) {
            (None, None) => Some(Self::Interactive),
            (Some(arg), None) if arg == FINISH => Some(Self::Elevated),
            (Some(arg), None) if arg == "--quiet" || arg == "/quiet" => Some(Self::Quiet),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_setup_invocations_bypass_normal_cli_parsing() {
        let parse = |args: &[&str]| SetupMode::parse(args.iter().map(OsString::from));
        assert_eq!(parse(&[]), Some(SetupMode::Interactive));
        assert_eq!(parse(&[FINISH]), Some(SetupMode::Elevated));
        assert_eq!(parse(&["--quiet"]), Some(SetupMode::Quiet));
        assert_eq!(parse(&["/quiet"]), Some(SetupMode::Quiet));
        for args in [
            &["--quiet", FINISH][..],
            &["status"],
            &["--help"],
            &["/quietly"],
        ] {
            assert_eq!(parse(args), None, "{args:?}");
        }
    }
}
