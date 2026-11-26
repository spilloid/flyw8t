use std::ffi::OsString;

// Order matches the Windows session picker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Intent {
    Assist,
    Share,
    SignIn,
    Console,
    Terminal,
}

const INVALID_LINK: &str =
    "This technician link is invalid. Open the device in flyw8t and choose a session again.";

/// Parse exactly the single argument supplied by the registered URL handler.
/// Keep the grammar literal: decoding or normalizing a URL could hide extra
/// arguments, credentials, or a different target.
pub fn parse_link(args: &[OsString]) -> Result<(Intent, Option<String>), String> {
    let [arg] = args else {
        return Err(INVALID_LINK.into());
    };
    let route = arg
        .to_str()
        .and_then(|uri| uri.strip_prefix("flyw8t://open/"))
        .ok_or(INVALID_LINK)?;
    let (path, host) = match route.split_once('?') {
        None => (route, None),
        Some((path, query)) => {
            let host = query
                .strip_prefix("host=")
                .and_then(crate::desktop_link::host)
                .ok_or(INVALID_LINK)?;
            (path, Some(host.to_owned()))
        }
    };
    let intent = match path {
        "assist" => Intent::Assist,
        "console" => Intent::Console,
        "sign-in" => Intent::SignIn,
        "terminal" => Intent::Terminal,
        _ => return Err(INVALID_LINK.into()),
    };
    Ok((intent, host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_only_prefill_the_named_windows_session() {
        for (path, intent) in [
            ("assist", Intent::Assist),
            ("console", Intent::Console),
            ("sign-in", Intent::SignIn),
            ("terminal", Intent::Terminal),
        ] {
            let link = format!("flyw8t://open/{path}");
            assert_eq!(parse_link(&[link.clone().into()]), Ok((intent, None)));
            for host in ["DELL-01", "ws-9.office.example.", "192.0.2.5"] {
                assert_eq!(
                    parse_link(&[format!("{link}?host={host}").into()]),
                    Ok((intent, Some(host.to_owned())))
                );
            }
        }
    }

    #[test]
    fn link_handler_rejects_extra_arguments_and_unsupported_uri_syntax() {
        let good = OsString::from("flyw8t://open/sign-in?host=pc");
        assert!(parse_link(&[]).is_err());
        assert!(parse_link(&[good, "--connect".into(), "pc".into()]).is_err());
        for uri in [
            "https://open/assist",
            "flyw8t://user@open/assist",
            "flyw8t://open:9/assist",
            "flyw8t://open/share",
            "flyw8t://open/console/",
            "flyw8t://open/assist#x",
            "flyw8t://open/sign-in?",
            "flyw8t://open/sign-in?host=",
            "flyw8t://open/assist?host=pc&host=x",
            "flyw8t://open/assist?connect=true",
            "flyw8t://open/assist?host=pc?more",
            "flyw8t://open/assist?host=pc:3389",
            "flyw8t://open/assist?host=[::1]",
            "flyw8t://open/assist?host=user@pc",
            "flyw8t://open/assist?host=pc%2elab",
            "flyw8t://open/assist?host=pc%22",
            "flyw8t://open/assist?host= pc",
            "flyw8t://open/assist?host=pc\n",
            "flyw8t://open/assist?host=pc/x",
            "flyw8t://open/assist?host=pc#x",
            "flyw8t://open/assist?host=pc..lab",
            "flyw8t://open/assist?host=-pc",
            "flyw8t://open/assist?host=127.1",
            "flyw8t://open/assist?host=010.0.0.1",
            "flyw8t://open/assist?host=0x7f000001",
            "flyw8t://open/assist?host=0x7f.0.0.1",
        ] {
            assert!(parse_link(&[uri.into()]).is_err(), "{uri:?}");
        }
    }
}
