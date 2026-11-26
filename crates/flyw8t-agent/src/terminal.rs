//! Local background terminal policy and the optional direct SSH readiness check.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::TcpStream;

const ENDPOINT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 22);
const IDENTIFICATION_LIMIT: u64 = 255;
const DEADLINE: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq, Eq)]
pub enum Readiness {
    GreetingReceived,
    ListenerUnavailable,
    InvalidGreeting,
    TimedOut,
}

/// Observe an SSH 2.0 greeting on the fixed local service address.
pub async fn check() -> Readiness {
    check_listener(ENDPOINT, DEADLINE).await
}

async fn check_listener(endpoint: SocketAddrV4, deadline: Duration) -> Readiness {
    let probe = async {
        let Ok(stream) = TcpStream::connect(endpoint).await else {
            return Readiness::ListenerUnavailable;
        };
        let mut reader = BufReader::new(stream.take(IDENTIFICATION_LIMIT));
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line).await.is_ok() && valid_identification(&line) {
            Readiness::GreetingReceived
        } else {
            Readiness::InvalidGreeting
        }
    };
    tokio::time::timeout(deadline, probe)
        .await
        .unwrap_or(Readiness::TimedOut)
}

fn valid_identification(line: &[u8]) -> bool {
    // RFC 4253 §4.2, limited to the immediate SSH 2.0 greeting used by OpenSSH.
    let Some(text) = line
        .strip_prefix(b"SSH-2.0-")
        .and_then(|text| text.strip_suffix(b"\r\n"))
    else {
        return false;
    };
    let version = text.split(|b| *b == b' ').next().unwrap_or_default();
    !version.is_empty()
        && version.iter().all(|b| *b != b'-')
        && text.iter().all(|b| matches!(b, 0x20..=0x7e))
}

#[cfg(windows)]
mod policy {
    use crate::config::{default_state_dir, is_default_state_dir};
    use crate::winsec::{check_private_dir, create_dir, Created, PRIVATE};
    use anyhow::{ensure, Context, Result};
    use flyw8t_protocol::messages::BackgroundTerminalPolicy;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    fn protected_state(state_dir: &Path) -> Result<PathBuf> {
        ensure!(
            is_default_state_dir(state_dir)?,
            "background terminal policy requires the default Windows agent state folder"
        );
        let state = default_state_dir()?;
        check_private_dir(state.parent().context("missing state folder parent")?)?;
        check_private_dir(&state)?;
        Ok(state)
    }

    fn marker(state: &Path, device: Uuid) -> PathBuf {
        state.join(format!("background-terminal.{device}.enabled"))
    }

    fn enabled(marker: &Path) -> Result<bool> {
        match std::fs::symlink_metadata(marker) {
            Ok(_) => {
                check_private_dir(marker)?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn read(state_dir: &Path, device: Uuid) -> BackgroundTerminalPolicy {
        match protected_state(state_dir).and_then(|state| enabled(&marker(&state, device))) {
            Ok(true) => BackgroundTerminalPolicy::Enabled,
            Ok(false) => BackgroundTerminalPolicy::Disabled,
            Err(error) => {
                tracing::warn!(%error, "background terminal policy could not be verified");
                BackgroundTerminalPolicy::Unavailable
            }
        }
    }

    pub fn configure(state_dir: &Path, allow: bool) -> Result<()> {
        let state = protected_state(state_dir)?;
        let device = crate::AgentConfig::load(&state)?
            .device_id
            .context("the agent is not enrolled")?;
        let path = marker(&state, device);
        if allow {
            ensure!(
                create_dir(&path, PRIVATE)? != Created::NotElevated,
                "run the command as Administrator"
            );
            check_private_dir(&path)?;
        } else if enabled(&path)? {
            std::fs::remove_dir(&path).with_context(|| format!("removing {}", path.display()))?;
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use policy::configure as configure_background_policy;
#[cfg(windows)]
pub(crate) use policy::read as read_background_policy;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn fake_listener() -> (TcpListener, SocketAddrV4) {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            panic!("expected an IPv4 listener");
        };
        (listener, address)
    }

    #[tokio::test]
    async fn reads_the_greeting_without_sending_any_bytes() {
        let (listener, address) = fake_listener().await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"SSH-2.0-OpenSSH_9.9\r\n").await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert!(received.is_empty());
        });
        assert_eq!(
            check_listener(address, DEADLINE).await,
            Readiness::GreetingReceived
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn refuses_an_overlong_or_unfamiliar_greeting() {
        let mut long = b"SSH-2.0-".to_vec();
        long.extend([b'x'; IDENTIFICATION_LIMIT as usize]);
        long.extend_from_slice(b"\r\n");
        for greeting in [
            b"HTTP/1.1 200 OK\r\n".as_slice(),
            b"SSH-1.5-obsolete\r\n",
            b"SSH-2.0- comment\r\n",
            b"SSH-2.0-invalid-version\r\n",
            b"SSH-2.0-server\0\r\n",
            b"SSH-2.0-truncated",
            &long,
        ] {
            let (listener, address) = fake_listener().await;
            let greeting = greeting.to_vec();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.write_all(&greeting).await.unwrap();
            });
            assert_eq!(
                check_listener(address, DEADLINE).await,
                Readiness::InvalidGreeting
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn bounds_a_silent_listener_and_detects_absence() {
        let (listener, address) = fake_listener().await;
        let result = check_listener(address, Duration::from_millis(50)).await;
        assert_eq!(result, Readiness::TimedOut);
        drop(listener);
        assert_eq!(
            check_listener(address, DEADLINE).await,
            Readiness::ListenerUnavailable
        );
    }
}
