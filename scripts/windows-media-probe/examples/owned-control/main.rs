//! Opt-in loopback SCTP fixture. Its only remotely mutable resource is a fixed
//! in-memory board drawn by this process's own Windows window.
mod login;
mod model;
#[path = "../../src/peer.rs"]
mod peer;
mod session;
mod window;

use model::Phase;
use rtc::{
    peer_connection::configuration::setting_engine::SettingEngineBuilder,
    peer_connection::sdp::{RTCSdpType, RTCSessionDescription},
    statistics::{report::RTCStatsReportEntry, StatsSelector},
};
use session::BoardSession;
use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader},
    sync::Notify,
};
use webrtc::{
    data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit},
    peer_connection::{
        PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCIceGatheringState,
        RTCPeerConnectionState,
    },
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const CHANNEL: &str = "flyw8t.owned-board.v2";

#[derive(Default)]
struct Events {
    gathered: Notify,
    connected: Notify,
    ended: Notify,
    board: Arc<Mutex<BoardSession>>,
}

impl Events {
    fn end(&self) {
        self.board.lock().expect("board").stop();
        self.ended.notify_one();
    }
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for Events {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            self.gathered.notify_one();
        }
    }
    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        match state {
            RTCPeerConnectionState::Connected => self.connected.notify_one(),
            RTCPeerConnectionState::Disconnected
            | RTCPeerConnectionState::Closed
            | RTCPeerConnectionState::Failed => self.end(),
            _ => (),
        }
    }
    // The endpoint creates exactly one reliable ordered channel. A second
    // channel or peer-initiated channel has no meaning in this protocol.
    async fn on_data_channel(&self, _: Arc<dyn DataChannel>) {
        self.end();
    }
}

async fn line(reader: &mut (impl AsyncBufRead + Unpin), limit: u64) -> Result<String> {
    let mut s = String::new();
    reader.take(limit + 1).read_line(&mut s).await?;
    if s.len() as u64 > limit || !s.ends_with('\n') {
        return Err("invalid signaling line".into());
    }
    Ok(s)
}

fn print_json(value: serde_json::Value) -> Result<()> {
    println!("{value}");
    std::io::stdout().flush()?;
    Ok(())
}

fn answer_ok(answer: &RTCSessionDescription) -> bool {
    let media: Vec<_> = answer.sdp.lines().filter(|s| s.starts_with("m=")).collect();
    answer.sdp_type == RTCSdpType::Answer
        && media.len() == 1
        && media[0].starts_with("m=application ")
        && media[0].ends_with(" UDP/DTLS/SCTP webrtc-datachannel")
        && answer
            .sdp
            .lines()
            .filter(|s| s.starts_with("a=candidate:"))
            .all(|s| s.split_ascii_whitespace().nth(4) == Some("127.0.0.1"))
}

async fn run(events: Arc<Events>, verify_only: bool) -> Result<()> {
    if !verify_only {
        let (ready, registered) = tokio::sync::oneshot::channel();
        let window_events = events.clone();
        std::thread::spawn(move || {
            if let Err(reason) = window::run(window_events.board.clone(), ready) {
                eprintln!("Windows board unavailable: {reason}");
            }
            window_events.end();
        });
        registered
            .await
            .map_err(|_| "cannot monitor an eligible Windows login")?;
    }

    // The observer also supervises an idle channel and the offer/answer exchange.
    // Every delivered input independently checks the login again under the same lock.
    let watch_login = async {
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if !events.board.lock().expect("board").check_login() {
                break;
            }
        }
    };
    tokio::pin!(watch_login);
    let mut pipe = BufReader::new(tokio::io::stdin());
    let identity = tokio::select! { biased;
        _ = &mut watch_login => return Ok(()),
        identity = line(&mut pipe, 256) => identity?,
    };
    let expected = peer::ExpectedPeer::parse(identity.trim_end())?;
    let peer::ExpectedPeer::Session { id, .. } = &expected else {
        return Err("session commitment required".into());
    };
    let conn = PeerConnectionBuilder::new()
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_include_loopback_candidate(true)
                .build(),
        )
        .with_handler(events.clone())
        .with_udp_addrs(vec![String::from("127.0.0.1:0")])
        .build()
        .await?;
    let result = tokio::select! { biased;
        _ = &mut watch_login => Ok(()),
        result = exchange(&events, &conn, &mut pipe, &expected, id) => result,
    };
    events.end();
    let closed = conn.close().await;
    result?;
    closed?;
    Ok(())
}

async fn exchange(
    events: &Events,
    conn: &impl PeerConnection,
    pipe: &mut (impl AsyncBufRead + Unpin),
    expected: &peer::ExpectedPeer,
    id: &uuid::Uuid,
) -> Result<()> {
    let channel = conn
        .create_data_channel(
            CHANNEL,
            Some(RTCDataChannelInit {
                ordered: true,
                ..Default::default()
            }),
        )
        .await?;
    conn.set_local_description(conn.create_offer(None).await?)
        .await?;
    events.gathered.notified().await;
    print_json(serde_json::to_value(
        conn.local_description().await.ok_or("no offer")?,
    )?)?;
    let answer = serde_json::from_str(&line(pipe, 65_536).await?)?;
    if !answer_ok(&answer) {
        return Err("single loopback SCTP answer required".into());
    }
    while_supervised(events, pipe, async {
        conn.set_remote_description(answer).await?;
        events.connected.notified().await;
        let report = conn.get_stats(Instant::now(), StatsSelector::None).await;
        let transport = report.transport().ok_or("missing established transport")?;
        let fp = |cert_id: &str| match report.get(cert_id) {
            Some(RTCStatsReportEntry::Certificate(c))
                if c.fingerprint_algorithm.eq_ignore_ascii_case("sha-256") =>
            {
                Ok(c.fingerprint.as_str())
            }
            _ => Err("missing actual DTLS certificate"),
        };
        let viewer = fp(&transport.remote_certificate_id)?;
        if !expected.matches(viewer) {
            return Err("viewer certificate did not match".into());
        }
        let code =
            peer::ExpectedPeer::session_code(id, viewer, fp(&transport.local_certificate_id)?)
                .ok_or("could not compute comparison code")?;
        events.board.lock().expect("board").peer_verified(code)?;
        print_json(serde_json::json!({"type":"peer_verified"}))?;
        let mut timer = tokio::time::interval(Duration::from_millis(40));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last = String::new();
        let mut open = false;
        loop {
            tokio::select! { biased;
                _ = timer.tick() => {
                    let (phase,state) = {
                        let board = events.board.lock().expect("board");
                        (board.board().phase, serde_json::to_string(board.board())?)
                    };
                    if phase == Phase::Stopped { break; }
                    if open && last != state { channel.send_text(&state).await?; last = state; }
                }
                event = channel.poll() => match event {
                    Some(DataChannelEvent::OnOpen) => open = true,
                    Some(DataChannelEvent::OnBufferedAmountLow) => (),
                    Some(DataChannelEvent::OnMessage(m)) if m.is_string && open => {
                        let mut b = events.board.lock().expect("board");
                        if b.apply(&m.data).is_err() { break; }
                    }
                    _ => break,
                }
            }
        }
        Ok(())
    })
    .await
}

// Supervision races the entire post-answer exchange. Even if SCTP cannot
// deliver a state update, loss of the private owner pipe releases input.
async fn while_supervised(
    events: &Events,
    pipe: &mut (impl AsyncBufRead + Unpin),
    exchange: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    let result = tokio::select! { biased;
        _ = pipe.fill_buf() => Ok(()),
        _ = events.ended.notified() => Ok(()),
        result = exchange => result,
    };
    events.end();
    result
}

fn main() -> Result<()> {
    let mode = std::env::args().skip(1).collect::<Vec<_>>();
    let verify_only = match mode.as_slice() {
        [v] if v == "--attended-owned-board" => false,
        [v] if v == "--verify-no-permission" => true,
        _ => return Err("choose --attended-owned-board or --verify-no-permission".into()),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let events = Arc::new(Events::default());
    let result = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(120), run(events.clone(), verify_only)).await
    });
    events.end();
    runtime.shutdown_background();
    result?
}

// The fixture decision and login changes below are available only in a Rust
// test binary. The regular executable requires the local Win32 Allow button.
#[cfg(test)]
fn browser_control_test(replace_login: bool) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let changed = Arc::new(AtomicBool::new(false));
    let observed = changed.clone();
    let mut bound = BoardSession::with_observer(move || {
        Ok(login::fixture(
            7,
            if observed.load(Ordering::SeqCst) {
                101
            } else {
                100
            },
        ))
    });
    bound.bind_login().unwrap();
    let events = Arc::new(Events {
        board: Arc::new(Mutex::new(bound)),
        ..Default::default()
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let participant = async {
            loop {
                {
                    let mut session = events.board.lock().unwrap();
                    if session.code().is_some() && session.board().phase == Phase::Waiting {
                        session.allow();
                    }
                    if session.board().pressed && session.board().held_key == Some('i') {
                        if replace_login {
                            changed.store(true, Ordering::SeqCst);
                        }
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            let (result, ()) = tokio::join!(run(events.clone(), true), participant);
            result.unwrap();
        })
        .await
        .unwrap();
    });
    runtime.shutdown_background();
    let mut session = events.board.lock().unwrap();
    let board = session.board();
    assert_eq!(board.phase, Phase::Stopped);
    assert_eq!(board.text, "Hi");
    assert_eq!(board.marked, Some((6, 2)));
    assert!(!board.pressed && board.held_key.is_none());
    let seq = board.seq;
    changed.store(false, Ordering::SeqCst);
    session.allow();
    let next = serde_json::json!({"scope":"owned_board", "seq":seq+1,
        "event":{"kind":"move","x":1,"y":0}});
    assert!(session.apply(&serde_json::to_vec(&next).unwrap()).is_err());
    assert_eq!(session.board().seq, seq);
}

#[test]
#[ignore = "driven by Edge against a test-owned memory board"]
fn browser_keyboard_and_pointer_to_memory_board() {
    browser_control_test(false);
}

#[test]
#[ignore = "driven by Edge against a test-owned memory board"]
fn browser_replaced_login_ends_an_idle_held_press() {
    browser_control_test(true);
}

#[tokio::test]
async fn losing_the_owner_releases_input_even_during_a_blocked_acknowledgement() {
    let mut session = BoardSession::with_observer(|| Ok(login::fixture(2, 100)));
    session.bind_login().unwrap();
    session.peer_verified("012345".into()).unwrap();
    session.allow();
    let activation = serde_json::to_value(session.board()).unwrap()["activation"].clone();
    assert!(activation.is_string());
    for (seq, event) in [
        serde_json::json!({"kind":"button","x":0,"y":0,"down":true}),
        serde_json::json!({"kind":"key","key":"a","down":true}),
    ]
    .into_iter()
    .enumerate()
    {
        let packet = serde_json::json!({"scope":"owned_board","activation":activation,"seq":seq+1,"event":event});
        session
            .apply(&serde_json::to_vec(&packet).unwrap())
            .unwrap();
    }
    let events = Events {
        board: Arc::new(Mutex::new(session)),
        ..Events::default()
    };
    let (owner, input) = tokio::io::duplex(16);
    let mut pipe = BufReader::new(input);
    let (began, blocked) = tokio::sync::oneshot::channel();
    let stalled = async {
        began.send(()).unwrap();
        std::future::pending::<Result<()>>().await
    };
    let cancel = async {
        blocked.await.unwrap();
        drop(owner);
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        let (result, ()) = tokio::join!(while_supervised(&events, &mut pipe, stalled), cancel);
        result.unwrap();
    })
    .await
    .unwrap();
    let session = events.board.lock().unwrap();
    assert_eq!(session.board().phase, Phase::Stopped);
    assert_eq!(session.board().seq, 2);
    assert!(!session.board().pressed && session.board().held_key.is_none());
}
