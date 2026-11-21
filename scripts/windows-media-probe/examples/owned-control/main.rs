//! Opt-in loopback SCTP fixture. Its only remotely mutable resource is a fixed
//! in-memory board drawn by this process's own Windows window.
mod model;
#[path = "../../src/peer.rs"]
mod peer;
mod window;

use model::{Board, Phase};
use rtc::{
    peer_connection::configuration::setting_engine::SettingEngineBuilder,
    peer_connection::sdp::{RTCSdpType, RTCSessionDescription},
    statistics::{report::RTCStatsReportEntry, StatsSelector},
};
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
const CHANNEL: &str = "flyw8t.owned-board.v1";

#[derive(Default)]
struct Events {
    gathered: Notify,
    connected: Notify,
    ended: Notify,
    board: Arc<Mutex<Board>>,
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
    let mut pipe = BufReader::new(tokio::io::stdin());
    let identity = line(&mut pipe, 256).await?;
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
    let answer = serde_json::from_str(&line(&mut pipe, 65_536).await?)?;
    if !answer_ok(&answer) {
        return Err("single loopback SCTP answer required".into());
    }
    conn.set_remote_description(answer).await?;
    tokio::select! { biased;
        _ = events.ended.notified() => return Err("connection ended".into()),
        _ = pipe.fill_buf() => return Err("supervisor disconnected".into()),
        _ = events.connected.notified() => (),
    }
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
    let code = peer::ExpectedPeer::session_code(id, viewer, fp(&transport.local_certificate_id)?)
        .ok_or("could not compute comparison code")?;
    // verify_only can observe a real handshake and refusal prior to local consent.
    // It has no way to transition the application model to Active.
    if !verify_only {
        let board = events.board.clone();
        std::thread::spawn(move || {
            if let Err(e) = window::run(board.clone(), code) {
                eprintln!("Board window closed: {e}");
            }
            board.lock().expect("board").stop();
        });
    }
    print_json(serde_json::json!({"type":"peer_verified"}))?;
    let mut timer = tokio::time::interval(Duration::from_millis(40));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last = String::new();
    let mut open = false;
    loop {
        tokio::select! { biased;
            _ = events.ended.notified() => break,
            _ = pipe.fill_buf() => break,
            _ = timer.tick() => {
                let (phase,state) = {
                    let board = events.board.lock().expect("board");
                    (board.phase, serde_json::to_string(&*board)?)
                };
                if phase == Phase::Stopped { break; }
                if open && last != state { channel.send_text(&state).await?; last = state; }
            }
            event = channel.poll() => match event {
                Some(DataChannelEvent::OnOpen) => open = true,
                Some(DataChannelEvent::OnBufferedAmountLow) => (),
                Some(DataChannelEvent::OnMessage(m)) if m.is_string && open => {
                    let mut b = events.board.lock().expect("board");
                    if b.apply(&m.data).is_err() { b.stop(); break; }
                }
                _ => break,
            }
        }
    }
    events.end();
    conn.close().await?;
    Ok(())
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

// Invoked by the Edge driver with a test binary only. It never creates a
// Windows window. The native GUI's Allow remains the sole live consent path.
#[test]
#[ignore = "driven by owned-control.mjs --check with this test executable"]
fn browser_keyboard_and_pointer_to_memory_board() {
    let events = Arc::new(Events::default());
    events.board.lock().unwrap().allow();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), run(events.clone(), true))
            .await
            .unwrap()
            .unwrap();
    });
    runtime.shutdown_background();
    let board = events.board.lock().unwrap();
    assert_eq!(board.phase, Phase::Stopped);
    assert_eq!(board.text, "Hi");
    assert_eq!(board.marked, Some((6, 2)));
    assert!(
        !board.pressed && board.held_key.is_none(),
        "disconnect must release the held key and button"
    );
}
