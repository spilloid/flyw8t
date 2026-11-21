//! A video-only fixture. Native ICE binds to loopback and signaling uses child-process pipes.
use super::{Result, FPS, FRAMES};
use rtc::interceptor::Registry;
use rtc::media::Sample;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_H264};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::{RTCSdpType, RTCSessionDescription};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::statistics::{report::RTCStatsReportEntry, StatsSelector};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::sync::Notify;
use webrtc::media_stream::track_local::{static_sample::TrackLocalStaticSample, TrackLocal};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCIceGatheringState,
    RTCPeerConnectionState,
};
use windows::core::HSTRING;
use windows::Win32::Media::MediaFoundation::*;

// Only the synthetic chart uses this protocol. The supervisor checks the durable
// lease before each heartbeat. The native monotonic deadlines run independently.
const CHART_HEARTBEAT_LIMIT: Duration = Duration::from_secs(1);
const CHART_GRANT_LIMIT: Duration = Duration::from_secs(30);

struct ChartDeadline {
    grant_end: tokio::time::Instant,
    pulse_end: tokio::time::Instant,
}

fn chart_deadline(expires: u64) -> Result<ChartDeadline> {
    let monotonic = tokio::time::Instant::now();
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let remaining = Duration::from_secs(expires)
        .checked_sub(wall)
        .filter(|v| !v.is_zero() && *v <= CHART_GRANT_LIMIT)
        .ok_or("invalid chart grant expiry")?;
    Ok(ChartDeadline {
        grant_end: monotonic + remaining,
        pulse_end: monotonic + CHART_HEARTBEAT_LIMIT,
    })
}

async fn control_stopped(
    control: &mut BufReader<tokio::io::Stdin>,
    deadline: Option<ChartDeadline>,
) -> Result<()> {
    let Some(mut deadline) = deadline else {
        let _ = control.fill_buf().await;
        return Ok(());
    };
    let reason = loop {
        let until = deadline.grant_end.min(deadline.pulse_end);
        let byte = tokio::time::timeout_at(until, control.read_u8()).await;
        // A buffered pulse can be readable at the same instant the timer becomes
        // ready. Check the clock before accepting it so a pause cannot revive a lease.
        if byte.is_err() || tokio::time::Instant::now() >= until {
            break if until == deadline.grant_end {
                "grant_expired"
            } else {
                "supervisor_stalled"
            };
        }
        match byte? {
            Ok(b'+') => deadline.pulse_end = tokio::time::Instant::now() + CHART_HEARTBEAT_LIMIT,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break "control_closed",
            _ => return Err("invalid chart supervisor heartbeat".into()),
        }
    };
    println!(
        "{}",
        serde_json::json!({"type":"chart_stopped","reason":reason})
    );
    Ok(())
}

fn access_units(path: &Path) -> Result<Vec<Vec<u8>>> {
    let stream = MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32;
    let mut units = Vec::new();
    unsafe {
        let reader = MFCreateSourceReaderFromURL(&HSTRING::from(path.as_os_str()), None)?;
        let ty = reader.GetNativeMediaType(stream, 0)?;
        reader.SetCurrentMediaType(stream, None, &ty)?;
        let mut config = vec![0; ty.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER)? as usize];
        ty.GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut config, None)?;
        for _ in 0..FRAMES * 4 {
            let mut flags = 0;
            let mut sample = None;
            reader.ReadSample(stream, 0, None, Some(&mut flags), None, Some(&mut sample))?;
            if flags & MF_SOURCE_READERF_ERROR.0 as u32 != 0 {
                return Err("compressed reader failed".into());
            }
            if let Some(sample) = sample {
                let buffer = sample.ConvertToContiguousBuffer()?;
                let mut data = std::ptr::null_mut();
                let mut size = 0;
                buffer.Lock(&mut data, None, Some(&mut size))?;
                // The sample and its buffer remain alive until the owned copy is complete.
                let payload = if size == 0 {
                    Vec::new()
                } else {
                    std::slice::from_raw_parts(data, size as usize).to_vec()
                };
                buffer.Unlock()?;
                if !payload.starts_with(&[0, 0, 1]) && !payload.starts_with(&[0, 0, 0, 1]) {
                    return Err(
                        "expected an Annex B access unit from the Windows MP4 source".into(),
                    );
                }
                if units.is_empty() {
                    config.extend_from_slice(&payload);
                    units.push(std::mem::take(&mut config));
                } else {
                    units.push(payload);
                }
            }
            if flags & MF_SOURCE_READERF_ENDOFSTREAM.0 as u32 != 0 {
                return if units.len() == FRAMES as usize {
                    Ok(units)
                } else {
                    Err("incomplete compressed stream".into())
                };
            }
        }
    }
    Err("compressed stream did not end".into())
}

#[derive(Default)]
struct Events {
    gathered: Notify,
    connected: Notify,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for Events {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            self.gathered.notify_one();
        }
    }
    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        if state == RTCPeerConnectionState::Connected {
            self.connected.notify_one();
        }
    }
}

pub fn run(path: &Path, relay: bool, await_grant: bool) -> Result<()> {
    let units = access_units(path)?;
    let profile = profile(&units[0])?;
    run_source(
        Source::Clip { units, await_grant },
        profile,
        relay.then_some(super::relay::Scope::Private),
    )
}

enum Source {
    Clip {
        units: Vec<Vec<u8>>,
        await_grant: bool,
    },
    Live(super::live::Surface),
}

fn profile(bytes: &[u8]) -> Result<String> {
    let sps = bytes
        .windows(7)
        .find(|p| p[..3] == [0, 0, 1] && p[3] & 31 == 7)
        .ok_or("missing Annex B H.264 sequence header")?;
    Ok(format!("{:02x}{:02x}{:02x}", sps[4], sps[5], sps[6]))
}

pub fn run_window(surface: super::live::Surface, relay: Option<super::relay::Scope>) -> Result<()> {
    run_source(
        Source::Live(surface),
        profile(&super::live::sequence_header(surface)?)?,
        relay,
    )
}

fn run_source(source: Source, profile: String, relay: Option<super::relay::Scope>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    // Even cancellation of the whole handshake/transmission joins the capture
    // thread before the caller shuts down process-wide Media Foundation.
    let result = std::thread::scope(|scope| {
        runtime.block_on(async {
            let timeout = match source {
                #[cfg(feature = "attended-picker")]
                Source::Live(super::live::Surface::Selected) => Duration::from_secs(180),
                _ => Duration::from_secs(25),
            };
            tokio::time::timeout(timeout, send(source, profile, scope, relay)).await?
        })
    });
    // A cancelled asynchronous stdin read can otherwise hold up process exit on Windows.
    runtime.shutdown_background();
    result
}

async fn send<'scope>(
    source: Source,
    codec_profile: String,
    scope: &'scope std::thread::Scope<'scope, '_>,
    relay_scope: Option<super::relay::Scope>,
) -> Result<()> {
    let mut control = BufReader::new(tokio::io::stdin());
    // The harness pins the browser certificate on a private pipe before seeing the offer.
    let mut identity = String::new();
    (&mut control).take(257).read_line(&mut identity).await?;
    if identity.len() > 256 || !identity.ends_with('\n') {
        return Err("invalid fixture identity message".into());
    }
    let expected = super::peer::ExpectedPeer::parse(identity.trim_end())?;
    let gated = matches!(
        source,
        Source::Clip {
            await_grant: true,
            ..
        }
    );
    if gated && !matches!(expected, super::peer::ExpectedPeer::Session { .. }) {
        return Err("the synthetic chart grant requires a session commitment".into());
    }
    if relay_scope.is_some()
        && matches!(source, Source::Live(_))
        && !matches!(expected, super::peer::ExpectedPeer::Session { .. })
    {
        return Err("attended streaming requires a console session commitment".into());
    }
    let relay = if let Some(scope) = relay_scope {
        let mut line = Vec::new();
        (&mut control)
            .take(4097)
            .read_until(b'\n', &mut line)
            .await?;
        Some(super::relay::Settings::parse(&line, scope)?)
    } else {
        None
    };
    #[cfg(feature = "attended-picker")]
    if matches!(source, Source::Live(super::live::Surface::Selected))
        && !matches!(expected, super::peer::ExpectedPeer::Session { .. })
    {
        return Err("the attended picker requires the console session commitment".into());
    }
    let codec = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_H264.to_owned(),
            clock_rate: 90_000,
            channels: 0,
            sdp_fmtp_line: format!(
                "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id={codec_profile}"
            ),
            rtcp_feedback: vec![],
        },
        payload_type: 102,
    };
    let mut media = MediaEngine::default();
    media.register_codec(codec.clone(), RtpCodecKind::Video)?;
    let interceptors = register_default_interceptors(Registry::new(), &mut media)?;
    let events = Arc::new(Events::default());
    let mut settings = SettingEngineBuilder::new().with_include_loopback_candidate(true);
    if relay.is_some() {
        // A relay-only chart has no higher-priority direct path to wait for.
        settings = settings.with_relay_acceptance_min_wait(Some(Duration::ZERO));
    }
    let builder = PeerConnectionBuilder::new()
        .with_media_engine(media)
        .with_interceptor_registry(interceptors)
        .with_setting_engine(settings.build())
        .with_handler(events.clone());
    let bind = relay
        .as_ref()
        .map(|r| r.bind)
        .unwrap_or(std::net::Ipv4Addr::LOCALHOST);
    let builder = if let Some(settings) = &relay {
        builder.with_configuration(settings.configuration())
    } else {
        builder
    };
    let peer = builder
        .with_udp_addrs(vec![format!("{bind}:0")])
        .build()
        .await?;
    let ssrc = 1;
    let track = Arc::new(TrackLocalStaticSample::new(
        Instant::now(),
        MediaStreamTrack::new(
            "fixture".into(),
            "synthetic-video".into(),
            "generated-luma".into(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(ssrc),
                    ..Default::default()
                },
                codec: codec.rtp_codec,
                ..Default::default()
            }],
        ),
    )?);
    let sender = peer.add_track(track.clone() as Arc<dyn TrackLocal>).await?;
    let offer = peer.create_offer(None).await?;
    peer.set_local_description(offer).await?;
    if relay.is_some() {
        // A Windows participant may stop while an egress filter silently drops
        // TURN Allocate requests. Never wait for the picker/session time budget.
        tokio::select! {
            biased;
            control_data = control.fill_buf() => {
                if control_data?.is_empty() {
                    return Err("participant closed during TURN allocation".into());
                }
                return Err("unexpected participant data before the relay offer".into());
            }
            gathered = tokio::time::timeout(Duration::from_secs(7), events.gathered.notified()) => {
                gathered.map_err(|_| "UDP relay did not answer before the allocation deadline")?;
            }
        }
    } else {
        events.gathered.notified().await;
    }
    let local = peer
        .local_description()
        .await
        .ok_or("missing local offer")?;
    if let Some(settings) = &relay {
        settings.check_sdp(&local.sdp)?;
    }
    println!("{}", serde_json::to_string(&local)?);
    std::io::stdout().flush()?;

    let mut line = Vec::new();
    (&mut control)
        .take(65_537)
        .read_until(b'\n', &mut line)
        .await?;
    if line.len() > 65_536 {
        return Err("oversize fixture answer".into());
    }
    let answer: RTCSessionDescription = serde_json::from_slice(&line)?;
    let mut sections = answer
        .sdp
        .lines()
        .filter_map(|line| line.strip_prefix("m="));
    if answer.sdp_type != RTCSdpType::Answer
        || sections
            .next()
            .and_then(|s| s.split_ascii_whitespace().next())
            != Some("video")
        || sections.next().is_some()
    {
        return Err("expected an answer with exactly one video section".into());
    }
    if let Some(settings) = &relay {
        settings.check_sdp(&answer.sdp)?;
    } else {
        for candidate in answer.sdp.lines().filter(|l| l.starts_with("a=candidate:")) {
            if candidate.split_ascii_whitespace().nth(4) != Some("127.0.0.1") {
                return Err("fixture accepts loopback candidates only".into());
            }
        }
    }
    peer.set_remote_description(answer).await?;
    tokio::select! {
        biased;
        _ = control.fill_buf() => { peer.close().await?; return Ok(()); }
        _ = events.connected.notified() => {}
    }
    let report = peer.get_stats(Instant::now(), StatsSelector::None).await;
    let remote = report
        .transport()
        .and_then(|t| report.get(&t.remote_certificate_id));
    if !matches!(remote, Some(RTCStatsReportEntry::Certificate(cert))
        if cert.fingerprint_algorithm.eq_ignore_ascii_case("sha-256") && expected.matches(&cert.fingerprint))
    {
        peer.close().await?;
        return Err("actual DTLS peer does not match the fixture commitment".into());
    }
    if let Some(settings) = &relay {
        let dtls = sender
            .transport()
            .await?
            .ok_or("missing native media transport")?;
        let pair = dtls
            .ice_transport()
            .get_selected_candidate_pair()
            .await?
            .ok_or("missing selected native ICE pair")?;
        settings.check_selected(&pair)?;
        eprintln!("Verified native selected pair: relay/relay UDP.");
    }
    let mut grant_deadline = None;
    let session_mode = matches!(expected, super::peer::ExpectedPeer::Session { .. });
    if let super::peer::ExpectedPeer::Session { id, .. } = expected {
        let transport = report
            .transport()
            .ok_or("missing established DTLS transport")?;
        let Some(RTCStatsReportEntry::Certificate(local)) =
            report.get(&transport.local_certificate_id)
        else {
            return Err("native certificate unavailable".into());
        };
        let Some(RTCStatsReportEntry::Certificate(remote)) = remote else {
            return Err("technician certificate unavailable".into());
        };
        if !local.fingerprint_algorithm.eq_ignore_ascii_case("sha-256") {
            return Err("unsupported native certificate fingerprint".into());
        }
        let sas =
            super::peer::ExpectedPeer::session_code(&id, &remote.fingerprint, &local.fingerprint)
                .ok_or("invalid DTLS certificate fingerprint")?;
        if gated {
            let observed = serde_json::json!({"session":id.to_string(),
                "viewer":remote.fingerprint.replace(':',"").to_lowercase(),
                "endpoint":local.fingerprint.replace(':',"").to_lowercase()});
            println!(
                "{}",
                serde_json::json!({"type":"chart_dtls","observed":observed})
            );
            std::io::stdout().flush()?;
            let mut command = Vec::new();
            (&mut control)
                .take(513)
                .read_until(b'\n', &mut command)
                .await?;
            if command.is_empty() {
                peer.close().await?;
                return Ok(());
            }
            if command.len() > 512 || !command.ends_with(b"\n") {
                return Err("invalid chart authorization length".into());
            }
            let admission: serde_json::Value = serde_json::from_slice(&command)?;
            let expires = admission["expires"]
                .as_u64()
                .ok_or("missing chart grant expiry")?;
            if admission
                != serde_json::json!({"allow":"view_synthetic_chart","observed":observed,"expires":expires})
            {
                return Err("chart authorization did not match the established session".into());
            }
            grant_deadline = Some(chart_deadline(expires)?);
        } else {
            println!("{}", serde_json::json!({"type":"peer_verified", "sas":sas}));
        }
        std::io::stdout().flush()?;
    }
    let params = sender.get_parameters().await?;
    let pt = params
        .rtp_parameters
        .codecs
        .first()
        .ok_or("no negotiated video codec")?
        .payload_type;
    let duration = Duration::from_secs_f64(1.0 / f64::from(FPS));
    let mut clock = tokio::time::interval(duration);
    clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let (local_stop, mut revoked) = tokio::sync::watch::channel(false);
    let worker = match &source {
        Source::Live(surface) => {
            let surface = *surface;
            let stop = local_stop.clone();
            eprintln!(
                "Verified loopback peer. Starting {} capture.",
                surface.label()
            );
            Some(scope.spawn(move || super::live::produce(tx, session_mode, surface, stop)))
        }
        Source::Clip { .. } => {
            drop(tx);
            None
        }
    };
    let transmit = async {
        let budget = match source {
            #[cfg(feature = "attended-picker")]
            Source::Live(super::live::Surface::Selected) => FPS as usize * 120,
            _ => FRAMES as usize * 10,
        };
        for index in 0..budget {
            tokio::select! {
                biased;
                _ = revoked.changed() => return Ok(()),
                _ = clock.tick() => {}
            }
            let payload = if let Source::Clip { units, .. } = &source {
                units[index % units.len()].clone()
            } else {
                let unit = tokio::select! {
                    biased;
                    _ = revoked.changed() => return Ok(()),
                    unit = rx.recv() => unit.ok_or("owned-window producer stopped before fixture revocation")?,
                };
                if index == 0 && profile(&unit)? != codec_profile {
                    return Err("live encoder profile differs from offer".into());
                }
                unit
            };
            let writer = track.sample_writer(ssrc, pt);
            let sample = Sample {
                data: payload.into(),
                duration,
                ..Sample::new(Instant::now())
            };
            tokio::select! {
                biased;
                _ = revoked.changed() => return Ok(()),
                sent = writer.write_sample(&sample) => sent?,
            }
            if index == 0 {
                if let Source::Live(surface) = &source {
                    eprintln!("First {} access unit sent.", surface.label());
                }
            }
        }
        Err("fixture controller did not stop the stream".into())
    };
    let transmission: Result<()> = tokio::select! {
        biased;
        ended = control_stopped(&mut control, grant_deadline) => ended,
        result = transmit => result,
    };
    drop(rx);
    peer.close().await?;
    if let Some(worker) = worker {
        worker
            .join()
            .map_err(|_| "owned-window capture worker panicked")??;
    }
    transmission
}
