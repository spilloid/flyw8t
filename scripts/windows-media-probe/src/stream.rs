//! A video-only fixture. Native ICE binds to loopback and signaling uses child-process pipes.
use super::{Result, FPS, FRAMES};
use rtc::interceptor::Registry;
use rtc::media::Sample;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_H264};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::statistics::{report::RTCStatsReportEntry, StatsSelector};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::sync::Notify;
use webrtc::media_stream::track_local::{static_sample::TrackLocalStaticSample, TrackLocal};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCIceGatheringState,
    RTCPeerConnectionState,
};
use windows::core::HSTRING;
use windows::Win32::Media::MediaFoundation::*;

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

pub fn run(path: &Path) -> Result<()> {
    let units = access_units(path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let result = runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(25), send(units)).await? });
    // A cancelled asynchronous stdin read can otherwise hold up process exit on Windows.
    runtime.shutdown_background();
    result
}

async fn send(units: Vec<Vec<u8>>) -> Result<()> {
    let mut control = BufReader::new(tokio::io::stdin());
    // The harness pins the browser certificate on a private pipe before seeing the offer.
    let mut identity = String::new();
    (&mut control).take(98).read_line(&mut identity).await?;
    let expected = identity.trim_end();
    if expected.len() != 95
        || !expected
            .split(':')
            .all(|b| b.len() == 2 && b.bytes().all(|x| x.is_ascii_hexdigit()))
    {
        return Err("invalid fixture peer fingerprint".into());
    }
    let sps = units[0]
        .windows(7)
        .find(|p| p[..3] == [0, 0, 1] && p[3] & 31 == 7)
        .ok_or("missing H.264 sequence header")?;
    let profile = format!("{:02x}{:02x}{:02x}", sps[4], sps[5], sps[6]);
    let codec = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_H264.to_owned(),
            clock_rate: 90_000,
            channels: 0,
            sdp_fmtp_line: format!(
                "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id={profile}"
            ),
            rtcp_feedback: vec![],
        },
        payload_type: 102,
    };
    let mut media = MediaEngine::default();
    media.register_codec(codec.clone(), RtpCodecKind::Video)?;
    let interceptors = register_default_interceptors(Registry::new(), &mut media)?;
    let events = Arc::new(Events::default());
    let peer = PeerConnectionBuilder::new()
        .with_media_engine(media)
        .with_interceptor_registry(interceptors)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_include_loopback_candidate(true)
                .build(),
        )
        .with_handler(events.clone())
        .with_udp_addrs(vec!["127.0.0.1:0"])
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
    events.gathered.notified().await;
    let local = peer
        .local_description()
        .await
        .ok_or("missing local offer")?;
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
    for candidate in answer.sdp.lines().filter(|l| l.starts_with("a=candidate:")) {
        if candidate.split_ascii_whitespace().nth(4) != Some("127.0.0.1") {
            return Err("fixture accepts loopback candidates only".into());
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
        if cert.fingerprint_algorithm.eq_ignore_ascii_case("sha-256") && cert.fingerprint.eq_ignore_ascii_case(expected))
    {
        peer.close().await?;
        return Err("actual DTLS peer does not match the fixture commitment".into());
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
    for payload in units.iter().cycle().take(units.len() * 10) {
        tokio::select! {
            biased;
            _ = control.fill_buf() => { peer.close().await?; return Ok(()); }
            _ = clock.tick() => {}
        }
        track
            .sample_writer(ssrc, pt)
            .write_sample(&Sample {
                data: payload.clone().into(),
                duration,
                ..Sample::new(Instant::now())
            })
            .await?;
    }
    peer.close().await?;
    Err("fixture controller did not stop the stream".into())
}
