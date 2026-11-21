//! Synchronous Windows H.264 transform for the owned-window fixture.
use super::{input_sample, media_type, Result, HEIGHT, WIDTH};
use flyw8t_windows_capture_probe::{capture_chart, CHART_HEIGHT, CHART_WIDTH};
use std::mem::ManuallyDrop;
use tokio::sync::mpsc;
use windows::Win32::{
    Media::MediaFoundation::*,
    System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    },
};

struct Encoder {
    transform: IMFTransform,
    buffer_size: u32,
}

impl Encoder {
    fn new() -> Result<Self> {
        unsafe {
            let transform: IMFTransform =
                CoCreateInstance(&CLSID_MSH264EncoderMFT, None, CLSCTX_INPROC_SERVER)?;
            transform.GetAttributes()?.SetUINT32(&MF_LOW_LATENCY, 1)?;
            let output = media_type(&MFVideoFormat_H264)?;
            output.SetUINT32(&MF_MT_AVG_BITRATE, 800_000)?;
            output.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Base.0 as u32)?;
            transform.SetOutputType(0, &output, 0)?;
            transform.SetInputType(0, &media_type(&MFVideoFormat_NV12)?, 0)?;
            let info = transform.GetOutputStreamInfo(0)?;
            if info.cbSize == 0
                || info.cbSize > 4 * 1024 * 1024
                || info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 != 0
            {
                return Err("unexpected Windows software encoder buffer contract".into());
            }
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
            Ok(Self {
                transform,
                buffer_size: info.cbSize,
            })
        }
    }

    fn header(&self) -> Result<Vec<u8>> {
        unsafe {
            let ty = self.transform.GetOutputCurrentType(0)?;
            let size = ty.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER)?;
            if size == 0 || size > 65536 {
                return Err("invalid encoder header length".into());
            }
            let mut header = vec![0; size as usize];
            ty.GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut header, None)?;
            Ok(header)
        }
    }

    fn encode(
        &self,
        frame: u32,
        nv12: &[u8],
        mut emit: impl FnMut(Vec<u8>) -> Result<()>,
    ) -> Result<()> {
        unsafe {
            self.transform
                .ProcessInput(0, &input_sample(frame, nv12)?, 0)?;
            // Drain output before offering another input. Bound a misbehaving transform.
            for _ in 0..32 {
                let sample = MFCreateSample()?;
                sample.AddBuffer(&MFCreateMemoryBuffer(self.buffer_size)?)?;
                let mut output = MFT_OUTPUT_DATA_BUFFER {
                    pSample: ManuallyDrop::new(Some(sample)),
                    ..Default::default()
                };
                let result =
                    self.transform
                        .ProcessOutput(0, std::slice::from_mut(&mut output), &mut 0);
                // windows-rs exposes these two caller-owned COM references as ManuallyDrop.
                let sample = ManuallyDrop::take(&mut output.pSample);
                drop(ManuallyDrop::take(&mut output.pEvents));
                match result {
                    Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(()),
                    other => other?,
                }
                let buffer = sample
                    .ok_or("encoder returned no sample")?
                    .ConvertToContiguousBuffer()?;
                let mut data = std::ptr::null_mut();
                let mut bytes = 0;
                buffer.Lock(&mut data, None, Some(&mut bytes))?;
                let payload = if bytes == 0 || data.is_null() {
                    None
                } else {
                    Some(std::slice::from_raw_parts(data, bytes as usize).to_vec())
                };
                buffer.Unlock()?;
                emit(payload.ok_or("empty encoder output")?)?;
            }
        }
        Err("encoder output did not drain".into())
    }
}

pub fn sequence_header() -> Result<Vec<u8>> {
    Encoder::new()?.header()
}

fn capture(tx: &mpsc::Sender<Vec<u8>>) -> Result<()> {
    assert_eq!((WIDTH, HEIGHT), (CHART_WIDTH, CHART_HEIGHT));
    let encoder = Encoder::new()?;
    let mut frame = 0;
    let mut first = true;
    let header = encoder.header()?;
    let pixels = (WIDTH * HEIGHT) as usize;
    let mut nv12 = vec![128; pixels + pixels / 2];
    capture_chart(
        || tx.is_closed(),
        |luma| {
            if luma.len() != pixels {
                return Err("unexpected captured plane size".into());
            }
            nv12[..pixels].copy_from_slice(&luma);
            // Hold each real WGC state long enough to observe it. A capacity-one queue
            // paces the producer against the connected browser sender.
            for _ in 0..12 {
                if tx.is_closed() {
                    return Err("loopback consumer stopped".into());
                }
                encoder.encode(frame, &nv12, |unit| {
                    let payload = if first {
                        first = false;
                        [header.as_slice(), &unit].concat()
                    } else {
                        unit
                    };
                    tx.blocking_send(payload)
                        .map_err(|_| "loopback consumer stopped".into())
                })?;
                frame += 1;
            }
            Ok(())
        },
    )
}

pub fn produce(tx: mpsc::Sender<Vec<u8>>) -> std::result::Result<(), String> {
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok() }.map_err(|e| e.to_string())?;
    let result = capture(&tx);
    unsafe {
        CoUninitialize();
    }
    if tx.is_closed() {
        return Ok(());
    }
    result.map_err(|e| e.to_string())
}
