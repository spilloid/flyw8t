//! Verify Windows Media Foundation can encode and decode a synthetic luma pattern.
//! No desktop, network, microphone, input, credentials or device enrollment are used.
use std::{error::Error, io, path::Path};

use windows::{
    core::{GUID, HSTRING},
    Win32::{
        Media::MediaFoundation::*,
        System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED},
    },
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const WIDTH: u32 = 320;
const HEIGHT: u32 = 180;
const FPS: u32 = 30;
const FRAMES: u32 = 32;

fn luma(frame: u32) -> u8 {
    if (frame / 8).is_multiple_of(2) {
        32
    } else {
        216
    }
}

fn timestamp(frame: u32) -> i64 {
    i64::from(frame) * 10_000_000 / i64::from(FPS)
}

fn pair(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

fn media_type(subtype: &GUID) -> windows::core::Result<IMFMediaType> {
    // All attributes are set on a newly created media type in this thread's COM apartment.
    unsafe {
        let ty = MFCreateMediaType()?;
        ty.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        ty.SetGUID(&MF_MT_SUBTYPE, subtype)?;
        ty.SetUINT64(&MF_MT_FRAME_SIZE, pair(WIDTH, HEIGHT))?;
        ty.SetUINT64(&MF_MT_FRAME_RATE, pair(FPS, 1))?;
        ty.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pair(1, 1))?;
        ty.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        Ok(ty)
    }
}

fn write_fixture(path: &Path) -> Result<()> {
    let pixels = (WIDTH * HEIGHT) as usize;
    let mut nv12 = vec![128u8; pixels + pixels / 2];
    let url = HSTRING::from(path.as_os_str());
    unsafe {
        let writer = MFCreateSinkWriterFromURL(&url, None, None)?;
        let output = media_type(&MFVideoFormat_H264)?;
        output.SetUINT32(&MF_MT_AVG_BITRATE, 800_000)?;
        let stream = writer.AddStream(&output)?;
        writer.SetInputMediaType(stream, &media_type(&MFVideoFormat_NV12)?, None)?;
        writer.BeginWriting()?;
        for frame in 0..FRAMES {
            nv12[..pixels].fill(luma(frame));
            let buffer = MFCreateMemoryBuffer(nv12.len() as u32)?;
            let mut target = std::ptr::null_mut();
            buffer.Lock(&mut target, None, None)?;
            // The allocation is exactly nv12.len(), distinct from the source, and locked.
            std::ptr::copy_nonoverlapping(nv12.as_ptr(), target, nv12.len());
            buffer.Unlock()?;
            buffer.SetCurrentLength(nv12.len() as u32)?;
            let sample = MFCreateSample()?;
            sample.AddBuffer(&buffer)?;
            sample.SetSampleTime(timestamp(frame))?;
            sample.SetSampleDuration(timestamp(frame + 1) - timestamp(frame))?;
            writer.WriteSample(stream, &sample)?;
        }
        writer.Finalize()?;
    }
    Ok(())
}

fn read_fixture(path: &Path) -> Result<u32> {
    let url = HSTRING::from(path.as_os_str());
    let stream = MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32;
    let mut decoded = 0;
    unsafe {
        let reader = MFCreateSourceReaderFromURL(&url, None)?;
        let native = reader.GetNativeMediaType(stream, 0)?;
        if native.GetGUID(&MF_MT_SUBTYPE)? != MFVideoFormat_H264 {
            return Err("container has no H.264 video stream".into());
        }
        reader.SetCurrentMediaType(stream, None, &media_type(&MFVideoFormat_NV12)?)?;
        // Some sources produce format notifications without a sample. Bound even that case.
        for _ in 0..(FRAMES * 4) {
            let mut flags = 0;
            let mut time = 0;
            let mut sample = None;
            reader.ReadSample(
                stream,
                0,
                None,
                Some(&mut flags),
                Some(&mut time),
                Some(&mut sample),
            )?;
            if flags & MF_SOURCE_READERF_ERROR.0 as u32 != 0 {
                return Err("source reader reported a stream error".into());
            }
            if let Some(sample) = sample {
                let buffer = sample.ConvertToContiguousBuffer()?;
                let mut data = std::ptr::null_mut();
                let mut length = 0;
                buffer.Lock(&mut data, None, Some(&mut length))?;
                // Only the first luma byte is needed. Copy it while the buffer is locked.
                let first = (length > 0).then(|| *data);
                buffer.Unlock()?;
                let actual = first.ok_or("empty decoded frame")?;
                // MP4 timestamps can round to the nearest container tick.
                if decoded >= FRAMES
                    || actual.abs_diff(luma(decoded)) > 12
                    || (time - timestamp(decoded)).abs() > 10_000
                {
                    return Err(format!(
                        "unexpected decoded frame {decoded}: luma={actual}, timestamp={time}"
                    )
                    .into());
                }
                decoded += 1;
            }
            if flags & MF_SOURCE_READERF_ENDOFSTREAM.0 as u32 != 0 {
                return if decoded == FRAMES {
                    Ok(decoded)
                } else {
                    Err(format!("decoded {decoded} of {FRAMES} frames").into())
                };
            }
        }
    }
    Err("decoder did not report end of stream".into())
}

fn probe(emit_mp4: bool) -> Result<u32> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("synthetic.mp4");
    write_fixture(&path)?;
    let frames = read_fixture(&path)?;
    if emit_mp4 {
        io::copy(&mut std::fs::File::open(path)?, &mut io::stdout().lock())?;
    }
    Ok(frames)
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let emit_mp4 = match (args.next(), args.next()) {
        (None, None) => false,
        (Some(flag), None) if flag == "--emit-mp4" => true,
        _ => return Err("usage: flyw8t-windows-media-probe [--emit-mp4]".into()),
    };
    // All COM interfaces in probe() drop before the runtime is shut down.
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
        let result = match MFStartup(MF_VERSION, MFSTARTUP_FULL) {
            Ok(()) => {
                let result = probe(emit_mp4);
                let shutdown = MFShutdown();
                result.and_then(|frames| {
                    shutdown?;
                    Ok(frames)
                })
            }
            Err(error) => Err(error.into()),
        };
        CoUninitialize();
        let decoded = result?;
        eprintln!("H.264 round trip: {decoded}/{FRAMES} synthetic frames, {WIDTH}x{HEIGHT} at {FPS} fps; luma and presentation timestamps verified.");
    }
    Ok(())
}
