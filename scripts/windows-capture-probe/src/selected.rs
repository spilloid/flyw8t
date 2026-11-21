//! Participant-selected capture. Only the Windows system picker can construct our source.
use super::*;
use std::{
    cell::Cell,
    mem::size_of,
    sync::{Arc, Once},
    thread,
};
use windows::{
    core::PWSTR,
    Graphics::Capture::GraphicsCapturePicker,
    Win32::{
        System::{RemoteDesktop::*, StationsAndDesktops::*},
        UI::{Accessibility::*, Shell::IInitializeWithWindow},
    },
};
use windows_future::AsyncStatus;

#[derive(Copy, Clone, PartialEq, Eq)]
struct Login {
    session: u32,
    logon_time: i64,
}

fn current_login() -> Result<Login> {
    unsafe {
        let mut buffer = PWSTR::null();
        let mut size = 0;
        WTSQuerySessionInformationW(
            None,
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            &mut buffer,
            &mut size,
        )?;
        let login = if !buffer.is_null() && size as usize >= size_of::<WTSINFOEXW>() {
            let info = &*buffer.0.cast::<WTSINFOEXW>();
            if info.Level == 1 {
                let state = info.Data.WTSInfoExLevel1;
                (state.SessionId != 0
                    && state.SessionState == WTSActive
                    && state.SessionFlags == WTS_SESSIONSTATE_UNLOCK as i32
                    && state.LogonTime > 0)
                    .then_some(Login {
                        session: state.SessionId,
                        logon_time: state.LogonTime,
                    })
            } else {
                None
            }
        } else {
            None
        };
        WTSFreeMemory(buffer.0.cast());
        let login = login.ok_or("sharing requires the current unlocked Windows login")?;
        let desktop = OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS)?;
        let mut name = [0u16; 128];
        let read = GetUserObjectInformationW(
            HANDLE(desktop.0),
            UOI_NAME,
            Some(name.as_mut_ptr().cast()),
            256,
            None,
        );
        CloseDesktop(desktop)?;
        read?;
        let end = name
            .iter()
            .position(|&v| v == 0)
            .ok_or("invalid input desktop name")?;
        if !String::from_utf16_lossy(&name[..end]).eq_ignore_ascii_case("Default") {
            return Err("Windows switched to a different input desktop".into());
        }
        Ok(login)
    }
}

// A sticky per-window bit. Any logon, lock, unlock, console/RDP switch, or Close
// ends this consent even if the login becomes eligible again before the next poll.
extern "system" fn control_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        if matches!(
            msg,
            WM_WTSSESSION_CHANGE | WM_CLOSE | WM_QUERYENDSESSION | WM_ENDSESSION | WM_DESTROY
        ) || (msg == WM_COMMAND && (wp.0 & 0xffff) == 1)
        {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 1);
            if msg == WM_CLOSE {
                // Control::drop unregisters notifications before destroying the HWND.
                return LRESULT(0);
            }
        }
        DefWindowProcW(hwnd, msg, wp, lp)
    }
}

struct Control(HWND);

// The hook delivers events on the thread that registered it. Keep switches sticky
// even when the default input desktop has returned before the frame is ready.
thread_local! {
    static DESKTOP_CHANGED: Cell<bool> = const { Cell::new(false) };
}
extern "system" fn desktop_switch(
    _: HWINEVENTHOOK,
    _: u32,
    _: HWND,
    _: i32,
    _: i32,
    _: u32,
    _: u32,
) {
    DESKTOP_CHANGED.set(true);
}
struct DesktopHook(HWINEVENTHOOK);
impl DesktopHook {
    fn register() -> Result<Self> {
        let hook = unsafe {
            SetWinEventHook(
                EVENT_SYSTEM_DESKTOPSWITCH,
                EVENT_SYSTEM_DESKTOPSWITCH,
                None,
                Some(desktop_switch),
                0,
                0,
                WINEVENT_OUTOFCONTEXT,
            )
        };
        if hook.is_invalid() {
            return Err("Windows could not monitor desktop switches".into());
        }
        Ok(Self(hook))
    }
}
impl Drop for DesktopHook {
    fn drop(&mut self) {
        unsafe {
            let _ = UnhookWinEvent(self.0);
        }
    }
}
impl Control {
    fn new() -> Result<Self> {
        unsafe {
            let instance = HINSTANCE(GetModuleHandleW(None)?.0);
            let class = w!("Flyw8t.AttendedCaptureControl");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(control_proc),
                hInstance: instance,
                lpszClassName: class,
                hCursor: LoadCursorW(None, IDC_ARROW)?,
                hbrBackground: HBRUSH(GetStockObject(WHITE_BRUSH).0),
                ..Default::default()
            };
            if RegisterClassW(&wc) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS {
                return Err(windows::core::Error::from_thread().into());
            }
            let control = Self(CreateWindowExW(
                WS_EX_TOPMOST,
                class,
                w!("Flyw8t · View-only screen sharing"),
                WS_CAPTION | WS_SYSMENU,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                375,
                105,
                None,
                None,
                Some(instance),
                None,
            )?);
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("BUTTON"),
                w!("Stop sharing"),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                12,
                12,
                325,
                32,
                Some(control.0),
                Some(HMENU(1 as _)),
                Some(instance),
                None,
            )?;
            WTSRegisterSessionNotification(control.0, 0)?;
            let _ = ShowWindow(control.0, SW_SHOW);
            Ok(control)
        }
    }
    fn active(&self) -> bool {
        unsafe {
            let mut msg = MSG::default();
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                if msg.message == WM_QUIT {
                    return false;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            !DESKTOP_CHANGED.get()
                && IsWindowVisible(self.0).as_bool()
                && !IsIconic(self.0).as_bool()
                && GetWindowLongPtrW(self.0, GWLP_USERDATA) == 0
        }
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        unsafe {
            let _ = WTSUnRegisterSessionNotification(self.0);
            let _ = DestroyWindow(self.0);
        }
    }
}

struct Apartment;
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe {
            RoUninitialize();
        }
    }
}

// Wake the other half of this scoped operation even if a caller callback unwinds.
struct EndShare<'a>(&'a dyn Fn());
impl Drop for EndShare<'_> {
    fn drop(&mut self) {
        (self.0)();
    }
}

fn choose(
    stop: &AtomicBool,
    revoke: &impl Fn(),
    send: mpsc::SyncSender<(GraphicsCaptureItem, Login)>,
) -> Result<()> {
    unsafe {
        RoInitialize(RO_INIT_SINGLETHREADED)?;
    }
    let _apartment = Apartment;
    let _desktop_hook = DesktopHook::register()?;
    let control = Control::new()?;
    let login = current_login()?;
    let picker = GraphicsCapturePicker::new()?;
    let initialize: IInitializeWithWindow = picker.cast()?;
    unsafe {
        initialize.Initialize(control.0)?;
    }
    let op = picker.PickSingleItemAsync()?;
    let active = || {
        !stop.load(Ordering::Acquire)
            && control.active()
            && current_login().ok().as_ref() == Some(&login)
    };
    while op.Status()? == AsyncStatus::Started {
        if !active() {
            revoke();
            let _ = op.Cancel();
            return Ok(());
        }
        thread::sleep(Duration::from_millis(15));
    }
    if op.Status()? != AsyncStatus::Completed || !active() {
        revoke();
        return Ok(());
    }
    // Empty selection is represented as a null interface. Never substitute another source.
    let item = op
        .GetResults()
        .map_err(|_| "no desktop or window was selected")?;
    send.send((item, login))
        .map_err(|_| "capture request ended")?;
    while active() {
        thread::sleep(Duration::from_millis(20));
    }
    revoke();
    Ok(())
}

/// Each plane is tightly packed NV12, 1280×720 (BT.601 limited range).
/// `on_stop` must promptly revoke downstream sends, including already queued frames.
/// The callback should enqueue with a bound and return promptly.
pub fn capture_selected(
    stopped: impl Fn() -> bool,
    on_stop: impl Fn() + Send + Sync,
    mut observe: impl FnMut(Vec<u8>) -> Result<()>,
) -> Result<()> {
    if stopped() {
        on_stop();
        return Ok(());
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let notified = Once::new();
    let revoke = || {
        cancel.store(true, Ordering::Release);
        notified.call_once(&on_stop);
    };
    let (tx, rx) = mpsc::sync_channel(1);
    thread::scope(|scope| -> Result<()> {
        let ui = scope.spawn(|| {
            let _end = EndShare(&revoke);
            let result = choose(&cancel, &revoke, tx);
            result.map_err(|e| e.to_string())
        });
        let end = EndShare(&revoke);
        let run = (|| -> Result<()> {
            while !cancel.load(Ordering::Acquire) && !stopped() {
                match rx.recv_timeout(Duration::from_millis(20)) {
                    Ok((item, login)) => {
                        return stream_item(item, &login, &cancel, &stopped, &revoke, &mut observe)
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
            Ok(())
        })();
        drop(end);
        ui.join()
            .map_err(|_| "local screen-sharing control stopped unexpectedly")??;
        run
    })
}

fn stream_item(
    item: GraphicsCaptureItem,
    login: &Login,
    cancel: &Arc<AtomicBool>,
    stopped: &impl Fn() -> bool,
    revoke: &impl Fn(),
    observe: &mut impl FnMut(Vec<u8>) -> Result<()>,
) -> Result<()> {
    unsafe {
        RoInitialize(RO_INIT_MULTITHREADED)?;
    }
    let _apartment = Apartment;
    if !GraphicsCaptureSession::IsSupported()? {
        return Err("Windows screen capture is unavailable".into());
    }
    let size = item.Size()?;
    if size.Width < 2
        || size.Height < 2
        || i64::from(size.Width) * i64::from(size.Height) > 16_777_216
    {
        return Err("selected surface exceeds the preview size limit".into());
    }
    let (device, ctx, rt_device) = super::capture_device()?;
    let mut staging = None;
    unsafe {
        device.CreateTexture2D(
            &D3D11_TEXTURE2D_DESC {
                Width: size.Width as u32,
                Height: size.Height as u32,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_STAGING,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                ..Default::default()
            },
            None,
            Some(&mut staging),
        )?;
    }
    let staging = staging.ok_or("missing staging surface")?;
    let pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
        &rt_device,
        DirectXPixelFormat::B8G8R8A8UIntNormalized,
        2,
        size,
    )?;
    let session = pool.CreateCaptureSession(&item)?;
    let flag = cancel.clone();
    let closed = item.Closed(&TypedEventHandler::new(move |_, _| {
        flag.store(true, Ordering::Release);
        Ok(())
    }))?;
    let (tx, rx) = mpsc::sync_channel(1);
    let ready = pool.FrameArrived(&TypedEventHandler::new(move |_, _| {
        let _ = tx.try_send(());
        Ok(())
    }))?;
    let active = || {
        !cancel.load(Ordering::Acquire)
            && !stopped()
            && current_login().ok().as_ref() == Some(login)
    };
    let result = (|| -> Result<()> {
        if !active() {
            return Ok(());
        }
        session.StartCapture()?;
        while active() {
            if rx.recv_timeout(Duration::from_millis(25)).is_err() {
                continue;
            }
            let frame = pool.TryGetNextFrame()?;
            if frame.ContentSize()? != size {
                return Err("the selected surface changed size; choose it again".into());
            }
            let access: IDirect3DDxgiInterfaceAccess = frame.Surface()?.cast()?;
            let raw: ID3D11Texture2D = unsafe { access.GetInterface()? };
            let nv12 = unsafe {
                let mut desc = D3D11_TEXTURE2D_DESC::default();
                raw.GetDesc(&mut desc);
                if desc.Width != size.Width as u32
                    || desc.Height != size.Height as u32
                    || desc.ArraySize != 1
                    || desc.MipLevels != 1
                    || desc.SampleDesc.Count != 1
                    || desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM
                {
                    return Err("unexpected capture surface".into());
                }
                ctx.CopyResource(&staging, &raw);
                let mut map = D3D11_MAPPED_SUBRESOURCE::default();
                ctx.Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut map))?;
                let converted = if !map.pData.is_null() && map.RowPitch >= desc.Width * 4 {
                    let bytes = std::slice::from_raw_parts(
                        map.pData.cast::<u8>(),
                        (desc.Height as usize - 1) * map.RowPitch as usize
                            + desc.Width as usize * 4,
                    );
                    Some(convert(
                        bytes,
                        map.RowPitch as usize,
                        desc.Width as usize,
                        desc.Height as usize,
                    ))
                } else {
                    None
                };
                ctx.Unmap(&staging, 0);
                converted.ok_or("invalid capture row stride")?
            };
            frame.Close()?;
            if !active() {
                break;
            }
            observe(nv12)?;
        }
        Ok(())
    })();
    // Release the consumer and fence queued output before closing graphics handles.
    revoke();
    let _ = pool.RemoveFrameArrived(ready);
    let _ = item.RemoveClosed(closed);
    let closed = session.Close().and_then(|()| pool.Close());
    result.and_then(|()| Ok(closed?))
}

fn convert(bytes: &[u8], stride: usize, width: usize, height: usize) -> Vec<u8> {
    let (w, h) = (PREVIEW_WIDTH as usize, PREVIEW_HEIGHT as usize);
    // Keep aspect ratio and align letterbox edges to chroma samples.
    let dest_w = (w.min(width * h / height) & !1).max(2);
    let dest_h = (h.min(height * w / width) & !1).max(2);
    let x0 = ((w - dest_w) / 2) & !1;
    let y0 = ((h - dest_h) / 2) & !1;
    let mut output = vec![128; w * h * 3 / 2];
    output[..w * h].fill(16);
    let columns: Vec<usize> = (0..dest_w).map(|x| (x * width / dest_w) * 4).collect();
    for y in (0..dest_h).step_by(2) {
        let rows = [
            y * height / dest_h * stride,
            (y + 1) * height / dest_h * stride,
        ];
        for (pair, offsets) in columns.chunks_exact(2).enumerate() {
            let x = pair * 2;
            let mut rgb = [0i32; 3];
            for (dy, row) in rows.iter().enumerate() {
                for (dx, offset) in offsets.iter().enumerate() {
                    let off = row + offset;
                    let [b, g, r] = [
                        i32::from(bytes[off]),
                        i32::from(bytes[off + 1]),
                        i32::from(bytes[off + 2]),
                    ];
                    output[(y0 + y + dy) * w + x0 + x + dx] =
                        (16 + ((66 * r + 129 * g + 25 * b + 128) >> 8)) as u8;
                    rgb[0] += r;
                    rgb[1] += g;
                    rgb[2] += b;
                }
            }
            let [r, g, b] = rgb.map(|v| (v + 2) / 4);
            let at = w * h + ((y0 + y) / 2) * w + x0 + x;
            output[at] = (128 + ((-38 * r - 74 * g + 112 * b + 128) >> 8)) as u8;
            output[at + 1] = (128 + ((112 * r - 94 * g - 18 * b + 128) >> 8)) as u8;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_request_revokes_without_opening_picker() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        capture_selected(
            || true,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
            },
            |_| panic!("cancelled capture delivered a frame"),
        )
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn portrait_capture_skips_row_padding_and_centers_chroma() {
        let mut pixels = Vec::new();
        for color in [
            [255, 0, 0, 255],
            [255, 0, 0, 255],
            [0, 255, 0, 255],
            [0, 255, 0, 255],
        ] {
            pixels.extend(color.repeat(2));
            pixels.extend([255; 8]);
        }
        let frame = convert(&pixels, 16, 2, 4);
        let (w, h) = (PREVIEW_WIDTH as usize, PREVIEW_HEIGHT as usize);
        assert_eq!(frame[10 * w + w / 2], 41);
        assert_eq!(frame[(h - 10) * w + w / 2], 144);
        let uv = w * h;
        let center = uv + w / 2;
        assert_eq!(&frame[center..center + 2], &[240, 110]);
        let lower = center + (h / 2 - 10) * w;
        assert_eq!(&frame[lower..lower + 2], &[54, 34]);
        assert_eq!(&frame[uv..uv + 2], &[128, 128]);
    }
    #[test]
    fn red_source_preserves_color_and_black_letterbox() {
        let pixels = [0, 0, 255, 255].repeat(16);
        let frame = convert(&pixels, 16, 4, 4);
        let (w, h) = (PREVIEW_WIDTH as usize, PREVIEW_HEIGHT as usize);
        assert_eq!(frame.len(), w * h * 3 / 2);
        assert_eq!(frame[h / 2 * w], 16);
        assert_eq!(frame[h / 2 * w + w / 2], 82);
        let uv = w * h + h / 4 * w + w / 2;
        assert_eq!(&frame[uv..uv + 2], &[90, 240]);
    }
}
