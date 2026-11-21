//! Owned-window capture fixture, with a separate opt-in Windows participant picker.
#[cfg(feature = "attended-picker")]
mod selected;
#[cfg(feature = "attended-picker")]
pub use selected::capture_selected;
use std::{
    error::Error,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use windows::{
    core::{factory, w, Interface},
    Foundation::TypedEventHandler,
    Graphics::{
        Capture::{Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCaptureSession},
        DirectX::{Direct3D11::IDirect3DDevice, DirectXPixelFormat},
    },
    Win32::{
        Foundation::*,
        Graphics::{
            Direct3D::D3D_DRIVER_TYPE_HARDWARE,
            Direct3D11::*,
            Dxgi::{Common::*, IDXGIDevice},
            Gdi::*,
        },
        System::{
            LibraryLoader::GetModuleHandleW,
            WinRT::{Direct3D11::*, Graphics::Capture::IGraphicsCaptureItemInterop, *},
        },
        UI::WindowsAndMessaging::*,
    },
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
static LIGHT: AtomicBool = AtomicBool::new(false);
static CHART: AtomicBool = AtomicBool::new(false);
pub const CHART_WIDTH: u32 = 320;
pub const CHART_HEIGHT: u32 = 180;
#[cfg(feature = "attended-picker")]
pub const PREVIEW_WIDTH: u32 = 1280;
#[cfg(feature = "attended-picker")]
pub const PREVIEW_HEIGHT: u32 = 720;

extern "system" fn paint(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    unsafe {
        if msg == WM_PAINT {
            let mut ps = PAINTSTRUCT::default();
            let dc = BeginPaint(hwnd, &mut ps);
            let brush = GetStockObject(if LIGHT.load(Ordering::Relaxed) {
                WHITE_BRUSH
            } else {
                BLACK_BRUSH
            });
            FillRect(dc, &ps.rcPaint, HBRUSH(brush.0));
            if CHART.load(Ordering::Relaxed) {
                let mut right = RECT::default();
                if GetClientRect(hwnd, &mut right).is_ok() {
                    right.left = right.right / 2;
                    let opposite = GetStockObject(if LIGHT.load(Ordering::Relaxed) {
                        BLACK_BRUSH
                    } else {
                        WHITE_BRUSH
                    });
                    FillRect(dc, &right, HBRUSH(opposite.0));
                }
            }
            let _ = EndPaint(hwnd, &ps);
            return LRESULT(0);
        }
        if msg == WM_DESTROY {
            PostQuitMessage(0);
            return LRESULT(0);
        }
        DefWindowProcW(hwnd, msg, w, l)
    }
}

struct TestWindow(HWND);
impl TestWindow {
    fn new() -> Result<Self> {
        unsafe {
            let instance = HINSTANCE(GetModuleHandleW(None)?.0);
            let class = w!("Flyw8t.OwnedCaptureProbe");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(paint),
                hInstance: instance,
                lpszClassName: class,
                ..Default::default()
            };
            if RegisterClassW(&wc) == 0 {
                return Err(windows::core::Error::from_thread().into());
            }
            let hwnd = CreateWindowExW(
                WS_EX_NOACTIVATE,
                class,
                w!("Flyw8t capture test"),
                WS_CAPTION | WS_SYSMENU,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                560,
                360,
                None,
                None,
                Some(instance),
                None,
            )?;
            let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
            Ok(Self(hwnd))
        }
    }
}
impl Drop for TestWindow {
    fn drop(&mut self) {
        unsafe {
            let _ = DestroyWindow(self.0);
        }
    }
}

// Copy only the centered test region. Respect GPU row padding before unmapping.
fn read_luma(
    surface: &ID3D11Texture2D,
    stage: &ID3D11Texture2D,
    ctx: &ID3D11DeviceContext,
    width: u32,
    height: u32,
) -> Result<Vec<u8>> {
    unsafe {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        surface.GetDesc(&mut desc);
        if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM || desc.Width < width || desc.Height < height {
            return Err("unexpected capture texture".into());
        }
        let x = (desc.Width - width) / 2;
        let y = (desc.Height - height) / 2;
        let region = D3D11_BOX {
            left: x,
            top: y,
            front: 0,
            right: x + width,
            bottom: y + height,
            back: 1,
        };
        ctx.CopySubresourceRegion(stage, 0, 0, 0, 0, surface, 0, Some(&region));
        let mut map = D3D11_MAPPED_SUBRESOURCE::default();
        ctx.Map(stage, 0, D3D11_MAP_READ, 0, Some(&mut map))?;
        if map.pData.is_null() || map.RowPitch < width * 4 {
            ctx.Unmap(stage, 0);
            return Err("invalid staging row pitch".into());
        }
        let mut luma = Vec::with_capacity((width * height) as usize);
        for row in 0..height as usize {
            let start = map.pData.cast::<u8>().add(row * map.RowPitch as usize);
            let bytes = std::slice::from_raw_parts(start, width as usize * 4);
            for bgra in bytes.as_chunks::<4>().0 {
                // The fixture paints grayscale. Map full-range BGRA into video-range Y.
                luma.push((16 + (219 * u32::from(bgra[1]) + 127) / 255) as u8);
            }
        }
        ctx.Unmap(stage, 0);
        Ok(luma)
    }
}

fn capture_device() -> Result<(ID3D11Device, ID3D11DeviceContext, IDirect3DDevice)> {
    let mut device = None;
    let mut context = None;
    unsafe {
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )?;
    }
    let device = device.ok_or("missing D3D device")?;
    let ctx = context.ok_or("missing D3D context")?;
    let dxgi: IDXGIDevice = device.cast()?;
    let rt_device: IDirect3DDevice =
        unsafe { CreateDirect3D11DeviceFromDXGIDevice(&dxgi)? }.cast()?;
    Ok((device, ctx, rt_device))
}

fn probe(
    chart: bool,
    states: usize,
    stopped: impl Fn() -> bool,
    mut observe: impl FnMut(Vec<u8>) -> Result<()>,
) -> Result<()> {
    if !GraphicsCaptureSession::IsSupported()? {
        return Err("WGC is unavailable in this interactive session".into());
    }
    CHART.store(chart, Ordering::Relaxed);
    let window = TestWindow::new()?;
    let interop: IGraphicsCaptureItemInterop = factory::<GraphicsCaptureItem, _>()?;
    // No external handle is accepted. The capture item is derived exclusively from TestWindow.
    let item: GraphicsCaptureItem = unsafe { interop.CreateForWindow(window.0) }?;
    let (device, ctx, rt_device) = capture_device()?;
    let (width, height) = if chart {
        (CHART_WIDTH, CHART_HEIGHT)
    } else {
        (1, 1)
    };
    let stage_desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
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
    };
    let mut stage = None;
    unsafe {
        device.CreateTexture2D(&stage_desc, None, Some(&mut stage))?;
    }
    let stage = stage.ok_or("missing staging texture")?;
    let pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
        &rt_device,
        DirectXPixelFormat::B8G8R8A8UIntNormalized,
        2,
        item.Size()?,
    )?;
    let session = pool.CreateCaptureSession(&item)?;
    session.SetIsCursorCaptureEnabled(false)?;
    let (notify, frames) = mpsc::sync_channel(1);
    let token = pool.FrameArrived(&TypedEventHandler::new(move |_, _| {
        let _ = notify.try_send(());
        Ok(())
    }))?;
    session.StartCapture()?;
    let result = (|| -> Result<()> {
        for index in 0..states {
            let light = index % 2 == 1;
            LIGHT.store(light, Ordering::Relaxed);
            if !unsafe { InvalidateRect(Some(window.0), None, false) }.as_bool() {
                return Err("fixture window closed".into());
            }
            let deadline = Instant::now() + Duration::from_secs(4);
            loop {
                if stopped() {
                    return Ok(());
                }
                let mut msg = MSG::default();
                unsafe {
                    while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                        if msg.message == WM_QUIT {
                            return Err("fixture closed by participant".into());
                        }
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
                if Instant::now() >= deadline {
                    return Err("no matching WGC pixel before deadline".into());
                }
                if frames.recv_timeout(Duration::from_millis(10)).is_err() {
                    continue;
                }
                let frame = pool.TryGetNextFrame()?;
                let access: IDirect3DDxgiInterfaceAccess = frame.Surface()?.cast()?;
                let raw: ID3D11Texture2D = unsafe { access.GetInterface()? };
                let luma = read_luma(&raw, &stage, &ctx, width, height)?;
                frame.Close()?;
                let mid = (width * (height / 2)) as usize;
                let left = luma[mid + (width / 4) as usize];
                let right = luma[mid + (3 * width / 4) as usize];
                let matches = |value, bright| if bright { value >= 220 } else { value <= 30 };
                if matches(left, light) && matches(right, if chart { !light } else { light }) {
                    observe(luma)?;
                    break;
                }
            }
        }
        Ok(())
    })();
    pool.RemoveFrameArrived(token)?;
    session.Close()?;
    pool.Close()?;
    result
}

fn run(
    chart: bool,
    states: usize,
    stopped: impl Fn() -> bool,
    observe: impl FnMut(Vec<u8>) -> Result<()>,
) -> Result<()> {
    unsafe {
        RoInitialize(RO_INIT_MULTITHREADED)?;
    }
    let result = probe(chart, states, stopped, observe);
    unsafe {
        RoUninitialize();
    }
    result
}

pub fn verify_window() -> Result<()> {
    run(false, 5, || false, |_| Ok(()))
}

/// Alternating full-size grayscale planes from our own two-panel test window.
pub fn capture_chart(
    states: usize,
    stopped: impl Fn() -> bool,
    observe: impl FnMut(Vec<u8>) -> Result<()>,
) -> Result<()> {
    run(true, states, stopped, observe)
}
