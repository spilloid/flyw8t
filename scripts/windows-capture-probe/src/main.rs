//! Capture only a window which this process creates and paints. No monitor capture or input.
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
                240,
                160,
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

// Copy just the center pixel into one CPU-readable texel. No images leave the GPU.
fn center(
    surface: &ID3D11Texture2D,
    stage: &ID3D11Texture2D,
    ctx: &ID3D11DeviceContext,
) -> Result<[u8; 3]> {
    unsafe {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        surface.GetDesc(&mut desc);
        if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM || desc.Width == 0 || desc.Height == 0 {
            return Err("unexpected capture texture".into());
        }
        let x = desc.Width / 2;
        let y = desc.Height / 2;
        let region = D3D11_BOX {
            left: x,
            top: y,
            front: 0,
            right: x + 1,
            bottom: y + 1,
            back: 1,
        };
        ctx.CopySubresourceRegion(stage, 0, 0, 0, 0, surface, 0, Some(&region));
        let mut map = D3D11_MAPPED_SUBRESOURCE::default();
        ctx.Map(stage, 0, D3D11_MAP_READ, 0, Some(&mut map))?;
        let rgb: [u8; 3] = map.pData.cast::<[u8; 3]>().read();
        ctx.Unmap(stage, 0);
        Ok(rgb)
    }
}

fn probe() -> Result<()> {
    if !GraphicsCaptureSession::IsSupported()? {
        return Err("WGC is unavailable in this interactive session".into());
    }
    let window = TestWindow::new()?;
    let interop: IGraphicsCaptureItemInterop = factory::<GraphicsCaptureItem, _>()?;
    // No external handle is accepted. The capture item is derived exclusively from TestWindow.
    let item: GraphicsCaptureItem = unsafe { interop.CreateForWindow(window.0) }?;
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
    let stage_desc = D3D11_TEXTURE2D_DESC {
        Width: 1,
        Height: 1,
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
        for light in [false, true, false, true] {
            LIGHT.store(light, Ordering::Relaxed);
            if !unsafe { InvalidateRect(Some(window.0), None, false) }.as_bool() {
                return Err("fixture window closed".into());
            }
            let deadline = Instant::now() + Duration::from_secs(4);
            loop {
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
                let pixel = center(&raw, &stage, &ctx)?;
                frame.Close()?;
                if pixel
                    .iter()
                    .all(|&c| if light { c >= 220 } else { c <= 30 })
                {
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

fn main() -> Result<()> {
    if std::env::args_os().len() != 1 {
        return Err("this fixture takes no window, display or other arguments".into());
    }
    unsafe {
        RoInitialize(RO_INIT_MULTITHREADED)?;
    }
    let result = probe();
    unsafe {
        RoUninitialize();
    }
    result?;
    println!("Windows Graphics Capture verified four black/white transitions on the fixture's own window.");
    Ok(())
}
