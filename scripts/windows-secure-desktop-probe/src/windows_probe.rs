use std::mem::{size_of, size_of_val};
use windows::{
    core::{Interface, BOOL},
    Win32::{
        Foundation::{HANDLE, HMODULE},
        Graphics::{
            Direct3D::D3D_DRIVER_TYPE_UNKNOWN,
            Direct3D11::{
                D3D11CreateDevice, ID3D11Texture2D, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC,
            },
            Dxgi::{
                CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1,
                DXGI_ERROR_NOT_FOUND, DXGI_OUTDUPL_FRAME_INFO,
            },
        },
        System::{
            RemoteDesktop::{ProcessIdToSessionId, WTSGetActiveConsoleSessionId},
            StationsAndDesktops::{GetThreadDesktop, GetUserObjectInformationW, UOI_IO, UOI_NAME},
            Threading::GetCurrentThreadId,
        },
    },
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const FRAME_TIMEOUT_MS: u32 = 2000;
const WINLOGON: &str = "Winlogon";

fn active_secure_desktop() -> Result<u32> {
    let mut session = 0;
    let mut name = [0u16; WINLOGON.len() + 1];
    let mut name_bytes = 0;
    let mut receives_input = BOOL::default();
    // The desktop handle belongs to this thread and must not be closed by the probe.
    unsafe {
        ProcessIdToSessionId(std::process::id(), &mut session)?;
        if session == 0 || session != WTSGetActiveConsoleSessionId() {
            return Err(
                "the probe must already be running in the active physical console session".into(),
            );
        }
        let desktop = GetThreadDesktop(GetCurrentThreadId())?;
        let handle = HANDLE(desktop.0);
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            Some(name.as_mut_ptr().cast()),
            size_of_val(&name) as u32,
            Some(&mut name_bytes),
        )?;
        GetUserObjectInformationW(
            handle,
            UOI_IO,
            Some((&raw mut receives_input).cast()),
            size_of::<BOOL>() as u32,
            None,
        )?;
    }
    if !receives_input.as_bool()
        || name_bytes as usize != size_of_val(&name)
        || !name.iter().copied().eq(WINLOGON.encode_utf16().chain([0]))
    {
        return Err("the probe must already be on the active Winlogon desktop".into());
    }
    Ok(session)
}

fn primary_output() -> Result<(IDXGIAdapter1, IDXGIOutput1)> {
    // Windows owns the enumerated COM objects; these wrappers release the references.
    let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1()? };
    for adapter_index in 0.. {
        let adapter = match unsafe { factory.EnumAdapters1(adapter_index) } {
            Err(error) if error.code() == DXGI_ERROR_NOT_FOUND => break,
            other => other?,
        };
        for output_index in 0.. {
            let output = match unsafe { adapter.EnumOutputs(output_index) } {
                Err(error) if error.code() == DXGI_ERROR_NOT_FOUND => break,
                other => other?,
            };
            let description = unsafe { output.GetDesc()? };
            let bounds = description.DesktopCoordinates;
            if description.AttachedToDesktop.as_bool() && bounds.left == 0 && bounds.top == 0 {
                return Ok((adapter, output.cast()?));
            }
        }
    }
    Err("no attached primary display was available".into())
}

pub fn observe_frame() -> Result<(u32, u32)> {
    let session = active_secure_desktop()?;
    let (adapter, output) = primary_output()?;
    let mut device = None;
    // DXGI requires a D3D device on the adapter that owns the selected display.
    unsafe {
        D3D11CreateDevice(
            &adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            None,
        )?;
    }
    let device = device.ok_or("Windows returned no D3D device")?;
    let duplication = unsafe { output.DuplicateOutput(&device)? };
    let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
    let mut resource = None;
    unsafe { duplication.AcquireNextFrame(FRAME_TIMEOUT_MS, &mut frame_info, &mut resource)? };
    let size = (|| -> Result<(u32, u32)> {
        let texture: ID3D11Texture2D = resource
            .ok_or("Windows returned no frame resource")?
            .cast()?;
        let mut description = D3D11_TEXTURE2D_DESC::default();
        unsafe { texture.GetDesc(&mut description) };
        if description.Width == 0 || description.Height == 0 {
            return Err("the frame was empty".into());
        }
        Ok((description.Width, description.Height))
    })();
    // Release the frame even when Windows returned a resource this probe could not inspect.
    unsafe { duplication.ReleaseFrame()? };
    if active_secure_desktop()? != session {
        return Err("the physical console session changed during the probe".into());
    }
    size
}

#[cfg(test)]
mod tests {
    #[test]
    fn rejects_the_runner_desktop_before_opening_dxgi() {
        assert!(super::active_secure_desktop().is_err());
    }
}
