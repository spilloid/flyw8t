[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binary
)

# Windows UI smoke. The only session started here targets a closed loopback port.
$ErrorActionPreference = 'Stop'
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class TechnicianSmoke {
    private delegate bool Callback(IntPtr hwnd, IntPtr data);
    [DllImport("user32")] private static extern bool EnumWindows(Callback cb, IntPtr data);
    [DllImport("user32")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32", CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr hwnd, StringBuilder text, int length);
    [DllImport("user32")] public static extern IntPtr GetDlgItem(IntPtr hwnd, int id);
    [DllImport("user32", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
    private static extern IntPtr ReadMessage(IntPtr hwnd, uint msg, UIntPtr count, StringBuilder text, uint flags, uint timeout, out UIntPtr result);
    [DllImport("user32")] public static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr w, IntPtr l);
    public static IntPtr Window(uint pid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((hwnd, data) => {
            uint owner;
            GetWindowThreadProcessId(hwnd, out owner);
            if (owner != pid) return true;
            var name = new StringBuilder(128);
            GetClassName(hwnd, name, name.Capacity);
            if (name.ToString() != "Flyw8tTechnicianWindow") return true;
            found = hwnd;
            return false;
        }, IntPtr.Zero);
        return found;
    }
    public static string Label(IntPtr root, int id) {
        var child = GetDlgItem(root, id);
        if (child == IntPtr.Zero) return "";
        var text = new StringBuilder(1024);
        UIntPtr result;
        ReadMessage(child, 13, (UIntPtr)text.Capacity, text, 2, 500, out result);
        return text.ToString();
    }
}
'@

# Reserve the port without listening. Connections will be refused, and another
# listener cannot acquire the port between selection and the attempt.
$reserved = [Net.Sockets.Socket]::new(
    [Net.Sockets.AddressFamily]::InterNetwork,
    [Net.Sockets.SocketType]::Stream,
    [Net.Sockets.ProtocolType]::Tcp)
$process = $null
$window = [IntPtr]::Zero
try {
    $reserved.ExclusiveAddressUse = $true
    $reserved.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
    $endpoint = $reserved.LocalEndPoint.ToString()
    $process = Start-Process -FilePath $binaryPath -ArgumentList @('--connect', $endpoint) -WindowStyle Hidden -PassThru
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    do {
        if ($process.HasExited) { throw "Viewer exited before reporting the connection outcome." }
        $window = [TechnicianSmoke]::Window($process.Id)
        $status = [TechnicianSmoke]::Label($window, 104)
        $action = [TechnicianSmoke]::Label($window, 101)
        if ($status.Contains($endpoint) -and $status.Contains('refused') -and $action -eq 'Connect') {
            Write-Output "Verified the refusal in the actual viewer. $status"
            return
        }
        Start-Sleep -Milliseconds 80
    } while ($deadline.Elapsed.TotalSeconds -lt 15)
    throw "No actionable refusal in time. Last status '$status', action '$action'."
} finally {
    $reserved.Dispose()
    if ($process -and !$process.HasExited) {
        if ($window -ne [IntPtr]::Zero) {
            [void][TechnicianSmoke]::PostMessage($window, 16, [IntPtr]::Zero, [IntPtr]::Zero)
        }
        if (!$process.WaitForExit(2500)) { $process.Kill() }
    }
}
