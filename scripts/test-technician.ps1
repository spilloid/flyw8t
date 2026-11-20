[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binary
)

# Windows UI smoke. The only session started here targets a closed loopback port.
$ErrorActionPreference = 'Stop'
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
if (!('TechnicianSmoke' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'technician-smoke-window.cs')
}

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
