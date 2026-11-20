[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binary
)

# Exercise Windows shell dispatch under a clean user account. Leave existing
# flyw8t registrations and browser preferences alone.
$ErrorActionPreference = 'Stop'
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$processName = [IO.Path]::GetFileNameWithoutExtension($binaryPath)
$schemeKey = 'HKCU:\Software\Classes\flyw8t'
$associationKey = 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\flyw8t'
foreach ($key in @($schemeKey, 'HKLM:\Software\Classes\flyw8t', "$associationKey\UserChoice", "$associationKey\UserChoiceLatest")) {
    if (Test-Path -LiteralPath $key) {
        throw "An existing flyw8t association occupies $key. Run this smoke test in a clean Windows user account."
    }
}

if (!('TechnicianSmoke' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'technician-smoke-window.cs')
}
$command = '"{0}" --open-uri "%1"' -f $binaryPath
$testComputer = "handoff-$([Guid]::NewGuid().ToString('N')).invalid"
$uri = "flyw8t://open/console?host=$testComputer"
$existingIds = @([Diagnostics.Process]::GetProcessesByName($processName) | ForEach-Object { $_.Id })

function Invoke-Registration([string]$Argument) {
    $helper = Start-Process -FilePath $binaryPath -ArgumentList $Argument -WindowStyle Hidden -PassThru
    try {
        if (!$helper.WaitForExit(12000)) {
            $helper.Kill()
            $helper.WaitForExit()
            throw "$Argument did not exit within 12 seconds."
        }
        if ($helper.ExitCode -ne 0) { throw "$Argument exited with code $($helper.ExitCode)." }
    } finally {
        $helper.Dispose()
    }
}

function Find-ChooserProcess {
    foreach ($candidate in [Diagnostics.Process]::GetProcessesByName($processName)) {
        if ($existingIds -contains $candidate.Id -or $candidate.Path -ne $binaryPath) { continue }
        # Windows may return no process for shell dispatch. Match the unique
        # per-run host as well as the new PID and exact executable path.
        $record = Get-CimInstance Win32_Process -Filter "ProcessId=$($candidate.Id)"
        if ($record -and $record.CommandLine -like "*$testComputer*") { return $candidate }
    }
}

$chooser = $null
$window = [IntPtr]::Zero
$registered = $false
try {
    Invoke-Registration '--register-protocol'
    $registered = $true
    Invoke-Registration '--register-protocol'
    $root = Get-Item -LiteralPath $schemeKey
    $handler = Get-Item -LiteralPath "$schemeKey\shell\open\command"
    if ($root.GetValueNames() -notcontains 'URL Protocol' -or $handler.GetValue('') -ne $command) {
        throw 'Registration did not install the expected URL protocol and quoted executable command.'
    }

    $start = [Diagnostics.ProcessStartInfo]::new($uri)
    $start.UseShellExecute = $true
    $start.Verb = 'open'
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $shellProcess = [Diagnostics.Process]::Start($start)
    if ($shellProcess) { $shellProcess.Dispose() }

    $deadline = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (!$chooser) { $chooser = Find-ChooserProcess }
        if ($chooser) {
            if ($chooser.HasExited) { throw 'The URI handler exited before displaying the chooser.' }
            $window = [TechnicianSmoke]::Window($chooser.Id)
            if ($window -ne [IntPtr]::Zero) {
                $address = [TechnicianSmoke]::Label($window, 102)
                $mode = [TechnicianSmoke]::Selection($window, 105)
                $action = [TechnicianSmoke]::Label($window, 101)
                $status = [TechnicianSmoke]::Label($window, 104)
                if ($address -ceq $testComputer -and $mode -eq 3 -and $action -ceq 'Check console' -and $status -eq '') {
                    break
                }
            }
        }
        if ($deadline.Elapsed.TotalSeconds -ge 15) {
            throw "Windows did not open the requested idle chooser. Computer '$address', mode '$mode', action '$action', status '$status'."
        }
        Start-Sleep -Milliseconds 80
    } while ($true)
} finally {
    try {
        if ($chooser -and !$chooser.HasExited) {
            if ($window -ne [IntPtr]::Zero) {
                [void][TechnicianSmoke]::PostMessage($window, 16, [IntPtr]::Zero, [IntPtr]::Zero)
            }
            if (!$chooser.WaitForExit(2500)) { $chooser.Kill(); $chooser.WaitForExit() }
        }
    } finally {
        if ($registered -or ((Test-Path -LiteralPath $schemeKey) -and (Get-Item -LiteralPath $schemeKey).GetValue('Flyw8tTechnicianCommand') -eq $command)) {
            Invoke-Registration '--unregister-protocol'
            Invoke-Registration '--unregister-protocol'
            if (Test-Path -LiteralPath $schemeKey) { throw 'Unregister left the per-user flyw8t scheme behind.' }
        }
    }
}
Write-Output 'Verified per-user registration, Windows shell dispatch to the idle unattended-console chooser, and registration removal.'
