[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Enable','Remove','Confirm','Absent')][string]$Action,
    [Parameter(Mandatory)][string]$Binary,
    [Parameter(Mandatory)][ValidatePattern('^handoff-[a-f0-9]{32}\.invalid$')][string]$ExpectedComputer,
    [int]$ChromeProcessId,
    [string]$Origin,
    [ValidateSet('assist','console','sign-in','terminal')][string]$Mode
)

$ErrorActionPreference = 'Stop'
if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This test changes the disposable Windows runner user only.'
}
$exe = (Resolve-Path -LiteralPath $Binary).Path
$key = 'HKCU:\Software\Classes\flyw8t'
$commandKey = "$key\shell\open\command"
$command = '"{0}" --open-uri "%1"' -f $exe
Add-Type -Path (Join-Path $PSScriptRoot 'technician-smoke-window.cs')

function Wait-For([scriptblock]$Check, [string]$Reason, [int]$Seconds = 15) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $found = & $Check
        if ($found) { return $found }
        Start-Sleep -Milliseconds 120
    } while ($timer.Elapsed.TotalSeconds -lt $Seconds)
    throw $Reason
}

function Registered-Here {
    (Test-Path -LiteralPath $commandKey) -and (Get-Item -LiteralPath $commandKey).GetValue('') -ceq $command
}

function Close-TestWindow($Process, [IntPtr]$Window) {
    if (!$Process.HasExited) {
        if ($Window -ne [IntPtr]::Zero) {
            [void][TechnicianSmoke]::PostMessage($Window, 16, [IntPtr]::Zero, [IntPtr]::Zero)
        }
        if (!$Process.WaitForExit(3000)) { $Process.Kill(); $Process.WaitForExit() }
    }
    $Process.Dispose()
}

if ($Action -eq 'Enable' -or $Action -eq 'Remove') {
    $enable = $Action -eq 'Enable'
    if ($enable) {
        $choices = 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\flyw8t'
        foreach ($path in @($key, 'HKLM:\Software\Classes\flyw8t', "$choices\UserChoice", "$choices\UserChoiceLatest")) {
            if (Test-Path -LiteralPath $path) { throw 'Expected a clean scheme on a fresh runner.' }
        }
    } elseif (!(Registered-Here)) {
        throw 'Removal requires the signed candidate to own the scheme.'
    }
    $app = Start-Process -FilePath $exe -WindowStyle Hidden -PassThru
    $window = [IntPtr]::Zero
    try {
        $window = Wait-For { $w = [TechnicianSmoke]::Window($app.Id); if ($w -ne [IntPtr]::Zero) { $w } } 'Technician window missing.'
        try {
            $menuCommand = Wait-For {
                if ($app.HasExited) { throw "Technician exited before its browser menu appeared (exit $($app.ExitCode))." }
                $id = [TechnicianSmoke]::BrowserMenuCommand($window, $enable)
                if ($id -gt 0) { $id }
            } 'Expected the browser menu entry.'
        } catch {
            throw "$_ Last menu state: $([TechnicianSmoke]::BrowserMenuState($window, $enable))."
        }
        if (![TechnicianSmoke]::PostMessage($window, 0x111, [IntPtr]$menuCommand, [IntPtr]::Zero)) {
            throw 'Could not post the browser menu command.'
        }
        if ($enable) {
            Wait-For { (Registered-Here) -and (Get-Item -LiteralPath $key).GetValueNames() -contains 'URL Protocol' } 'Menu did not register the downloaded candidate.' | Out-Null
        } else {
            Wait-For { !(Test-Path -LiteralPath $key) } 'Menu did not remove its handler.' | Out-Null
        }
    } finally {
        Close-TestWindow $app $window
    }
    return
}

function Find-Chooser {
    foreach ($candidate in [Diagnostics.Process]::GetProcessesByName([IO.Path]::GetFileNameWithoutExtension($exe))) {
        if ($candidate.Path -ne $exe) { continue }
        $argsRecord = Get-CimInstance Win32_Process -Filter "ProcessId=$($candidate.Id)"
        if ($argsRecord.CommandLine -like "*$ExpectedComputer*") { return $candidate }
    }
}

if ($Origin -notmatch '^http://127\.0\.0\.1:[0-9]+$') { throw 'Expected the ephemeral loopback origin.' }
$chrome = Get-Process -Id $ChromeProcessId -ErrorAction Stop
if ($chrome.ProcessName -ne 'chrome') { throw 'Expected the fixture Chrome process.' }
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$root = [System.Windows.Automation.AutomationElement]::FromHandle($chrome.MainWindowHandle)
if (!$root) { throw 'Chrome has no desktop window.' }

function Find-OpenPrompt {
    $scope = [System.Windows.Automation.TreeScope]::Descendants
    $all = [System.Windows.Automation.Condition]::TrueCondition
    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
    foreach ($button in $root.FindAll($scope, $all)) {
        if ($button.Current.ControlType -ne [System.Windows.Automation.ControlType]::Button -or
            $button.Current.Name -notmatch '^Open .*flyw8t' -or $button.Current.IsOffscreen -or !$button.Current.IsEnabled) { continue }
        # The browser owns this dialog. Never treat page content or the address bar
        # as evidence that Chrome asked for permission to open the application.
        $ancestor = $walker.GetParent($button)
        $dialog = $null
        while ($ancestor -and !$ancestor.Equals($root)) {
            if ($ancestor.Current.ControlType -eq [System.Windows.Automation.ControlType]::Document) { break }
            if ($ancestor.Current.LocalizedControlType -match 'dialog' -or
                $ancestor.Current.Name -match '^Open .*flyw8t.*\?$') { $dialog = $ancestor; break }
            $ancestor = $walker.GetParent($ancestor)
        }
        if (!$dialog) { continue }
        $children = $dialog.FindAll($scope, $all)
        $cancel = $children | Where-Object { $_.Current.ControlType -eq [System.Windows.Automation.ControlType]::Button -and $_.Current.Name -eq 'Cancel' }
        $site = $children | Where-Object { $_.Current.Name -and $_.Current.Name.Contains($Origin.Substring(7)) }
        if ($cancel -and $site) { return $button }
    }
}

function Invoke-OpenPrompt($Prompt) {
    # UIA can expose the button as Chrome is still activating its new dialog.
    # Recheck the same browser-owned control after it has remained visible.
    Start-Sleep -Milliseconds 1500
    $settled = Find-OpenPrompt
    if (!$settled -or ![System.Windows.Automation.Automation]::Compare($Prompt, $settled)) {
        throw 'The external-app prompt changed before it could be approved.'
    }
    $settled.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
}

if ($Action -eq 'Absent') {
    if (Test-Path -LiteralPath $key) { throw 'Handler remains registered.' }
    # Depending on the Shell/Chrome cache, removal either suppresses the prompt
    # or prompts again. Accept a residual verified prompt to exercise that path.
    $accepted = $false
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (Find-Chooser) { throw 'The removed application still received the browser link.' }
        if (!$accepted) {
            $prompt = Find-OpenPrompt
            if ($prompt) {
                Invoke-OpenPrompt $prompt
                $accepted = $true
                $timer.Restart()
            }
        }
        Start-Sleep -Milliseconds 180
    } while ($timer.Elapsed.TotalSeconds -lt 8)
    Write-Output 'Removed handler received no launch after the real browser click.'
    return
}

if (!(Registered-Here)) { throw 'Expected the signed handler for the prompted click.' }
$first = $Mode -eq 'assist'
$response = Wait-For {
    if (Find-Chooser) {
        if ($first) { throw 'The handler launched before first-use prompt approval.' }
        return 'already approved'
    }
    Find-OpenPrompt
} 'Chrome did not display the Flyw8t external-app prompt or open the approved handler.'
if ($response -isnot [string]) {
    if (Find-Chooser) { throw 'The handler launched while the prompt was visible.' }
    Invoke-OpenPrompt $response
    Write-Output "Invoked the browser prompt for $Mode."
}
try {
    $app = Wait-For { Find-Chooser } 'The handler window was not observed.' 30
} catch {
    if (Find-OpenPrompt) { throw "Chrome still shows the $Mode prompt after invoking Open." }
    throw "Chrome dismissed the $Mode prompt but Windows did not open the expected handler."
}
$window = [IntPtr]::Zero
try {
    $expected = @{ 'assist' = @(0,'Find sessions'); 'console' = @(3,'Check console'); 'sign-in' = @(2,'Connect'); 'terminal' = @(4,'Open terminal') }[$Mode]
    $window = Wait-For { $w = [TechnicianSmoke]::Window($app.Id); if ($w -ne [IntPtr]::Zero) { $w } } 'Missing technician chooser.'
    Wait-For {
        [TechnicianSmoke]::Label($window,102) -ceq $ExpectedComputer -and
        [TechnicianSmoke]::Selection($window,105) -eq $expected[0] -and
        [TechnicianSmoke]::Label($window,101) -ceq $expected[1] -and
        [TechnicianSmoke]::Label($window,104) -ceq ''
    } 'The application showed the wrong synthetic host, mode, or idle action.' | Out-Null
    Write-Output "Verified $Mode idle chooser."
} finally {
    Close-TestWindow $app $window
}
