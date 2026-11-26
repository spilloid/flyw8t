$ErrorActionPreference = 'Stop'
# Development observations only. Every child gets synthetic input and a fresh minimal environment.
# No timeout, module-search or security policy is changed for the real runner by this probe.
$probeRoot = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'target\powershell-startup') ([Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($probeRoot) | Out-Null
$systemFolder = [Environment]::SystemDirectory
$windowsFolder = [Environment]::GetFolderPath('Windows')
$programFolder = [Environment]::GetFolderPath('ProgramFiles')
$psFolder = Join-Path $systemFolder 'WindowsPowerShell\v1.0'
foreach ($probeCase in @('full-cold', 'system-only-cold', 'system-first-cold', 'explicit-imports-cold')) {
    $caseFolder = Join-Path $probeRoot $probeCase
    [IO.Directory]::CreateDirectory($caseFolder) | Out-Null
    $source = @'
[Console]::WriteLine('engine-ready')
[Console]::WriteLine('module-path=' + $env:PSModulePath)
$ProgressPreference = 'SilentlyContinue'
__IMPORTS__
$utf8 = New-Object System.Text.UTF8Encoding($false, $true)
[Console]::WriteLine('utility-ready')
$bytes = New-Object System.IO.MemoryStream
[Console]::OpenStandardInput().CopyTo($bytes)
[Console]::WriteLine('stdin-eof')
$here = Join-Path $PSScriptRoot 'values.json'
[Console]::WriteLine('management-ready')
exit 0
'@
    $imports = ''
    if ($probeCase -eq 'explicit-imports-cold') {
        $imports = @'
Microsoft.PowerShell.Core\Import-Module -Name ([IO.Path]::Combine($PSHOME, 'Modules', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module -Name ([IO.Path]::Combine($PSHOME, 'Modules', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Management.psd1')) -ErrorAction Stop
[Console]::WriteLine('imports-ready')
'@
    }
    $wrapper = Join-Path $caseFolder 'wrapper.ps1'
    [IO.File]::WriteAllText($wrapper, $source.Replace('__IMPORTS__', $imports), [Text.UTF8Encoding]::new($true))
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $psFolder 'powershell.exe'
    $info.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $wrapper + '"'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.WorkingDirectory = $caseFolder
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.EnvironmentVariables.Clear()
    $minimalEnvironment = @{
        'SystemRoot' = $windowsFolder; 'windir' = $windowsFolder; 'SystemDrive' = $windowsFolder.Substring(0,2)
        'ComSpec' = (Join-Path $systemFolder 'cmd.exe'); 'ProgramFiles' = $programFolder
        'PATH' = "$systemFolder;$windowsFolder;$systemFolder\Wbem;$psFolder"
        'PSModulePath' = "$programFolder\WindowsPowerShell\Modules;$psFolder\Modules"
        'APPDATA' = $caseFolder; 'LOCALAPPDATA' = $caseFolder; 'TEMP' = $caseFolder; 'TMP' = $caseFolder
    }
    if ($probeCase -eq 'system-only-cold') { $minimalEnvironment.PSModulePath = "$psFolder\Modules" }
    if ($probeCase -eq 'system-first-cold' -or $probeCase -eq 'explicit-imports-cold') { $minimalEnvironment.PSModulePath = "$psFolder\Modules;$programFolder\WindowsPowerShell\Modules" }
    foreach ($name in $minimalEnvironment.Keys) { $info.EnvironmentVariables[$name] = $minimalEnvironment[$name] }
    $started = [Diagnostics.Stopwatch]::StartNew()
    $process = [Diagnostics.Process]::Start($info)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Write('{}')
    $process.StandardInput.Close()
    $exited = $process.WaitForExit(20000)
    if (-not $exited) {
        $process.Kill()
        if (-not $process.WaitForExit(5000)) { throw 'The diagnostic interpreter did not terminate after kill.' }
    }
    # A descendant can retain a pipe after its parent exits. Observation collection must also be bounded.
    $outText = if ($stdout.Wait(2000)) { $stdout.Result } else { '<stdout did not close>' }
    $errText = if ($stderr.Wait(2000)) { $stderr.Result } else { '<stderr did not close>' }
    [pscustomobject]@{ case=$probeCase; milliseconds=$started.ElapsedMilliseconds; exited=$exited; code=$process.ExitCode; stdout=$outText; stderr=$errText } | ConvertTo-Json -Compress
    $process.StandardOutput.Dispose()
    $process.StandardError.Dispose()
    $process.Dispose()
}
