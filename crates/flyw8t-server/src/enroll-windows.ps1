& {
    $ErrorActionPreference = 'Stop'
    $server = __SERVER_URL__
    $name = 'flyw8t-agent-v__VERSION__-x86_64-pc-windows-msvc.exe'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open PowerShell as Administrator in the folder with the two downloads.'
    }
    if (Get-Service -Name flyw8t-agent -ErrorAction SilentlyContinue) {
        throw 'The Flyw8t service is already installed. Check this PC in Devices.'
    }
    if ($env:FLYW8T_AGENT_STATE_DIR) {
        throw 'Use a PowerShell window with the default Flyw8t service state directory.'
    }

    $folder = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).ProviderPath }
    $path = Join-Path $folder $name
    $manifest = Join-Path $folder 'SHA256SUMS'
    if (!(Test-Path -LiteralPath $path -PathType Leaf) -or !(Test-Path -LiteralPath $manifest -PathType Leaf)) {
        throw "Put $name and SHA256SUMS together in $folder and try again."
    }
    $agent = (Resolve-Path -LiteralPath $path).ProviderPath
    $pattern = '^([0-9a-fA-F]{64})  ' + [regex]::Escape($name) + '$'
    $entry = @(Select-String -LiteralPath $manifest -Pattern $pattern -CaseSensitive)
    $file = [IO.File]::OpenRead($agent)
    try {
        if ($entry.Count -ne 1 -or (Get-FileHash -InputStream $file).Hash -ine $entry[0].Matches[0].Groups[1].Value) {
            throw 'The agent does not match SHA256SUMS. Download both files from the same Flyw8t release.'
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $agent
        if ($signature.Status -ne 'Valid' -or !$signature.TimeStamperCertificate -or
            $signature.SignerCertificate.GetNameInfo('SimpleName', $false) -cne 'Joseph Spillers') {
            throw 'Windows could not verify the timestamped Flyw8t publisher signature.'
        }
        $version = & $agent --version
        if ($LASTEXITCODE -ne 0 -or $version -cne 'flyw8t-agent __VERSION__') {
            throw 'This agent belongs to a different release.'
        }

        Write-Host "Enrolling this Windows PC with $server."
        $token = Read-Host 'Paste the enrollment token from the console' -AsSecureString
        if ($null -eq $token -or $token.Length -eq 0) {
            throw 'No enrollment token was entered. Run setup again and paste the token at the prompt.'
        }
        $previous = $env:FLYW8T_ENROLL_TOKEN
        try {
            $env:FLYW8T_ENROLL_TOKEN = [Net.NetworkCredential]::new('', $token).Password
            & $agent enroll --server $server
            if ($LASTEXITCODE -ne 0) { throw 'Enrollment failed. Check the message above and the token in the console.' }
        } finally {
            $env:FLYW8T_ENROLL_TOKEN = $previous
            if ($null -ne $token) { $token.Dispose() }
        }
        & $agent service install
        if ($LASTEXITCODE -ne 0) { throw 'Enrollment succeeded, but service installation failed. Fix the reported error and run the verified agent with service install.' }
        $service = Get-Service -Name flyw8t-agent
        if ($service.Status -ne 'Running') {
            Write-Host 'Windows is starting the Flyw8t service.'
            try { $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30)) }
            catch { throw 'This PC is enrolled, but Windows has not confirmed the service is running. Check flyw8t-agent in Services.' }
        }
        $service.Refresh()
        $service | Select-Object Name, Status
        Write-Host 'Open Devices in the console and confirm this PC shows Connected.'
    } finally {
        if ($null -ne $file) { $file.Dispose() }
    }
}
