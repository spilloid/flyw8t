$ErrorActionPreference = 'Stop'

try {
    $expectedServer = __SERVER_URL__
    $expectedOrganization = __ORGANIZATION_ID__
    $expectedSite = __SITE_ID__
    $minimumVersion = [version] __VERSION__
    $agent = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'flyw8t\flyw8t-agent.exe'
    $state = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'flyw8t\agent'

    # Both bare and quoted arguments are valid when the path contains no spaces.
    $agentArg = '"' + [regex]::Escape($agent) + '"'
    if ($agent -notmatch '\s') { $agentArg = '(?:' + $agentArg + '|' + [regex]::Escape($agent) + ')' }
    $stateArg = '"' + [regex]::Escape($state) + '"'
    if ($state -notmatch '\s') { $stateArg = '(?:' + $stateArg + '|' + [regex]::Escape($state) + ')' }
    $serviceCommand = '^' + $agentArg + '\s+service\s+run\s+--state-dir\s+' + $stateArg + '$'
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name = 'flyw8t-agent'"
    if (!$service -or $service.PathName -notmatch $serviceCommand -or
        $service.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) { exit 1 }

    # Hold a read-only handle through verification and execution.
    $file = [IO.File]::OpenRead($agent)
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $agent
        if ($signature.Status -ne 'Valid' -or !$signature.TimeStamperCertificate -or
            $signature.SignerCertificate.GetNameInfo('SimpleName', $false) -cne 'Joseph Spillers') {
            exit 1
        }

        $output = & $agent --state-dir $state status --json 2>$null
        if ($LASTEXITCODE -ne 0) { exit 1 }
        $status = $output | ConvertFrom-Json
    } finally {
        $file.Dispose()
    }

    $deviceId = [guid]::Empty
    if (![guid]::TryParse($status.device_id, [ref]$deviceId) -or $deviceId -eq [guid]::Empty) { exit 1 }
    if ([string]$status.server_url.Trim().TrimEnd('/') -cne $expectedServer.Trim().TrimEnd('/')) { exit 1 }
    if ($status.agent_version -cnotmatch '^\d+\.\d+\.\d+$' -or
        [version]$status.agent_version -lt $minimumVersion) { exit 1 }

    $scope = $status.enrollment_scope
    if (!$scope -or $scope.organization_id -ine $expectedOrganization -or
        !$scope.PSObject.Properties['site_id'] -or $scope.site_id -ine $expectedSite) { exit 1 }

    'Flyw8t enrollment detected'
    exit 0
} catch {
    exit 1
}
