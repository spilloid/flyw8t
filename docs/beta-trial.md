# Try flyw8t on one Windows PC

Start with one Windows x64 PC you administer. Install the agent there to verify a live check-in and a diagnostic. You can run Flyw8t Technician on the same PC to test opening the desktop chooser from the browser. To try an actual remote session, use Technician on a second Windows x64 PC with a network route to the first.

## Install from a site package

On a release that supports Windows installers, sign in to your console and open **Devices → Enroll a Windows device**. Choose the organization and site, then set how many PCs can enroll and how long the installer is valid. Choose **Download Windows installer**. You can also download a one-PC installer directly from a site's **Devices** card.

Open `Flyw8t-Setup-x64.exe` on the target PC. Check the organization, site, and console shown in Setup, then approve the Windows administrator prompt. Setup reports when this PC has enrolled and the Windows service is running. Open **Devices** in the console and wait for **Connected · live**. You can then verify a diagnostic in step 3.

The personalized installer is unsigned. It comes from your console and contains the revocable enrollment token, so share it only with the people setting up those PCs and discard it when you're done. The installer retains the original signed release binary when it installs the service. For a private CA or a PC that requires signed installers, use the manual process below.

## 1. Get a console and the signed downloads for manual setup

Sign in to your organization's flyw8t console as an administrator or an assigned technician. If you're hosting your first instance, follow the Compose setup using the release's source, set its public HTTPS URL, and complete the initial administrator sign-in. The default Compose address is loopback. For a separate endpoint, give it a reachable HTTPS hostname and allow WebSocket upgrades at the proxy. [Server setup and HTTPS](deployment.md#server-with-docker-compose)

The download links in your console match its release. Choose **flyw8t-agent** for the endpoint and **flyw8t-technician** for your workstation. Each Windows x64 filename ends in `x86_64-pc-windows-msvc.exe`. Download **SHA256SUMS** from the same release as the executable. [All beta releases and checksums](https://github.com/spilloid/flyw8t/releases)

Use a folder you control. The console's setup file and its clipboard fallback both verify the agent. For the Technician app or a manual agent install, verify the download before opening it.

<details>
<summary>Verify a Windows download manually</summary>

Open PowerShell in the download folder. Set `$role` to `technician` or `agent`.

```powershell
$role = 'technician'
$files = @(Get-ChildItem -File -Filter "flyw8t-$role-v*-x86_64-pc-windows-msvc.exe")
if ($files.Count -ne 1) { throw "Expected one Windows $role download in this folder." }
$file = $files[0]
$hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
if ((Get-Content -LiteralPath .\SHA256SUMS -ErrorAction Stop) -notcontains "$hash  $($file.Name)") {
    throw "SHA256SUMS does not match $($file.Name)."
}
$sig = Get-AuthenticodeSignature -LiteralPath $file.FullName
if ($sig.Status -ne 'Valid' -or !$sig.TimeStamperCertificate -or
    $sig.SignerCertificate.GetNameInfo('SimpleName', $false) -ne 'Joseph Spillers') {
    throw "Expected a valid, timestamped signature from Joseph Spillers. Status was $($sig.Status)."
}
"Verified $($file.Name)"
```

</details>

## 2. Enroll the agent locally

1. Open **Devices → Enroll a Windows device** and choose the organization that owns this PC. An administrator can create an organization in **Organizations**.
2. On the Windows PC, save the signed Windows agent and **SHA256SUMS** in the same folder. Expand **Manual setup downloads** if that section is shown. Keep both filenames. Select a site if needed, leave **Devices** at **1**, and create a manual enrollment token. Keep the page open.
3. Save **Download setup file** beside the agent and SHA256SUMS. Open PowerShell **as Administrator** in that folder and run `.\Install-Flyw8t.ps1`. Paste the token at the prompt. Setup verifies the signed download, enrolls the PC, and starts the service. Copy the device ID it prints.

   **Copy setup commands** is available under **Manual setup commands**. If Windows policy blocks unsigned scripts, follow the manual enrollment commands below with your current execution policy.

Open **Devices** and look for **Connected · live** next to this PC. If the agent reports an existing identity, preserve its state and follow the [existing enrollment instructions](deployment.md#existing-test-enrollment).

<details>
<summary>Manual enrollment for restricted PowerShell, v0.1.6, or a private certificate authority</summary>

Open **Organizations**, choose the organization, set **Devices** to **1** and select **Create enrollment token**. Verify the download using the manual check above and rename it to `flyw8t-agent.exe`. Open an elevated PowerShell in that folder. Enter your console URL and paste the token when prompted. For a private CA, add `--ca-cert .\ca.pem` to the enrollment command and put your administrator's CA certificate at that path.

```powershell
$server = Read-Host 'Public URL of your flyw8t console'
$token = Read-Host 'Single-use enrollment token' -AsSecureString
try {
    $env:FLYW8T_ENROLL_TOKEN = [Net.NetworkCredential]::new('', $token).Password
    .\flyw8t-agent.exe enroll --server $server
    if ($LASTEXITCODE -ne 0) { throw 'Enrollment failed. Read the agent message above.' }
} finally {
    Remove-Item Env:\FLYW8T_ENROLL_TOKEN -ErrorAction SilentlyContinue
    $token.Dispose()
}
```

After enrollment prints the new device ID, install and start the service in the same elevated window. The installer puts its own copy under Program Files and runs it as LocalSystem with automatic startup. Keep the default state directory so Windows protects the device key and job journal.

```powershell
.\flyw8t-agent.exe service install
if ($LASTEXITCODE -ne 0) { throw 'Service installation failed. Read the agent message above.' }
.\flyw8t-agent.exe status
Get-Service -Name flyw8t-agent
```

Expect the service to show **Running**. Copy the **device id** from `status`. If the agent reports an existing identity, preserve its state and follow the migration guidance before trying another enrollment. [Existing enrollments](deployment.md#existing-test-enrollment)

</details>

## 3. Verify the device in the console

Open **Devices** and select the endpoint. Under **Identity**, match the **Device ID** to the one you copied. Refresh until the device shows **Connected · live**. Local `status` reads the stored identity. The console badge confirms that this identity has an authenticated connection.

Under **Run a diagnostic**, choose **Run** on **System information**. Open the job and look for **Succeeded**, **Verification** set to `verified`, and the returned inventory under **Output**. If the device remains offline, check its service and `%ProgramData%\flyw8t\agent\logs\agent.log`, then verify that the endpoint can reach your console URL. [Agent deployment and logs](deployment.md)

## 4. Open its desktop from the browser

On your technician workstation, move the verified **Technician** executable to the folder where you'll keep it. Open it under the Windows account that uses your browser. Select **Browser links → Enable for this Windows user**, then close the window. If you move the app later, enable the links again from the new location.

On the Windows device page, choose a mode under **Open in Flyw8t Technician**. Accept the browser's open-app prompt if it appears. Verify the computer and mode in the native window before starting a connection.

| Choose | What happens |
| --- | --- |
| **Help someone** | **Find sessions** lists signed-in Windows sessions. Select the person and choose **View session** or **Request control**. Windows enforces session-query permissions and the host's consent policy. |
| **Unattended console** | **Check console** checks the active physical login and the owner's existing Windows shadow policy. This needs Windows session-query access and read access to the policy through Remote Registry. |
| **Windows sign-in** | **Connect** opens a native RDP sign-in using Windows credentials. It can resume an existing session or lock the physical desktop. Clipboard redirection follows your choice and the host policy. |

The agent connects outbound to the server and can check in from behind NAT. Native desktop access separately requires a route from the technician's PC to the Windows host, typically over the LAN or VPN, and the appropriate Windows permissions. For attended viewing across networks, use **Support** to invite the person to choose a tab, window or screen. The browser viewer uses WebRTC. A reachable TURN relay can carry the media when a direct connection fails. [Attended support and relay setup](deployment.md#attended-screen-sharing-across-networks)

### SSH terminal in the next Technician build

On the Windows device page, choose **Open SSH terminal**. Check the destination in Technician and choose **Open terminal**. Enter `user@host` for a different account or `user@host:port` for a different SSH port. Windows OpenSSH prompts for host verification and authentication in a separate terminal window. The endpoint needs an existing SSH service and a network route from your workstation. Closing the terminal ends the SSH session.

## End the trial

- **Unused invitation to enroll.** Open the organization's **Enrollment tokens** list and choose **Revoke** for the unused token. An already enrolled device has its own credential.
- **Enrolled device.** On the device page, an administrator opens **Revoke or retire this device**. **Revoke device credential** disconnects the agent and permanently invalidates its key on this server. **Retire device** also removes it from the active list and keeps its history. Re-enrollment requires a new device identity.
- **Endpoint service.** In an elevated PowerShell, run `& "$env:ProgramFiles\flyw8t\flyw8t-agent.exe" service uninstall`. It stops and removes the service. The installed files and state remain. After retaining any required history, remove the trial's agent files from the flyw8t directories under Program Files and ProgramData according to your retention policy. [Service locations and removal](deployment.md#windows-agent)
- **Technician workstation.** In the same Windows account, choose **Browser links → Remove for this Windows user**, close the app, then delete your copy if you no longer need it.
