// Runs only inside the signing rehearsal's disposable, authenticated loopback fixture.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const lines = text => text.replaceAll('\r\n', '\n');

export async function exerciseSignedTrial({ origin, binaries, shell, call, evaluate, waitFor, organization, site, otherSite }) {
  assert.equal(process.platform, 'win32');
  assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
  assert.equal(process.env.RUNNER_OS, 'Windows');
  assert.match(origin, /^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/);
  const dir = await fs.mkdtemp(path.join(process.env.RUNNER_TEMP, 'signed-trial-'));
  const manifest = await fs.readFile('Cargo.toml', 'utf8');
  const version = /\[workspace\.package\][^\[]*?^version\s*=\s*"(\d+\.\d+\.\d+)"/m.exec(manifest)?.[1];
  assert.ok(version, 'Workspace package version missing');
  const name = 'flyw8t-agent-v' + version + '-x86_64-pc-windows-msvc.exe';
  const agent = path.join(dir, name);
  await fs.copyFile(path.join(binaries, 'flyw8t-agent.exe'), agent);
  const hash = createHash('sha256').update(await fs.readFile(agent)).digest('hex');
  await fs.writeFile(path.join(dir, 'SHA256SUMS'), hash + '  ' + name + '\n', { flag: 'wx' });
  const template = await fs.readFile('crates/flyw8t-server/src/enroll-windows.ps1', 'utf8');
  const expected = lines(template.replaceAll('__VERSION__', version).replaceAll('__SERVER_URL__', "'" + origin + "'"));

  function powershell(stage, script, env = {}) {
    // The single-use token is supplied only through the child environment. Capture all child
    // output, including errors, so an unexpected server/agent response cannot log the token.
    const input = "$ErrorActionPreference = 'Stop'\ntry {\n" + lines(script);
    const reportFailure = [
      '} catch {',
      "  $hint = 'PowerShell'",
      '  switch -Regex ($_.Exception.Message) {',
      "    'module could not be loaded' { $hint = 'module-load'; break }",
      "    'owned by .+, not Administrators or SYSTEM' { $hint = 'file-owner'; break }",
      "    'is not as .+ made it|permissions from the folder above|could not be locked' { $hint = 'directory-permissions'; break }",
      "    'access is denied|error 5\\b' { $hint = 'access-denied'; break }",
      "    'enrollment refused' { $hint = 'token-refused'; break }",
      "    'connecting to .+|connect timed out' { $hint = 'server-connection'; break }",
      "    'does not match SHA256SUMS' { $hint = 'checksum'; break }",
      "    'timestamped Flyw8t publisher signature' { $hint = 'publisher-signature'; break }",
      "    'belongs to a different release' { $hint = 'version'; break }",
      "    'two downloads|together in .+ and try again' { $hint = 'setup-location'; break }",
      "    'Unexpected prompt|Expected one secure prompt' { $hint = 'setup-prompt'; break }",
      "    'service installation failed|Windows has not confirmed' { $hint = 'service-start'; break }",
      '  }',
      "  if ($_.Exception -is [System.Management.Automation.PSSecurityException] -and $trialPrompt.Reads -eq 0) { $hint = 'download-policy' }",
      "  [Console]::Error.WriteLine(('FLYW8T-TRIAL-FAIL {0} {1} {2}' -f $_.InvocationInfo.ScriptLineNumber, $hint, $_.CategoryInfo.Category))",
      '  exit 1',
      '}'
    ].join('\n');
    const encoded = Buffer.from(input + '\n' + reportFailure, 'utf16le').toString('base64');
    const child = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
      cwd: dir, env: { ...process.env, ...env }, encoding: 'utf8', timeout: 90000, windowsHide: true
    });
    if (child.error || child.status !== 0) {
      // Only return our own labels and numeric source locations. Other child output may
      // include a token, a command line or untrusted server text.
      const marker = /^FLYW8T-TRIAL-FAIL (\d{1,5}) (PowerShell|module-load|file-owner|directory-permissions|access-denied|token-refused|server-connection|checksum|publisher-signature|version|setup-location|setup-prompt|service-start|download-policy) ([A-Za-z]+)\r?$/m.exec(child.stderr ?? '');
      let detail = child.error?.code === 'ETIMEDOUT' ? ', timed out' : '';
      if (marker) {
        const line = Number(marker[1]);
        detail = ', ' + marker[2] + '/' + marker[3] + ', PowerShell line ' + line;
        const offset = input.indexOf(expected);
        if (offset >= 0) {
          const templateLine = line - input.slice(0, offset).split('\n').length + 1;
          if (templateLine > 0 && templateLine <= expected.trimEnd().split('\n').length) {
            detail += ', enroll-windows.ps1 line ' + templateLine;
          }
        }
      }
      const error = Error(stage + ' failed (exit ' + child.status + detail + ')');
      error.trialHint = marker?.[2];
      throw error;
    }
    return child.stdout.trim();
  }

  powershell('Confirm clean hosted runner', [
    "if (Get-Service flyw8t-agent -ErrorAction SilentlyContinue) { throw 'Existing service' }",
    "if ((Test-Path (Join-Path $env:ProgramData 'flyw8t')) -or (Test-Path (Join-Path $env:ProgramFiles 'flyw8t'))) { throw 'Existing installation' }",
    "if ($env:FLYW8T_AGENT_STATE_DIR -or $env:FLYW8T_ENROLL_TOKEN) { throw 'Existing agent configuration' }"
  ].join('\n'));

  await call('Page.navigate', { url: origin + '/devices' });
  const organizationPath = '/organizations/' + organization;
  const setupLink = 'a[href="' + organizationPath + '#enroll-device"]';
  await waitFor(() => evaluate('!!document.querySelector(' + JSON.stringify(setupLink) + ')'), 'Device enrollment shortcut missing');
  await evaluate('document.querySelector(' + JSON.stringify(setupLink) + ').click()');
  const form = '#windows-enrollment-form';
  await waitFor(() => evaluate('!!document.querySelector(' + JSON.stringify(form) + ')'), 'Organization enrollment form missing');
  await evaluate('(() => { const f=document.querySelector(' + JSON.stringify(form) + ');' +
    'if (new URL(f.action).origin!==location.origin || f.method!=="post" || f.elements.max_uses.value!=="1") throw Error();' +
    'f.elements.site.value=' + JSON.stringify(site) + '; if (!f.elements.site.value) throw Error();' +
    'f.requestSubmit(); return true; })()');
  await waitFor(() => evaluate('!!document.querySelector("#enrollment-commands")'), 'Enrollment setup commands missing');
  const text = await evaluate('document.querySelector("#enrollment-commands").value');
  assert.ok(typeof text === 'string' && lines(text) === expected, 'Displayed commands differ from the reviewed local template');

  await call('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: dir });
  await evaluate('document.querySelector(\'a[download="Install-Flyw8t.ps1"]\').click()');
  const setup = path.join(dir, 'Install-Flyw8t.ps1');
  await waitFor(async () => {
    try { await fs.access(setup); return true; }
    catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  }, 'Browser did not save the setup file');
  assert.ok(lines(await fs.readFile(setup, 'utf8')) === '\uFEFF' + expected,
    'Downloaded setup file differs from the reviewed template');

  // Copy only the setup commands to the disposable user's clipboard. Read the token from DOM
  // into process memory separately, just as the person supplies it at the secure prompt.
  await call('Browser.grantPermissions', { origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] });
  await call('Page.bringToFront');
  await call('Runtime.evaluate', { expression: 'document.querySelector("#copy-commands").click()', userGesture: true });
  await waitFor(() => evaluate('document.querySelector("#commands-status")?.textContent === "Setup commands copied."'), 'Copy setup commands failed');
  const clipboard = await call('Runtime.evaluate', {
    expression: 'navigator.clipboard.readText()', userGesture: true, awaitPromise: true, returnByValue: true
  });
  const copied = clipboard.result?.value;
  assert.ok(typeof copied === 'string' && lines(copied) === expected, 'Clipboard differs from reviewed enrollment template');
  const token = await evaluate('document.querySelector("#enrollment-token").value');
  assert.ok(typeof token === 'string' && /^fw8e_[A-Za-z0-9_-]{43}$/.test(token), 'Single-use token missing');

  try {
    const prompt = [
      "$trialSecret = ConvertTo-SecureString $env:FLYW8T_TRIAL_INPUT -AsPlainText -Force",
      'Remove-Item Env:FLYW8T_TRIAL_INPUT',
      '$trialPrompt = @{ Reads = 0 }',
      'function Read-Host([string]$Prompt, [switch]$AsSecureString) {',
      "  if (!$AsSecureString -or $trialPrompt.Reads -ne 0 -or $Prompt -cne 'Paste the enrollment token from the console') { throw 'Unexpected prompt' }",
      '  $trialPrompt.Reads++; return $trialSecret.Copy()',
      '}'
    ];
    // The file and clipboard script run in different PowerShell scopes. The prompt and
    // its caller share a state object so both paths can verify the same one prompt.
    const finish = "$trialSecret.Dispose(); if ($trialPrompt.Reads -ne 1) { throw 'Expected one secure prompt' }";
    const input = { FLYW8T_TRIAL_INPUT: token };
    let setupSource = 'downloaded setup file';
    try {
      powershell('Run downloaded enrollment file', [...prompt, '& .\\Install-Flyw8t.ps1', finish].join('\n'), input);
    } catch (error) {
      if (error.trialHint !== 'download-policy') throw error;
      // The download and clipboard already matched the reviewed template. The runner's
      // PowerShell policy can deny the file before enrollment. Exercise the copied commands
      // in that case and keep the policy in effect.
      setupSource = 'reviewed setup commands';
      console.log('PowerShell policy refused the downloaded setup file before the enrollment prompt. Checking the clipboard setup path.');
      powershell('Run reviewed enrollment commands', [...prompt, copied, finish].join('\n'), input);
    }

    assert.equal(powershell('Read service status', '(Get-Service flyw8t-agent).Status.ToString()'), 'Running');
    const status = execFileSync(agent, ['status'], { encoding: 'utf8', windowsHide: true, timeout: 15000 });
    const id = /^device id:\s+([0-9a-f-]{36})\s*$/mi.exec(status)?.[1];
    assert.ok(id, 'Installed agent must report its enrolled device ID');
    // This server-rendered page disallows fetch in its CSP. Use normal browser navigation
    // for each fresh observation and read only the row for the identity reported by the agent.
    const selector = JSON.stringify('a[href="/devices/' + id + '"]');
    let live = false;
    for (let attempt = 0; attempt < 20; attempt++) {
      await call('Page.navigate', { url: origin + '/devices' });
      await waitFor(() => evaluate('location.pathname === "/devices" && document.readyState === "complete"'), 'Devices page missing');
      live = await evaluate('document.querySelector(' + selector + ')?.closest("tr")?.textContent.includes("Connected · live") === true');
      if (live) break;
      await delay(1500);
    }
    assert.ok(live, 'Newly enrolled device did not report Connected · live');
    const deviceUrl = origin + '/devices/' + id;
    const checkUrl = deviceUrl + '/physical-console/check';
    const checkForm = JSON.stringify('form[method="post"][action="/devices/' + id + '/physical-console/check"]');
    await evaluate('document.querySelector(' + selector + ').click()');
    await waitFor(() => evaluate('location.href === ' + JSON.stringify(deviceUrl) +
      ' && document.readyState === "complete"'), 'Enrolled device page missing');
    await evaluate('(() => { const f = document.querySelector(' + checkForm + ');' +
      'if (!f || f.action !== ' + JSON.stringify(checkUrl) + ' || !f.elements.csrf?.value) throw Error();' +
      'f.requestSubmit(); return true; })()');
    await waitFor(() => evaluate('location.href === ' + JSON.stringify(checkUrl) +
      ' && document.readyState === "complete"'), 'Physical console check did not return');
    assert.equal(await evaluate('document.querySelector(".crumbs")?.querySelector(' + selector + ')?.href'),
      deviceUrl, 'Physical console result must identify the enrolled device');

    // Hosted runners may be locked, lack an attached console, or return inconclusive WTS
    // evidence. Accept only actual endpoint replies, never an unsupported or failed delivery.
    const observations = new Map([
      ['A user is signed in at the Windows physical console.', 'active_console'],
      ['Windows reported no active login at the physical console.', 'no_interactive_user'],
      ['Windows reported no attached physical console.', 'no_console'],
      ['Windows could not determine the physical console state.', 'unavailable'],
    ]);
    const finding = await evaluate('document.querySelector("#console-finding")?.textContent');
    assert.ok(observations.has(finding), 'The signed Windows service must answer the physical console check');
    console.log('Verified signed agent enrollment from the ' + setupSource + ', Running service and matching device console reply (' + observations.get(finding) + ').');

    await call('Page.navigate', { url: origin + organizationPath + '#enroll-device' });
    const detectorButton = 'button[name="download"][value="intune-detection"]';
    await waitFor(() => evaluate('!!document.querySelector(' + JSON.stringify(detectorButton) + ')'),
      'Intune detection download is missing');
    const detectorTemplate = await fs.readFile('crates/flyw8t-server/src/intune-detection.ps1', 'utf8');
    for (const [selectedSite, expectedExit] of [[site, 0], [otherSite, 1]]) {
      const detectorDir = path.join(dir, selectedSite);
      await fs.mkdir(detectorDir);
      await call('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: detectorDir });
      const detectorPath = path.join(detectorDir, 'Detect-Flyw8t.ps1');
      await evaluate('(() => { const b=document.querySelector(' + JSON.stringify(detectorButton) + ');' +
        'const f=b.form; if (f?.id!=="windows-enrollment-form" || f.action!==' +
        JSON.stringify(origin + organizationPath + '/enrollment-tokens') + ' || !f.elements.csrf?.value) throw Error();' +
        'f.elements.site.value=' + JSON.stringify(selectedSite) + '; if (!f.elements.site.value) throw Error();' +
        'f.requestSubmit(b); return true; })()');
      await waitFor(async () => {
        try { await fs.access(detectorPath); return true; }
        catch (error) { if (error.code === 'ENOENT') return false; throw error; }
      }, 'Browser did not save the Intune detection script');
      const expectedDetector = '\uFEFF' + lines(detectorTemplate
        .replaceAll('__SERVER_URL__', "'" + origin + "'")
        .replaceAll('__ORGANIZATION_ID__', "'" + organization + "'")
        .replaceAll('__SITE_ID__', "'" + selectedSite + "'")
        .replaceAll('__VERSION__', "'" + version + "'"));
      assert.ok(lines(await fs.readFile(detectorPath, 'utf8')) === expectedDetector,
        'Downloaded detector differs from the reviewed site-specific template');
      const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', detectorPath], {
        cwd: dir, encoding: 'utf8', timeout: 30000, windowsHide: true
      });
      assert.ok(!result.error && result.status === expectedExit,
        'Intune detector did not return the expected exit code for the selected site');
      assert.equal(result.stdout.trim(), expectedExit === 0 ? 'Flyw8t enrollment detected' : '');
      assert.equal(result.stderr.trim(), '');
    }
    console.log('Verified the generated Intune detector against the installed signed agent for the matching and wrong site.');
  } finally {
    // The preflight required an empty service, program and state location. Check the registered
    // executable and its digest again before uninstalling the service created by this trial.
    powershell('Remove only the trial service', [
      '$svc = Get-CimInstance Win32_Service -Filter "Name = \'flyw8t-agent\'"',
      'if ($svc) {',
      "  $installed = Join-Path $env:ProgramFiles 'flyw8t\\flyw8t-agent.exe'",
      '  if (!$svc.PathName.StartsWith((\'"\' + $installed + \'" \'), [StringComparison]::OrdinalIgnoreCase)) { throw \'Unexpected service executable\' }',
      "  if ((Get-FileHash -LiteralPath $installed).Hash -ine '" + hash + "') { throw 'Different service binary' }",
      '  & $installed service uninstall',
      "  if ($LASTEXITCODE -ne 0) { throw 'Service removal failed' }",
      "  for ($i=0; $i -lt 20 -and (Get-Service flyw8t-agent -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 250 }",
      "  if (Get-Service flyw8t-agent -ErrorAction SilentlyContinue) { throw 'Service still exists' }",
      '}'
    ].join('\n'));
  }
}
