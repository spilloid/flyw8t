// Runs only inside the signing rehearsal's disposable, authenticated loopback fixture.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const lines = text => text.replaceAll('\r\n', '\n');

export async function exerciseSignedTrial({ origin, binaries, shell, call, evaluate, waitFor }) {
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
    const encoded = Buffer.from("$ErrorActionPreference = 'Stop'\n" + script, 'utf16le').toString('base64');
    const child = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
      cwd: dir, env: { ...process.env, ...env }, encoding: 'utf8', timeout: 90000, windowsHide: true
    });
    if (child.error || child.status !== 0) throw Error(stage + ' failed (exit ' + child.status + ')');
    return child.stdout.trim();
  }

  powershell('Confirm clean hosted runner', [
    "if (Get-Service flyw8t-agent -ErrorAction SilentlyContinue) { throw 'Existing service' }",
    "if ((Test-Path (Join-Path $env:ProgramData 'flyw8t')) -or (Test-Path (Join-Path $env:ProgramFiles 'flyw8t'))) { throw 'Existing installation' }",
    "if ($env:FLYW8T_AGENT_STATE_DIR -or $env:FLYW8T_ENROLL_TOKEN) { throw 'Existing agent configuration' }"
  ].join('\n'));

  await call('Page.navigate', { url: origin + '/devices' });
  const setupLink = 'a[href^="/organizations/"][href$="#enroll-device"]';
  await waitFor(() => evaluate('!!document.querySelector(' + JSON.stringify(setupLink) + ')'), 'Device enrollment shortcut missing');
  await evaluate('document.querySelector(' + JSON.stringify(setupLink) + ').click()');
  const form = 'form[action$="/enrollment-tokens"]';
  await waitFor(() => evaluate('!!document.querySelector(' + JSON.stringify(form) + ')'), 'Organization enrollment form missing');
  await evaluate('(() => { const f=document.querySelector(' + JSON.stringify(form) + ');' +
    'if (new URL(f.action).origin!==location.origin || f.method!=="post" || f.elements.max_uses.value!=="1") throw Error();' +
    'f.requestSubmit(); return true; })()');
  await waitFor(() => evaluate('!!document.querySelector("#enrollment-commands")'), 'Enrollment setup commands missing');
  const text = await evaluate('document.querySelector("#enrollment-commands").value');
  assert.ok(typeof text === 'string' && lines(text) === expected, 'Displayed commands differ from the reviewed local template');

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
    // Preserve the copied block, including its actual signature/hash checks and service install.
    // Supply only its interactive Read-Host response, once, inside this PowerShell process.
    powershell('Run signed enrollment commands', [
      "$trialSecret = ConvertTo-SecureString $env:FLYW8T_TRIAL_INPUT -AsPlainText -Force",
      'Remove-Item Env:FLYW8T_TRIAL_INPUT',
      '$script:reads = 0',
      'function Read-Host([string]$Prompt, [switch]$AsSecureString) {',
      "  if (!$AsSecureString -or $script:reads -ne 0 -or $Prompt -cne 'Paste the enrollment token from the console') { throw 'Unexpected prompt' }",
      '  $script:reads++; return $trialSecret.Copy()',
      '}',
      copied,
      "$trialSecret.Dispose(); if ($script:reads -ne 1) { throw 'Expected one secure prompt' }"
    ].join('\n'), { FLYW8T_TRIAL_INPUT: token });

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
    console.log('Verified signed enrollment from copied commands, Running service and matching live Devices entry.');
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
