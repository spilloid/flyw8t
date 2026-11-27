Flyw8t Win32 app for Microsoft Intune

In Intune admin center, add a Windows app (Win32) and upload the included
Flyw8t-Setup-x64.intunewin.

Program
  Install command       Flyw8t-Setup-x64.exe --quiet
  Uninstall command     cmd.exe /d /c Uninstall-Flyw8t.cmd
  Install behavior      System

Requirements
  Architecture          x64
  Minimum OS            Select the oldest Windows release supported by your fleet.

Detection rules
  Rule format           Use a custom detection script
  Script file           Detect-Flyw8t.ps1
  Run as 32-bit         No
  Enforce signature     No (the detector verifies the installed agent signature)

Assign to a test group first. After installation, check the device's site,
connection, and version in Flyw8t. Uninstall removes the Windows service
and retains the endpoint identity for recovery.

For an existing enrollment, apply the signed agent upgrade separately and
wait for the agent to check in. Detection uses the original enrollment
scope, which an upgraded agent can recover from the console's token history.
Check that scope with flyw8t-agent status --json on the device.

The installer can enroll new devices only while the token is valid and has
uses left. Use a newly issued bundle for later enrollment waves. Anyone
holding the app package can recover its token, so share it privately.
