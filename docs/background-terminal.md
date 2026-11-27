# Background terminal

The interactive **Background terminal** is an open 0.3.0 release requirement. The planned workflow gives the technician a PowerShell prompt from the device page through the enrolled agent. The technician can type ordinary PowerShell commands, enter responses to prompts, and interrupt the foreground command with Ctrl+C. Commands share a PowerShell process and its working directory and state. The agent carries the session outside the employee's desktop. Direct SSH is available for endpoints with an SSH service.

## Account choices

- **Background terminal** runs under the Windows identity authorized for unattended maintenance on that device. Show the identity before connecting and in the session record. Enrollment, device policy, and technician permissions govern access. Opening the background terminal requires no prompt on the employee's desktop.
- **Signed-in desktop user** is an attended path. The person approves access to their session and can end it. Their profile and active desktop session are distinct from an SSH login.
- **Service-level work** uses **Run approved script**. The Windows service normally runs these jobs as LocalSystem. Script signing and run checks also apply to schedules. The job outcome shows the account class observed on PowerShell.

## Authorization and audit

The operator approved ordinary command input inside the live technician terminal on 2026-11-26. Catalog validation and script signing govern jobs, including scheduled runs. Terminal input belongs to one technician's live session on one Windows device. Job APIs, schedules, and MCP retain their existing execution rules.

Check the technician's authenticated console session, device scope, account policy, and endpoint opt-in before attaching. Bind a short-lived attachment to the initiator and the exact agent connection. A device administrator authorizes the Windows account used for maintenance. Keep terminal activity attributable and make access revocation and local end controls close the stream.

An audit event records the initiator, device, execution account class, session lifecycle and end reason. A transport attachment and an authenticated terminal session are recorded as separate events. Audit records omit terminal contents.

The console now verifies the admission conditions. From **Check background terminal policy**, an enabled device shows **Verify session access**. The confirmation has a 30-second lifetime and works once in the same browser sign-in. It rechecks the original device connection, current local opt-in, and technician access. The agent registry checks the confirmation deadline before queuing its policy request and uses that deadline to decide whether a reply is timely. The result appears in Device Activity, linked to the policy check in Audit. The interactive session and its lifecycle remain open.

## Acceptance on Windows

On Windows, `flyw8t-agent terminal-check --powershell` checks the local PowerShell host through a Windows pseudoconsole (ConPTY). It uses fixed commands to check variable persistence, interrupt a long-running command, answer a `Read-Host` prompt, and confirm a clean exit. A second probe closes the Windows Job Object while PowerShell is waiting for input and checks that the process stops with the input pipe and pseudoconsole still open. The quiet-install test runs the installed executable as LocalSystem with `--require-session-zero`. This mode requires the diagnostic and both PowerShell processes to run in Windows session 0. [Microsoft's pseudoconsole documentation](https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session), [Windows process session API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-processidtosessionid)

Use an enrolled PC with an employee signed in and a meeting in progress. An authorized technician opens **Background terminal** through the agent and gets a PowerShell prompt. The employee keeps their desktop, keyboard, and mouse. Flyw8t presents prompts and output in the technician's terminal, with no employee approval prompt for the background session.

Install a test package that supports background installation without restarting Windows or closing the meeting app. Answer any console confirmations in the terminal, verify the installed version, and record the result in the ticket. Confirm that the meeting continues, the device history identifies the technician and session, and Ctrl+C and disconnect work. Repeat access checks with the device offline, terminal access disabled by policy, the technician's access revoked, and the agent reconnected.

## Direct SSH

Under **Technician and connection options**, **Open direct SSH** opens the existing Windows OpenSSH client over a LAN or VPN route. Specify the computer and **SSH account**. The account field accepts a user name or `DOMAIN\user`. Leave it blank for OpenSSH's default or enter `user@computer` in the computer field. OpenSSH authenticates each session independently.

`flyw8t-agent terminal-check` checks for a local SSH 2.0 greeting on port 22. The readiness check and the attachment prototype provide evidence about their own behavior. The agent-backed terminal remains open on the sprint checklist.

On an enrolled Windows agent, a local administrator can run `flyw8t-agent terminal-policy status` from an elevated console. Use `flyw8t-agent terminal-policy enable` or `flyw8t-agent terminal-policy disable` to change the local setting. The default is disabled. The device page can query the setting on the current authenticated agent connection, and a policy change is visible on the next check without restarting the service.

The check records the technician, device, time and observed policy. If access changes while a check is in flight, the audit records a denied outcome under the original request ID and Flyw8t withholds the policy result. Opening, closing and auditing an interactive PowerShell session remain pending.
