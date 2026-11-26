# Background terminal

The 0.2.0 target is an interactive **Background terminal** carried by the enrolled agent. A technician opens it from the device page and gets a PowerShell prompt by default. Output streams back, console prompts are answered in the technician's terminal, and Ctrl+C interrupts the foreground command. The terminal runs in a separate Windows session using Flyw8t's existing agent connection. Direct SSH is a separate option for endpoints with an SSH service.

## Account choices

- **Background terminal** runs under the Windows identity authorized for unattended maintenance on that device. Show the identity before connecting and in the session record. Enrollment, device policy, and technician permissions govern access. Opening the background terminal requires no prompt on the employee's desktop.
- **Signed-in desktop user** is an attended path. The person approves access to their session and can end it. Their profile and active desktop session are distinct from an SSH login.
- **Service-level work** uses **Run approved script**. The Windows service normally runs these jobs as LocalSystem. Script signing and run checks also apply to schedules. The job outcome shows the account class observed on PowerShell.

## Admission and evidence

Check the technician's authenticated console session, device scope, account policy, and endpoint opt-in before attaching. Bind a short-lived attachment to the initiator and the exact agent connection. Keep terminal activity attributable and make access revocation and local end controls close the stream.

An audit event records the initiator, device, execution account class, session lifecycle and end reason. A transport attachment and an authenticated terminal session are recorded as separate events. Audit records omit terminal contents.

## Acceptance on Windows

Use an enrolled PC with an employee signed in and a meeting in progress. An authorized technician opens **Background terminal** through the agent and gets a PowerShell prompt. The employee keeps their desktop, keyboard, and mouse. Flyw8t presents prompts and output in the technician's terminal, with no employee approval prompt for the background session.

Install a test package that supports background installation without restarting Windows or closing the meeting app. Answer any console confirmations in the terminal, verify the installed version, and record the result in the ticket. Confirm that the meeting continues, the device history identifies the technician and session, and Ctrl+C and disconnect work. Repeat access checks with the device offline, terminal access disabled by policy, the technician's access revoked, and the agent reconnected.

## Direct SSH

Under **Technician and connection options**, **Direct SSH** opens the existing Windows OpenSSH client over a LAN or VPN route. Specify the computer and **SSH account**. The account field accepts a user name or `DOMAIN\user`. Leave it blank for OpenSSH's default or enter `user@computer` in the computer field. OpenSSH authenticates each session independently.

`flyw8t-agent terminal-check` checks for a local SSH 2.0 greeting on port 22. The readiness check and the attachment prototype provide evidence about their own behavior. The agent-backed terminal remains open on the sprint checklist.

On an enrolled Windows agent, a local administrator can run `flyw8t-agent terminal-policy enable` or `flyw8t-agent terminal-policy disable` from an elevated console. The default is disabled. The device page can query the setting on the current authenticated agent connection, and a policy change is visible on the next check without restarting the service. The check records the technician, device, time and observed policy. Opening, closing and auditing an interactive PowerShell session remain pending.
