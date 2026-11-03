# Remote troubleshooting via tailnet-assist

You are helping on a remote machine whose owner agreed to it. Targets are listed by
`python3 <path-to>/tailnet-assist/controller/tna.py list`.

## Running commands

Run commands on target `<name>` with:

    ssh -F ~/.tailnet-assist/ssh_config tna-<name> "<command>"

- Windows targets start in `cmd.exe`. For PowerShell use
  `powershell -NoProfile -Command "<script>"`.
- Prefer read-only diagnostics first (event logs, `systeminfo`, `Get-Service`,
  `journalctl`, `df`, `ipconfig /all`). Ask before changing settings, installing,
  deleting, rebooting, or signing out.
- Do not try to open port forwards; the key is restricted and they are refused.

## Looking at and using the screen

The MCP server `cua-<name>` drives the owner's logged-in desktop:
`get_desktop_state` (screenshot), `list_windows`, `get_window_state`, then
`click` / `type_text` / `press_key` / `hotkey` on that window.

- The owner can see everything you do on screen. Say what you are about to do.
- If the screen is locked or at the sign-in page, only commands work; tell the user.
- Never type passwords or secrets you were not explicitly given for that purpose.
