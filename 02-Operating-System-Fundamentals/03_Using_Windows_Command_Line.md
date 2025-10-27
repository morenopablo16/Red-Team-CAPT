# 03 - Using Windows Command Line

## Overview
- Two CLIs on Windows: CMD (legacy, MS-DOS style) and PowerShell (modern, object-oriented).
- PowerShell is more powerful and suited to automation, scripting, and secure practices (cmdlets, objects, code signing, execution policies). CMD remains for compatibility with older scripts.

## PowerShell installation (summary)
- Windows: preferred via Winget. Example: `winget search Microsoft.PowerShell` then `winget install --id Microsoft.PowerShell --source winget`.
- Linux (Ubuntu): `sudo snap install powershell --classic`.
- macOS: install via Homebrew: `brew install powershell/tap/powershell`.

## CMD (basic commands) — quick reference (examples from provided text)
- `dir` : list files/folders in current directory.
- `cd`  : change directory (`.` current, `..` parent).
- `mkdir` : create directory.
- `rmdir` : remove an empty directory.
- `copy` : copy files (`copy src dest`).
- `move` : move or rename files/directories.
- `del` : delete files.

## PowerShell basics
- Start PowerShell (or PowerShell ISE for a GUI that supports writing, testing, and debugging scripts).
- Check version: `$PSVersionTable`.
- PowerShell commands are often called cmdlets and use `Verb-Noun` naming (e.g., `Get-Process`, `Get-Service`).

### Help and discovery
- `Get-Help <cmdlet>` — view help for a command (e.g., `Get-Help Get-Help`).
- `Get-Command` — list available commands, cmdlets, functions, aliases, filters, scripts, and application commands.
- `Update-Help` — update local help pages (requires elevated privileges).

### Aliases and tab completion
- Aliases provide shortcuts (e.g., `cd` is an alias for `Set-Location`). Use `alias` to list them or `alias cd` to inspect a specific alias.
- Tab completion completes command or parameter names and cycles through matches when pressed repeatedly.

## File and directory cmdlets
- `Get-ChildItem` (alias `ls`) — list directory contents.
- `Set-Location` (alias `cd`) — change working directory.
- `New-Item` — create files or directories (use `-ItemType Directory` for directories).
- `Remove-Item` (alias `rm`) — delete files or directories.
- `Copy-Item` (alias `cp`) — copy files or directories.
- `Move-Item` (alias `mv`) — move or rename files/directories.
- `Get-Content` (alias `cat`) — display file contents.

## Process and service management
- `Get-Process` — list running processes; filter with `-Name` or pipe to `Select-Object` / `Where-Object`.
- `Stop-Process -Id <pid>` or `Stop-Process -Name <name>` — terminate a process.
- `Get-Service` — list services and their status.
- `Start-Service` / `Stop-Service` — start or stop a service.

## Object selection, filtering, and text search
- PowerShell uses objects; pipe (`|`) passes objects between cmdlets.
- `Select-Object` — choose specific properties (e.g., `Get-Process | Select-Object ProcessName, Id`).
- `Where-Object` — filter objects (e.g., `Get-Service | Where-Object Status -eq "Running"`). Operators include `-eq`, `-ne`, `-gt`, `-ge`, `-lt`, `-le`.
- `Select-String` — search text/regex in files or strings (`Select-String -Pattern "today" .\\file.txt`).

## User and group management (local and Active Directory)
- RSAT provides server/AD modules and GUI tools; install via Settings → Apps → Optional features → Add a feature → search for RSAT.

Local users (examples):
- `Get-LocalUser` — list local users.
- `New-LocalUser -Name "j.doe" -Password (ConvertTo-SecureString -String 'password123' -AsPlainText -Force)` — create a local user.
- `Set-LocalUser`, `Disable-LocalUser`, `Enable-LocalUser`, `Remove-LocalUser` — manage local accounts.

Local groups (examples):
- `Get-LocalGroup`, `New-LocalGroup -Name "Students"`, `Set-LocalGroup`, `Add-LocalGroupMember`, `Remove-LocalGroupMember`, `Remove-LocalGroup`.

Active Directory (requires AD modules / RSAT):
- `Get-ADUser`, `New-ADUser`, `Set-ADUser`, `Remove-ADUser` — manage AD users.
- `Get-ADGroup`, `New-ADGroup`, `Set-ADGroup`, `Get-ADGroupMember`, `Add-ADGroupMember`, `Remove-ADGroupMember`, `Remove-ADGroup` — manage AD groups.

## Networking and connection testing
- `Get-NetIPAddress` — retrieve IP address and interface configuration (PowerShell cmdlet).
- Legacy/commonly used tools: `ipconfig`, `netstat`, `nslookup`, `arp -a` — still useful inside PowerShell.
- `Test-NetConnection` — test network connectivity (ping-like checks).
- `Invoke-WebRequest -Uri <url> -OutFile <file>` — download files from the web.

## System and forensic information
- `Get-ComputerInfo` — retrieve OS and hardware details.
- `Get-WmiObject -Class win32_OperatingSystem` — query WMI for OS info.
- `Get-Hotfix` — view installed updates.
- To inspect Defender-related services: `Get-Service | Where-Object DisplayName -like '*Defender*'`.

## Files, ACLs and hashes
- Find text in files: `Get-ChildItem -Recurse *.* | Select-String -Pattern "SEARCH_STR"`.
- View ACL: `Get-Acl file.txt`.
- Compute file hash: `Get-FileHash file.txt`.

## PowerShell scripting fundamentals
- Scripts are plain text files with `.ps1` extension. Use PowerShell ISE or any editor to write, test, and debug.
- Variables: `$name = "John Doe"`, `$age = 30`.
- Conditionals: `if` / `else` examples provided in source.
- `switch` statement example provided (useful for branching on string values such as day-of-week).
- Loops: `for`, `while`, `do { } while`, and `foreach` examples included in source text.

## PowerShell Gallery and modules
- The PowerShell Gallery hosts modules and scripts; use `Find-Module` / `Install-Module` to discover and install (example: `Find-Module -Name "sysinternals"` then `Install-Module -Name SysInternals`).

## Quick notes / study tips (student-style)
- Prefer PowerShell for automation: it's object-oriented and has richer cmdlets and security features.
- Use `Get-Help` + `Get-Command` + `Get-ChildItem` to discover tooling quickly.
- Practice piping + `Select-Object` / `Where-Object` to extract only the fields you need.
- When working on domain environments, install RSAT to access AD cmdlets safely and always run elevated when required.

-
