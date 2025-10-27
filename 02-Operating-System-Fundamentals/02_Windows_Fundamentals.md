
# 02 - Windows Fundamentals

## Windows architecture — system files (concise)
- Program Files: `C:\Program Files` (64-bit apps on 64-bit Windows)
- Program Files (x86): `C:\Program Files (x86)` (32-bit apps on 64-bit Windows)
- ProgramData: shared program data independent of user profiles
- Users: `C:\Users` contains user profiles; `C:\Users\Public` for shared files; per-user data in `AppData`
- Windows system folders: `C:\Windows`, `C:\Windows\System32`, `C:\Windows\SysWOW64`, `C:\Windows\WinSxS`
- PerfLogs: performance logs

## File systems — FAT / NTFS / exFAT (summary)
- FAT: older, simple, limited security and max file sizes.
- FAT32: popular for portable media (better than old FAT; may have file-size limits depending on implementation).
- NTFS: default modern Windows FS. Journaling, permissions (ACLs), compression, encryption, quotas — more secure and reliable.
- exFAT: designed for portable drives, supports large files, lighter than NTFS.

## Access Control (ACL) — quick
- ACLs define who can access resources and what they can do (Full control, Modify, Read & execute, List folder contents, Read, Write).
- View/change via file Properties → Security tab (or use administrative tools).

## NTFS features to note
- Alternate Data Streams (ADS): hidden streams attached to files (used for metadata but can hide malware).
- Shadow Copy: point-in-time copies for file recovery — not a guaranteed defense against ransomware (malware can delete shadow copies).

## Windows user structure & account types
- Administrators: full system control; install software; change settings — should be limited to trusted users.
- Standard Users: limited permissions; run apps, edit files, but not change system settings.
- Other types: Guest, Assigned Access (kiosk-like).

## Managing accounts
- Local Users and Groups (`lusrmgr`) to create/manage local accounts and groups.

## User Account Control (UAC)
- UAC prompts for elevation when actions require admin privileges.
- Levels: Always notify → Default (notify for program changes) → Notify w/o dimming → Never notify (disabled).
- Pros: security, control; Cons: annoyance, possible app incompatibility.

## Windows history & versions (brief)
- Windows started 1985; milestones: Windows 3.0 (1990), NT line introduced NTFS (1993), XP (2001), Vista (2006), Windows 7/8/10, Windows 11 current.
- Course focuses on Windows 10 (common) though Windows 11 is current; server versions exist (e.g., Windows Server 2025 mentioned).

## Access methods
- Local access: physical login at machine.
- Remote access: RDP (Remote Desktop Protocol) — use RDP client (e.g., Remmina). Requires RDP enabled and credentials.

## Interface overview
- Desktop, Start Menu, Search Box, Taskbar — main GUI components.

## Services & processes — monitoring tools
- Services: background programs providing system functions.
- Processes: running program instances (use Task Manager / Resource Monitor).

### Task Manager (key tabs)
- Processes: list running apps and processes; can terminate.
- Performance: CPU, memory, disk, network graphs.
- App history: resource usage history.
- Startup: manage startup programs.
- Users: show logged-on users.
- Details: extended process info (username, CPU, memory).
- Services: start/stop services.

### Resource Monitor
- Detailed view of CPU, Memory, Disk, Network usage and which processes access files/ports.

## Sysinternals suite (useful tools)
- Process Explorer: detailed process, handles, DLLs, child processes, search capability.
- Autoruns: view/manage startup items.
- DiskMon: monitor disk activity.

## Configuration tools
- Settings (modern) vs Control Panel (classic). Settings is the current preferred UI; Control Panel still exists for legacy options.
- MSConfig: manage startup, boot options, services, and quick access to tools.
- Registry (`regedit`): central configuration database; dangerous to edit without care.
- Local Group Policy: manage settings on a single machine (GPOs are domain-managed centrally).

## Command-line interfaces
- Command Prompt (`cmd`): classic CLI (commands: `tasklist`, `whoami`, `cls`).
- PowerShell: modern CLI & scripting (object-based, cmdlets, `.ps1` scripts). Recommended over `cmd`.
- Example troubleshooting: `ipconfig` (network info), `ipconfig -?` for help.

## Security features (device & OS)
### Core isolation & Memory integrity
- Core isolation: virtualization-based protection for sensitive processes (Memory integrity prevents tampering with critical memory areas).

### TPM / Security Processor
- TPM: hardware module to securely store keys, biometrics, and other sensitive secrets.

### BitLocker
- Full-disk encryption feature. Protects data at rest; requires recovery key to access encrypted drives.

### Windows Hello
- Biometric or PIN-based auth (facial, fingerprint, iris). More secure than passwords.

### FIDO2 Security Keys
- Hardware keys for 2FA/passwordless auth (USB, NFC). Uses asymmetric keys bound to device.

## Windows Update & Defender (concise)
- Windows Update: monthly Patch Tuesday (second Tuesday) for security updates; can have out-of-cycle updates for urgent patches.

### Windows Security app features
- Virus & Threat Protection: real-time protection, Quick/Full/Custom/Offline scans.
- Protection settings: Real-time Protection, Cloud-Delivered Protection, Automatic Sample Submission, Tamper Protection, Controlled Folder Access, Exclusions, Notifications.
- Firewall & Network Protection: manage Defender Firewall, network profiles (Domain, Private, Public), inbound/outbound rules and logs.
- App & Browser Control: reputation-based protection and exploit protection (applies OS or app-level mitigations).

---
