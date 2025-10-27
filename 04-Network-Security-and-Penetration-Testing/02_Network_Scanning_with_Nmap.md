# 02 - Network Scanning with Nmap

## Introduction
- Modern networks are dynamic; penetration testing helps assess and secure them. Nmap is a core tool for network scanning in pentesting.

## What is Network Scanning?
- Process of discovering devices, services, and open ports on a network to map its state and find vulnerabilities.
- Objectives: identify vulnerabilities, map topology, monitor services.

## Types of Scanning
- Host discovery: find active hosts in IP ranges.
- Port scanning: discover services listening on ports.
- Network mapping: identify devices and configurations (firewalls, rules).
- OS identification: fingerprint operating systems.
- Vulnerability scanning: check devices for known vulnerabilities.

## Basic Networking Concepts (brief)
- TCP: reliable, ordered, error-checked delivery; uses flags like SYN, ACK, FIN, RST, PSH, URG.
- IP: addressing of devices on networks.
- Port: logical service endpoint (e.g., 80 HTTP, 443 HTTPS).
- TCP/IP model: Application, Transport, Internet, Network Access layers.

## Nmap Overview & History
- First released 1997 as a simple Linux port scanner; evolved to include OS/version detection, NSE (scripting engine), GUI, cross-platform support.
- Nmap is used for discovery, port scanning, vulnerability checks, and system management.

## Stages of an Nmap Scan
1. Target identification
2. Host discovery
3. Port scanning
4. Version detection
5. OS detection
6. Traceroute
7. NSE scripting
8. Reporting (multiple output formats)

## Basic Usage
- Syntax: `nmap [Scan Type(s)] [Options] {target specification}`
- Nmap supports hostnames, IPs, networks, input lists, exclusions, and more.

## Host Discovery Techniques
- Nmap can perform list scans (-sL), ping scans (-sn), and skip discovery (-Pn).
- Host discovery probes can include TCP SYN/ACK, UDP, ICMP types, and IP protocol pings.

### List Scan (-sL)
- Lists targets without sending packets; performs reverse DNS lookups by default.

### Ping Scan (-sn)
- Performs host discovery (no port scans) — useful to count hosts or monitor availability.

### No Ping (-Pn)
- Skips discovery and treats all hosts as up; useful when targets block ICMP or ping probes.

## Port Scanning Basics
- `nmap <target>` scans the default 1,000 TCP ports and classifies ports as open/closed/filtered/unfiltered/open|filtered/closed|filtered.

## Common Port Examples
- TCP common ports (e.g., 22 SSH, 80 HTTP, 443 HTTPS, 3389 RDP, 445 SMB).
- UDP common ports (e.g., 53 DNS, 161 SNMP, 69 TFTP).

## Port States (as Nmap reports)
- Open: application accepts connections.
- Closed: reachable but no application listening.
- Filtered: probes are blocked by filtering (firewall).
- Unfiltered: reachable but state (open/closed) unknown.
- Open|Filtered and Closed|Filtered: ambiguous states used for specific scan types.

## Scan Types & Examples

### Fast Scan (`-F`, `--top-ports`)
- `-F`: scan most common ports (faster); `--top-ports N` scans the top N ports.

### Specific Port Scanning (`-p`)
- `-p 80` single port, `-p 22,80,443` multiple ports, `-p 1000-2000` range, `-p-` all ports (1–65535).

### Aggressive Scan (`-A`)
- `-A` enables OS detection, version detection, script scanning, and traceroute for comprehensive results.

### TCP SYN (Stealth) Scan (`-sS`)
- Sends SYN and interprets SYN/ACK as open; does not complete the TCP handshake (half‑open). Fast and stealthy but may trigger IDS.

### TCP Connect Scan (`-sT`)
- Completes full TCP connection using the OS connect() call. Useful when raw sockets are unavailable; more likely to be logged.

### UDP Scan (`-sU`)
- Sends UDP packets; states include open, open|filtered, closed, filtered. Generally slower and more challenging to interpret.

### TCP FIN, NULL, Xmas (`-sF`, `-sN`, `-sX`)
- Special packet scans that set unusual flag combinations to exploit RFC 793 behavior; good for bypassing some filters but less reliable on all systems.

### TCP ACK Scan (`-sA`)
- Maps firewall rules and determines whether ports are filtered/unfiltered; does not reliably reveal open ports.

### TCP Idle (Zombie) Scan (`-sI`)
- Uses a third‑party 'zombie' host to relay probes, concealing the attacker's IP. Very stealthy but requires a suitable idle zombie.

## Timing Templates (`-T0`..`-T5`)
- Templates control scan speed/stealth: paranoid (0), sneaky (1), polite (2), normal (3), aggressive (4), insane (5). Choose based on network reliability and stealth needs.

## Service Version Detection (`-sV`)
- `-sV` probes open ports to identify service names and versions — essential for vulnerability assessments and inventory.

## OS Detection (`-O`)
- `-O` uses TCP/IP stack fingerprinting to guess target OS; results may be unreliable if not enough info (need some open & closed ports).

## Nmap Scripting Engine (NSE)
- NSE allows Lua scripts for discovery, versioning, vulnerability checks, and exploitation. Scripts are categorized (auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln).
- Run default scripts with `-sC`, or specific categories with `--script=<category>`, and pass arguments via `--script-args`.

## Output & Reporting
- Output formats: normal (-oN), XML (-oX), grepable (-oG), script output (-oS), or combined (-oA). Use `-v` for verbosity and `-d` for debugging.

## Practical Tips (from provided text)
- Use `-Pn` when targets block pings.
- Combine `-sU` with TCP scans to check both protocols.
- Use `-sS` for speed/stealth when privileged; use `-sT` when unprivileged.
- Use timing templates to balance speed vs stealth; `-T4` is often a reasonable aggressive default on reliable networks.
- Use NSE scripts for discovery and vulnerability checks; be cautious with intrusive scripts.
