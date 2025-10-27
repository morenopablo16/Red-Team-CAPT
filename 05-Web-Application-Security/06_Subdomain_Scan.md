# 06 - Subdomain Scan

## Introduction
- Subdomain scanning discovers subdomains under a main domain (e.g., blog.example.com) that host separate services or applications. Finding subdomains expands the attack surface and can reveal admin panels, staging sites, APIs, or other sensitive endpoints.

## Definitions

### Subdomain
- A subdivision of a main domain (subdomain.domain.com). Used for content separation, multilingual sites, app/API separation (e.g., app.example.com, api.example.com).

### Vhost (Virtual Host)
- A technique to host multiple websites (different hostnames) on one physical server. Vhosts are configured at the webserver level (Apache/Nginx). Subdomains and vhosts can coexist on the same server.

## Passive vs Active Subdomain Enumeration

### Passive Enumeration
- Gathers subdomain information without querying the target directly. Sources include search engines, public certificate logs (crt.sh), VirusTotal, Censys, and third-party services.
- Advantage: no traffic to target, stealthy.

### Active Enumeration
- Direct queries to DNS or brute-force using wordlists; includes DNS brute-force, DNS zone transfer attempts, recursive querying and header-based vhost fuzzing.
- Advantage: finds up-to-date or hidden subdomains not visible via passive methods, but is noisier.

## Wordlists
- Use curated wordlists (e.g., SecLists). Wordlists can miss randomly-named subdomains but typically find many common subdomains. Example: `/root/Desktop/misc/SecLists/Discovery/DNS/subdomains-top1million-20000.txt` on HackerBox.

## Tools & Methods
- Common tools: `gobuster` (dns/vhost modes), `ffuf` (subdomain and vhost fuzzing), `theHarvester`, `dnsdumpster`, `crt.sh`, `VirusTotal`, `Censys`, and search engine dorks.

### theHarvester / OSINT
- Aggregates subdomains, emails and hosts from public sources.

### Certificate Transparency (crt.sh) / Censys
- Certificates logged publicly often list hostnames; useful to extract subdomains from issued TLS certs.

### VirusTotal & DNSdumpster
- VirusTotal stores DNS resolutions and artifacts; DNSdumpster provides DNS maps and host records.

## Gobuster (DNS & Vhost modes)

- `gobuster dns -d example.com -w /path/to/wordlist` — DNS brute-force mode: append words to domain and test resolution.
- `gobuster vhost -u https://example.com -w /path/to/wordlist` — Vhost mode fuzzes the Host header against an IP/URL to find virtual hosts.
- Useful flags: `-d/--domain`, `-w/--wordlist`, `-t/--threads`, `--show-cname`, `--show-ips`, `--wildcard`, and `--exclude-length` to filter responses by size.

## FFUF (subdomain & vhost fuzzing)

- Subdomain fuzzing: `ffuf -w /path/to/wordlist -u https://FUZZ.example.com/`.
- Vhost fuzzing (Host header): `ffuf -w /path/to/wordlist -u https://example.com -H 'Host: FUZZ.example.com'`.
- Common technique: filter responses by size (`-fs`) or other matchers to identify VHosts that return different content.

## Vhost fuzzing notes
- Because vhost fuzzing only changes the Host header, many requests will return the same status (e.g., 200). Detecting a real vhost typically relies on differences in response size or content.
- Example filters: `-fs <size>` in ffuf or `--exclude-length <size>` in gobuster to ignore constant-size noise and surface variants.

## Passive data sources & examples
- SSL/TLS certificate logs (crt.sh), Censys — extract hostnames from certs.
- VirusTotal — DNS replication/history.
- theHarvester — aggregated hosts and emails from multiple sources.

## Practical workflow recommendations
1. Start passive enumeration (crt.sh, VirusTotal, search engines, theHarvester) to build an initial list of candidate subdomains.
2. Use curated wordlists for active brute-force (Gobuster/FFUF) to expand discovery.
3. Try vhost fuzzing to find virtual-hosted sites on the same IP (filter by size/content).
4. Note: obtain authorization before active scanning; active methods are noisy.

## Summary
- Subdomain scanning combines passive OSINT with active brute-force and vhost fuzzing to discover subdomains and hidden services. Tools like `gobuster` and `ffuf`, plus public datasets (crt.sh, VirusTotal), are key components of an effective subdomain discovery workflow.


