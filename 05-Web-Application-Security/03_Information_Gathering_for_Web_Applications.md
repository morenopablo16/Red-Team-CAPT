# 03 - Information Gathering for Web Applications

## Introduction

- Goal: teach methods, techniques and tools to gather information about a website for security analysis.
- Two main categories: Active and Passive information gathering.

## Active vs Passive

### Active Information Gathering
- Direct interaction with the target; may be detected and leaves traces.
- Examples: port scans, service/version scans. Treat as more aggressive and use carefully.

### Passive Information Gathering
- No direct interaction with the target; covert and leaves no traces on the target system.
- Examples: WHOIS queries, social media analysis, third‑party databases.

---

## Common tools & techniques covered in this module
- whois, technology identification (BuiltWith/Wappalyzer), Wayback Machine, Google Dorks, robots.txt, sitemap.xml, security.txt, humans.txt.
- DNS enumeration, subdomain enumeration, theHarvester, Netcraft, viewdns, mxtoolbox, gobuster, ffuf, dig/host/nslookup, curl.

## Whois

- Whois is a query/response protocol revealing domain ownership, contact info, registration/expiry dates, nameservers, registrar and status flags.
- Tools: web WHOIS services (ICANN Whois, whois.com, DomainTools) or CLI `whois`.
- Example CLI output shows registrar, name servers, creation/updated/expiry dates and contact/org info.
- Interpretation: domain owner/contact, registration dates, nameserver clues to hosting/provider.

## Identifying Website Technologies

- Methods: online tools (BuiltWith, Wappalyzer), browser extensions (Wappalyzer, WhatRuns), and CLI header inspection (`curl --head`).
- HTTP headers and cookies often reveal server software or frameworks (e.g., `server: nginx`, WordPress-specific cookies like `wp-settings`).
- HTML source can include generator/meta tags that identify CMS/frameworks.

## Wayback Machine (Internet Archive)

- Archive of historical web pages; useful for research, security analysis, and retrieving lost content.
- Link: https://web.archive.org/ — examine past versions of pages to find changes or historical data.

## Google Dorks

- Use advanced Google operators to find specific file types, pages, or content.
- Common operators: `site:`, `filetype:`, `inurl:`, `intext:`, `intitle:`. Combine operators for targeted searches.
- GHDB (Google Hacking Database) collects proven dorks for security research (https://www.exploit-db.com/google-hacking-database).

## Meta files

### robots.txt
- Located in site root; gives crawling rules (User-agent, Disallow, Allow) — not enforceable but useful for discovery.
- Can accidentally list sensitive paths (e.g., `Disallow: /adminpanel`) — fetch with `curl` or via browser.

### sitemap.xml
- Lists pages/files and site structure; can reveal deep/hidden endpoints. Often at `/sitemap.xml`.
- Fetch via `curl` to enumerate listed resources.

### security.txt
- Standard (RFC 9116) for publishing security contact/policy info; found at `/security.txt` or `/.well-known/security.txt`.
- Useful for responsible disclosure, contact methods, bug bounty links.

### humans.txt
- Optional file listing people/teams behind a site; can provide OSINT useful for social engineering and targeting.

## DNS enumeration

- DNS is essential for mapping domains → IPs and discovering infrastructure (A, AAAA, MX, NS, PTR, SOA, TXT, CNAME, SRV).
- Tools: `dig`, `host`, `nslookup`, and online services like DNSdumpster.
- Typical workflow: query A/AAAA for addresses, MX for mail servers, NS for authoritative servers, TXT for verification/SPF, PTR for reverse lookup.
- Examples in this module show `dig` outputs for A/AAAA/MX/NS/SOA/TXT and `host`/`nslookup` usage.

## Other discovery tools

- theHarvester: OSINT tool for emails, subdomains, hosts and people from multiple sources.
- Netcraft: site reports for hosting/SSL/provider info.
- viewdns.info, mxtoolbox: various DNS/blacklist/SSL checks.

## Subdomain enumeration

- Important for expanding scope and finding hidden services.
- Tools: `gobuster` (dns mode, vhost mode), `ffuf`.
- Gobuster dns example: `gobuster dns -d example.com -w /path/to/wordlist` — discovers subdomains.
- Gobuster vhost mode: fuzz Host header to find virtual hosts hosted on same IP; useful flags include `--exclude-length` to filter noise.

## File & directory scanning

- Find hidden files, admin panels, backups, and other sensitive endpoints.
- Tools: `gobuster dir` and `ffuf` (wordlist-driven discovery).
- Example: `gobuster dir -u http://example.com -w /path/to/wordlist.txt` and `gobuster dir -u <IP> -w common.txt --extensions php -v`.

## Practical notes

- Active techniques (scanning/fuzzing) are noisy — plan and obtain authorization before use.
- Combine passive OSINT (whois, Wayback, GHDB, meta files) with targeted active checks to build a complete picture.

## Summary

- Information gathering is foundational: use passive OSINT to map targets, then carefully apply active enumeration to validate and expand findings.
- The module covers whois, technology identification, Wayback, Google Dorks, meta files, DNS and subdomain enumeration, and directory fuzzing — all core skills for web reconnaissance.


