# 07 - Brute-Force in Web Applications

## Introduction
- Brute force attacks systematically try many combinations to discover credentials or hidden resources. They are simple but effective when defenses are weak.

## Common Types of Brute-Force Attacks

### 1) Dictionary Attack
- Definition: Uses lists of common passwords (dictionaries) to try known or likely passwords (e.g., "123456", "password").
- Mechanism: Sequentially try entries for a target username (example URL form):
	- https://example.com/login?username=admin&password=123456
- Defenses: strong password policies, MFA, account lockouts / attempt limits.

### 2) Exhaustive Search
- Definition: Tries all possible character combinations (brute-forcing the entire keyspace). Very time-consuming.
- Mechanism: Iterate through characters and lengths (e.g., a..z, 0..9, symbols).
- Defenses: long complex passwords, session limits, CAPTCHA.

### 3) Credential Stuffing
- Definition: Reuse username/password pairs leaked from other breaches against a target site.
- Mechanism: Automated replay of breach-sourced credentials (e.g., john@example.com : password123) across sites.
- Defenses: MFA, monitoring for reused credentials, login alerts, breached-credential checks.

## Effects of Brute Force Attacks
- Account takeover (full access to victim accounts).
- Service disruption (high-volume attempts can affect performance).
- Unauthorized access to internal data or privileged functionality.

## Common Vulnerabilities for Brute Force
- Weak password policies (short/simple passwords).
- Guessable or reused security questions used for resets.
- Missing rate limiting / no session attempt controls.

## Protection Methods
- Strong password policies (min length, complexity).
- Multi-Factor Authentication (SMS/app-based authenticators).
- Rate limiting and incremental lockouts.
- CAPTCHA for automated-bot protection.
- Temporary IP blocking after repeated failures.

## Directory Fuzzing (Directory Brute-Forcing)
- Goal: Discover hidden/unlisted directories and files by trying common paths from wordlists.
- Mechanism: Use tools to try entries from a wordlist and detect existing resources by HTTP status codes, sizes, or content differences.
- Tools & examples:
	- ffuf: `ffuf -u https://example.com/FUZZ -w /path/to/wordlist.txt`
	- gobuster: `gobuster dir -u https://example.com -w /path/to/wordlist.txt`

## Page Fuzzing (Page Brute-Forcing)
- Goal: Find hidden pages/endpoints (e.g., admin.php, login.jsp).
- Mechanism: Use wordlists and extension filters; detect hits by HTTP responses or content size.
- Tools & examples:
	- ffuf: `ffuf -u https://example.com/FUZZ -w /path/to/wordlist.txt`
	- gobuster (with extensions): `gobuster dir -u https://example.com -w /path/to/wordlist.txt -x php,html,asp`

## Sub-domain Fuzzing
- Goal: Discover subdomains used for services, admin panels or hidden apps.
- Mechanism: Try common subdomain names via DNS or Host header fuzzing and validate existence from responses.
- Tools & examples:
	- ffuf: `ffuf -u https://FUZZ.example.com -w /path/to/wordlist.txt -H "Host: FUZZ.example.com"`
	- Sublist3r: `sublist3r -d example.com -o subdomains.txt`

## Vhost Fuzzing
- Goal: Identify virtual-host configurations on a server (multiple hostnames on one IP).
- Mechanism: Vary the Host header to find hostnames that return different content.
- Tools & examples:
	- ffuf (Host header): `ffuf -u https://example.com -H "Host: FUZZ.example.com" -w /path/to/wordlist.txt`
	- gobuster vhost: `gobuster vhost -u https://example.com -w /path/to/wordlist.txt`

## GET Parameter Fuzzing
- Goal: Find vulnerabilities and unexpected behavior by fuzzing URL GET parameters.
- Mechanism: Replace parameter values with wordlist entries and evaluate responses (status, size, time).
- Tools & examples:
	- ffuf: `ffuf -u "https://example.com/page.php?param=FUZZ" -w /path/to/wordlist.txt`
	- Burp Intruder: capture request → send to Intruder → mark parameter(s) → choose payload list → analyze responses.

## POST Parameter Fuzzing
- Goal: Test POST parameters for security issues by sending many payloads and analyzing server responses.
- Tools & examples:
	- Burp Suite Intruder: capture POST request, mark parameters, add payloads, run attack and analyze results.
	- ffuf (POST): `ffuf -u "https://example.com/login.php" -X POST -d "username=admin&password=FUZZ" -w /usr/share/wordlists/rockyou.txt -H "Content-Type: application/x-www-form-urlencoded"`

## CAPTCHA Bypass Brute Force
- Goal: Bypass CAPTCHA protections when they are predictable, reused, or weak against ML/OCR.
- Mechanisms:
	1. Predictable codes or limited codespace.
	2. Reused or deterministic captchas.
	3. Machine-learning / OCR recognition for image-based captchas.
- Tools & methods:
	- Captcha solver services or ML/OCR tools (varies by captcha type).
	- Burp Intruder to brute-force captcha fields if feasible.
- Defenses:
	- Use strong, unpredictable captchas.
	- Combine CAPTCHA with other layers (MFA, IP reputation, behavioral analysis).

## Practical workflow / Recommendations
1. Always start with passive discovery (OSINT, previous scans) to minimize noise.
2. Use curated wordlists for directory/page/subdomain fuzzing (ffuf/gobuster/Sublist3r).
3. For parameters, prefer Burp Intruder for fine-grained control and analysis; use ffuf for fast bulk testing.
4. Respect rate limits and obtain authorization before active scanning.

## Summary
- Brute force techniques range from credential guessing (dictionary, exhaustive, credential stuffing) to resource discovery (directory/page/subdomain/vhost fuzzing) and parameter-based fuzzing. Tools like `ffuf`, `gobuster`, `sublist3r`, and Burp Suite Intruder are commonly used. Defenses include strong passwords, MFA, rate limiting, CAPTCHAs, and monitoring.


