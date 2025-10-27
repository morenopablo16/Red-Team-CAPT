# 16 - Using sqlmap

## Introduction
- sqlmap is an open-source, Python-based automation tool to discover and exploit SQL injection vulnerabilities. It supports many DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, etc.) and automates detection, enumeration and exploitation tasks.

## Key Features
- Multi-DBMS support and automatic DBMS detection.
- Enumeration: databases, tables, columns, users, current DB, banner, password hashes.
- Injection techniques: boolean/text-based, time-based blind, error-based, UNION, stacked queries, out-of-band.
- Data extraction and dumping (`--dump`, `--dump-all`).
- OS access: `--os-shell`, `--os-cmd`, `--os-pwn` (post-exploitation features).
- Automation: scripts, sessions, proxy/Tor support, request files.

## Integrations
- Works with Metasploit, Burp Suite, OWASP ZAP, WebScarab, Maltego, Wireshark and other tooling. Can read proxy-captured requests and be driven from other pentest tools.

## Installation & Requirements
- sqlmap is Python-based (supports Python 3.x). Clone from GitHub:
	- `git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev`
- Update: `python sqlmap.py --update` (keeps payloads and modules current).
- Optional DB bindings / extras for direct DB connections: `pymysql`, `psycopg2`, `cx_Oracle`, `pymssql`, etc. NTLM auth support: `python-ntlm`.

## Legal / Safety Reminder
- Always have explicit authorization before testing systems. sqlmap's output contains a legal disclaimer: do not attack systems without permission.

## Basic usage & important options
- Run: `python sqlmap.py [options]`
- Common options:
	- `-u, --url` — target URL (e.g. `-u "http://site/vuln.php?id=1"`).
	- `--data` — POST data (e.g. `"username=foo&password=bar"`).
	- `-p` — parameter to test (e.g. `-p id`).
	- `--dbms` — force DBMS type.
	- `--level` / `--risk` — expand detection tests (level 1-5, risk 1-3).
	- `--technique` — choose techniques (E, B, U, S, T, Q; default BEUSTQ).
	- `--proxy` / `--tor` — proxy/Tor network support.
	- `--batch` — non-interactive (use defaults).
	- `--flush-session` — clear saved session for the target.

## Detection & enumeration examples
- Basic scan: `sqlmap -u "http://example/?id=1"` — sqlmap will test parameters and report injection points.
- POST data test: `sqlmap -u "http://site/login.php" --data="username=test&password=test" -p "username"`.
- Enumerate DBs/tables/columns: `--dbs`, `--tables -D <db>`, `--columns -D <db> -T <table>`.
- Dump data: `--dump -D <db>` or `--dump -T <table> -D <db>`.

## Example output & interpretation (from labs)
- sqlmap identifies injection points and technique types (boolean-based, time-based, UNION). It reports DBMS, web server tech and stores output under `~/.local/share/sqlmap/output/<target>`.

## Targeting, scanning tips
- Start with low `--level/--risk` and increase if needed.
- Use `--string` to detect boolean-based payloads that return a known string, or `--technique` to focus tests.
- If a WAF/protection is present, try tamper scripts (`--tamper`) or proxy through Burp to adjust payloads.

## Advanced features
- Scan from a saved HTTP request: `-r request.txt` (capture via Burp or curl and feed to sqlmap).
- Session management: `--session=<name>` to resume long scans.
- OS access: `--os-shell`, `--os-cmd`, `--os-pwn` (requires careful use and authorization).
- Tor/proxy: `--tor`, `--proxy="http://host:port"`.

## Common techniques & flags mapping
- Error-based (E): `--technique=E` — force error-based extraction.
- Boolean-based (B): `--technique=B` — blind boolean inference.
- UNION (U): `--technique=U` — test UNION-based extraction (must match column count).
- Stacked (S): `--technique=S` — execute stacked queries where supported.
- Time-based (T): `--technique=T` — time delays (SLEEP) to infer data.
- Out-of-band (Q): `--technique=Q` — OOB via DNS/HTTP callbacks.

## Examples from the lab (concise)
- Detect injection in `?search=`: boolean, time-based and `UNION` payloads discovered; sqlmap reported MySQL and Nginx and saved results.
- POST example: `--data="username=test&password=test" -p username` revealed time-based injection in POST parameter.
- Enumerated databases (`--dbs`), found `ecliptica_cars`, listed tables (`--tables -D ecliptica_cars`), columns (`--columns -D ecliptica_cars -T cars`) and dumped rows (`--dump -D ecliptica_cars`).

## Practical tips & ethics
- Use `--batch` for unattended runs in labs; for real targets keep interactive mode off unless authorized.
- Limit request rate for time-based tests (`--delay` / `--timeout`) to avoid DoS.
- Store and analyze sqlmap output files for forensics and reporting (`~/.local/share/sqlmap/output/<target>`).

## Quick reference (useful commands)
- Clone: `git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev`
- Basic scan: `python sqlmap.py -u "http://target/vuln?id=1" -p id --dbs`
- POST test: `python sqlmap.py -u "http://target/login.php" --data="user=foo&pass=bar" -p user --dump`
- Resume session: `python sqlmap.py -u "http://target/vuln?id=1" --session=session_name`

## References
- Project: https://github.com/sqlmapproject/sqlmap


