# 05 - Directory Scan

## Introduction
- Directory scanning is a core reconnaissance step in web application testing. It helps discover hidden/forgotten files, directories, and misconfigurations that may expose sensitive data or attack vectors.
- This section covers terminology (directory scanning, content discovery, fuzzing), wordlists, and common tools/techniques.

## Key Concepts

### Directory scanning
- Technique to map a website's file/directory structure by probing likely paths and observing responses.

### Content discovery
- Finding hidden pages, files and resources that are not linked from the visible site surface.

### Fuzzing
- Sending unexpected or random inputs (e.g., file names, form data) to observe application behavior and reveal vulnerabilities.
- Often implemented as brute-force checks with large input lists.

## Wordlists
- Wordlists are dictionaries of common filenames and paths used for fuzzing and discovery (similar to dictionary attacks).
- Use curated collections (e.g., SecLists) rather than building lists from scratch. Example path on HackerBox: `/root/Desktop/misc/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt`.

## Tools
- Common directory/content discovery tools: `gobuster`, `ffuf`, `dirb`, `feroxbuster`, plus manual checks (robots.txt, sitemap.xml).

### Gobuster
- Fast Go-based tool with multiple modes: `dir`, `dns`, `s3`, `gcs`, `vhost`, `fuzz`, `tftp`.
- Strengths: speed, concurrency. Limitation: no recursive scanning in some modes.
- Example usage: `gobuster dir -u http://example.com -w /path/to/wordlist.txt`.
- Useful flags include `-u` (URL), `-w` (wordlist), `-t` (threads), `--exclude-length`, `--extensions`, `-r` (follow redirects), `-k` (skip TLS validation), `-H` (headers), `--proxy`.

### FFUF (Fuzz Faster U Fool)
- Go-based, flexible fuzzing tool (directories, vhosts, parameters, POST data).
- Usage example: `ffuf -u http://example.com/FUZZ -w /path/to/wordlist`.
- Supports filtering/matching (status codes, size, regex), custom headers, recursion and many input modes.

### Dirb
- Classic directory scanner with built-in wordlists (approx ~4,000 words by default).
- Usage: `dirb <url_base> [<wordlist_file(s)>]`.

### Feroxbuster
- Rust-based high-performance content discovery tool with recursion, extraction and collection features.
- Basic usage: `feroxbuster -u <url> -w <wordlist>`.
- Supports many options: proxying, recursion depth, filters, thread control, auto-tune, collect-extensions/backups.

## Manual discovery checks

### robots.txt
- Located at site root, lists crawling rules (User-agent, Disallow, Allow). Not enforceable but useful to find potentially sensitive paths (e.g., `/admin`).

### sitemap.xml
- XML map of important site URLs and relationships; useful for finding deep or forgotten pages. Often at `/sitemap.xml`.

## Scanning examples & modes
- Directory scanning: `gobuster dir -u 172.20.8.56 -w /root/.../directory-list-1.0.txt`.
- File/extension scanning: `gobuster dir -u 172.20.8.56 -w common.txt --extensions php -v`.
- Feroxbuster examples: `feroxbuster -u 172.20.8.56 -w /.../directory-list-1.0.txt` and `feroxbuster -u 172.20.8.56 -w common.txt -x pdf`.
- FFUF example for fuzzing: `ffuf -u http://172.20.3.144/FUZZ -w /root/.../directory-list-1.0.txt` and extension probing `ffuf -u http://172.20.3.144/indexFUZZ -w web-extensions.txt`.

## Practical notes
- Start with manual checks (robots.txt, sitemap.xml) before noisy scans.
- Use curated wordlists (SecLists) and tune concurrency/rate limits to avoid throttling or lockouts.
- Prefer tools that support filtering and response analysis (size, status, regex) to reduce noise.

## Summary
- Directory and content discovery are essential first steps in web app assessment. Combine wordlists, efficient tools (gobuster/ffuf/feroxbuster/dirb) and manual OSINT to build a comprehensive map of potential attack surface.


