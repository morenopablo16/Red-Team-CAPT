# 04 - Use Burp Suite

## Introduction & Editions
- Burp Suite (PortSwigger) — Java-based web security toolkit first released 2003.
- Editions: Community (free, basic tools), Professional (advanced scanning, reporting, faster Intruder), Enterprise (scheduling, multi-user, centralized management).

## Key Purpose
- Intercept, inspect, manipulate HTTP/HTTPS traffic between browser and server.
- Supports vulnerability discovery, exploitation, and reporting workflows.

## Major Tools (overview)
- Target: manage targets, Site Map and Scope.
- Proxy: intercept/modify traffic, HTTP history, WebSockets, proxy listeners, certificates.
- Intruder: automated payload-driven attacks (fuzzing, brute force) — positions, payloads, attack types, resource pool.
- Repeater: manual request editing and resending.
- Sequencer: analyze randomness of tokens (session IDs, CSRF tokens).
- Decoder: decode/encode transformations (Base64, URL, Hex, etc.) and some hash support.
- Comparer: visual diffs between two data blobs (bytes/words).
- Logger: broader traffic logging than HTTP History.
- Organizer: notes, findings, classification and statuses.
- Extensions / BApp Store: add plugins (Turbo Intruder, SQLMap bridge, Autorize, Active Scan++ etc.).

## Installation & Getting Started
- Download appropriate package from PortSwigger Releases. Kali Linux often ships with Community edition preinstalled.
- Supported platforms: JAR, Linux (ARM/x64), macOS (Intel/Apple Silicon), Windows (ARM/x64).

### Project types on startup
- Temporary Project: RAM-only, no disk traces.
- New Project: persistent project with settings and metadata.
- Open Existing Project: load previous work.

### Configuration
- Use Burp Defaults or load a saved configuration file. Configure proxy listeners, scanner, extensions, and other options from the Settings area.

## Dashboard & Task Management
- Dashboard shows scans, task list, security alerts and quick status.
- Add/manage tasks (New live task), view task status, and access scan results and remediation advice.

## Target: Site Map & Scope
- Site Map: tree view of discovered URLs; filter by resource type or method and inspect requests/responses.
- Scope: include/exclude targets; use advanced filters to focus tests and avoid out-of-scope noise.

## Proxy (core workflow)
- Intercept: toggle Intercept On/Off to pause traffic and inspect requests/responses.
- Forward, Drop, or Act (automatic forwarding rules).
- HTTP History: chronological record of proxied requests/responses.
- WebSockets History: monitor full‑duplex WS traffic.

### Proxy Options & Listeners
- Configure listeners (default 127.0.0.1:8080), add multiple endpoints, and define interception rules (request/response filters).
- Request/Response interception rules let you exclude filetypes or code paths to reduce noise.

### Certificates & Browsers
- Export Burp CA (DER) via Proxy > Options or visit http://burp to download.
- Install CA in browser's trust store (Trusted Root Certification Authorities) to inspect HTTPS traffic.
- Optionally use Burp's embedded Chromium browser to avoid manual certificate setup.

## Intruder (automation)
- Send requests to Intruder to run automated attacks.
- Positions: mark parameters/values to mutate; clear or adjust automatic selections.
- Attack types: Sniper, Battering Ram, Pitchfork, Cluster Bomb — choose based on test strategy.
- Payloads: upload lists (e.g., SecLists), configure processing/encoding and payload settings.
- Resource pool & Settings: control concurrency and timeouts to avoid overload.
- Start Attack: review responses (status, length, differences) to identify successful payloads.

## Repeater (manual testing)
- Send captured requests to Repeater to edit method, URL, headers, body and resend.
- Useful for fine-grained testing and verifying vulnerability responses.

## Sequencer (token analysis)
- Capture many token samples (thousands recommended) and analyze randomness/uniformity.
- Reports statistical tests and helps assess session token strength.

## Decoder & Comparer
- Decoder: smart-detect decoding, manual transforms (URL, Base64, Hex), decompress (gzip) and encode back.
- Comparer: compare bytes or words to highlight differences between two pieces of data (responses, tokens, files).

## Logger & HTTP History
- Logger records broad traffic and events; HTTP History focuses on proxied HTTP(S) requests/responses.
- Right-click items to send to other tools (Repeater, Intruder, Decoder, etc.).

## Organizer & Issue Management
- Store notes, findings and metadata; add statuses (New, In Progress, Done) and highlight rows for triage.

## Extensions & Automation
- Install from BApp Store or manually add .jar/.py extensions.
- Popular extensions: Turbo Intruder, SQLMap integration, Autorize, Active Scan++, 403 Bypasser.
- Extensions appear as new UI tabs or menu items and can be updated/removed via the Extensions tab.

## APIs
- Burp exposes APIs for automating tasks and writing custom extensions.

## Practical notes & safety
- Use proxies and interception responsibly; obtain authorization before active testing.
- Configure proxy and certificate correctly to avoid breaking browser TLS checks.

## Summary
- Burp Suite is a comprehensive, extensible toolkit for web application security testing — from lightweight community workflows to enterprise automation and management.


