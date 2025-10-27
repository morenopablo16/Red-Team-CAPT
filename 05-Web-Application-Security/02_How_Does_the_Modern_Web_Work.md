# 02 - How Does the Modern Web Work?

## Introduction

### World Wide Web (WWW)
- Invented by Tim Berners-Lee at CERN (1989) to make distributed information easy to access using hypertext.
- Key concepts: web pages, URLs (Uniform Resource Locators), hyperlinks.
- Berners-Lee also created the first web browser and server to navigate text-based information.

### Internet
- Originated as ARPANET (late 1960s), a resilient network funded by the U.S. DoD.
- Evolved from academic/research network to the global Internet used today (supports web, email, file transfer, messaging).
- The Internet = infrastructure; the Web = an application/service that runs on that infrastructure.

### Differences: Internet vs Web
- Internet: global network connecting devices (infrastructure).
- Web: a service built on the Internet composed of hypertext documents and multimedia accessed via browsers.

### Website
- Websites are collections of web pages built with HTML, CSS, and JavaScript.
- First website published by Tim Berners-Lee in 1991.
- Modern websites can be static or dynamic and enable information, commerce, social interaction, etc.

## Client-Server Model
- Core model for web interactions: clients (browsers/devices) request resources; servers host and respond.
- Communication usually via HTTP/HTTPS.
- Centralized servers enable cost advantages and on-demand resource usage.

### Client
- Any device running a web browser (PC, mobile, tablet).
- Browser sends HTTP/HTTPS requests (e.g., typing a URL or clicking a link).

### Server
- Hosts web pages, media, and applications (examples: Apache, Nginx, Microsoft IIS).
- Designed for always-on operation (24/7) and servicing client requests.

### Client-Server Communication (example flow)
1. User enters www.example.com in browser.
2. Browser sends HTTP GET to the server.
3. Server locates the resource and returns an HTTP response with HTML.
4. Browser renders the HTML into a visual page.
5. HTTPS adds encryption to protect data in transit.

## Generating Dynamic Content
- Dynamic pages are generated server-side using languages/frameworks (PHP, Python, Go, Node.js, etc.).
- Server-side code queries databases, processes data, and returns generated HTML or APIs (JSON/XML).

## Domain Name System (DNS)
- DNS translates human-readable domains to IP addresses (like a phone book for the Internet).
- Replaced early hosts.txt approach with a distributed, hierarchical system (RFC 882/883).

### DNS structure & components
- Domain: hierarchical labels (e.g., www.example.com = subdomain.www + second-level example + TLD com).
- TLD (Top-Level Domain): .com, .org, country-code TLDs (.uk, .de), and many new gTLDs (.tech, .guru).
- Key servers: root servers, TLD servers, authoritative name servers, and recursive resolvers.

### DNS query process (summary)
1. Browser asks local resolver (ISP) for the domain.
2. If not cached, resolver queries root server → TLD server → authoritative server.
3. Authoritative server returns the IP; resolver replies to the client.

### Common DNS record types
- A: maps domain to IPv4 address.
- AAAA: maps domain to IPv6 address.
- CNAME: alias to another domain.
- MX: mail exchange server.
- NS: name server for the domain.
- PTR: reverse DNS mapping (IP → name).
- SOA: start of authority for a DNS zone.
- TXT: arbitrary text (e.g., SPF records).
- SRV: service locator.

## HTTP and HTTPS

### HTTP
- Protocol for transferring web resources using a request-response model.
- History: HTTP/0.9 → HTTP/1.0 (1996) → HTTP/1.1 (1997) → HTTP/2 (2015) → HTTP/3 (QUIC).

### HTTPS
- HTTP over TLS/SSL to encrypt client-server communication.
- Ensures server authentication (certificates), session key establishment, and encrypted data transfer.

### HTTP requests (components)
- URL, Method (GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH/CONNECT/TRACE), Headers, and optional Body.
- Example header usages: Host, User-Agent, Accept, Authorization, Cookie, Content-Type, Cache-Control.

### HTTP responses
- Consist of a status line, headers, and an optional response body (e.g., HTML, JSON).
- Status codes grouped: 1xx (informational), 2xx (success), 3xx (redirection), 4xx (client errors), 5xx (server errors).

## Step-by-step web request workflow
1. Enter URL → browser starts DNS lookup.
2. DNS resolves domain to IP.
3. Browser sends HTTP request to the server IP.
4. Server processes the request and responds with content.
5. Browser renders the content and may fetch additional resources.
6. Connection ends (or persists with keep-alive).

## Frontend and Backend

### Frontend (client-side)
- Technologies: HTML, CSS, JavaScript.
- Role: layout, styling, interactivity; runs in the user’s browser.
- Framework examples: React, Angular, Vue.js.

### Backend (server-side)
- Technologies: Node.js, Go, Python (Django/Flask), Ruby on Rails, PHP (Laravel), etc.
- Responsibilities: business logic, database access, authentication, APIs.

## Backend languages & examples
- Go (Fiber, Echo) — lightweight, high-performance servers.
- Node.js — event-driven JS server-side runtime.
- Python (Django, Flask) — from full-featured to minimalist frameworks.
- Ruby on Rails, PHP (Laravel) — established web frameworks.

## Web development lifecycle
- Design & planning (UX/UI)
- Development (frontend + backend + APIs)
- Testing & deployment (CI/CD, staging, production)

## APIs
- REST: resource-based APIs over HTTP (JSON/XML payloads).
- SOAP: XML-based, enterprise-focused web services.
- GraphQL: flexible queries returning exactly requested fields.
- WebSocket: persistent, bidirectional connections for real-time apps.

## Web servers & deployment
- Common servers: Apache, Nginx, IIS, Tomcat (Java servlets).
- Web servers handle static and dynamic content, reverse proxying, and load balancing.

## Security & performance
- Key concerns: DDoS, SQL injection, XSS; mitigations include WAFs, TLS, secure coding.
- Performance techniques: caching, CDNs, load balancers, connection pooling.

## Infrastructure & supporting services
- CDN: caches content closer to users for faster delivery.
- Log servers (ELK, Splunk): collect and analyze logs for security and monitoring.
- Mail servers (SMTP/IMAP/POP3): manage email delivery.
- Session services: session stores (Redis) or JWT for stateless authentication.
- Backup & disaster recovery: regular backups and restoration plans.

## Cloud architecture & modern tooling
- Cloud models: IaaS, PaaS, SaaS; deployment models: public, private, hybrid.
- Containerization (Docker), orchestration (Kubernetes), microservices, and DevOps/CI-CD enable scalable, reliable deployments.

## Summary
- The modern web is built on decades of layered technologies: DNS, HTTP(S), client-server interactions, frontend/backend development, APIs, and cloud infrastructure.
- Security, performance, and scalability are recurring design priorities.


