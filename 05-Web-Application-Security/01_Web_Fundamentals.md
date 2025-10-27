
# Web Fundamentals

## World Wide Web (WWW)

- The WWW is a global information system of hypertext documents linked by hyperlinks.
- Hypertext links let users jump quickly between related documents (e.g., click a link for more information).
- Invented in 1989 by Tim Berners-Lee at CERN to enable automatic information sharing among scientists worldwide.
- Key technologies combined to create the Web: HTML, URL, and HTTP.

## Internet vs Web

- Internet: the global network connecting millions of computers; it is the infrastructure that supports many services (email, file transfer, gaming, etc.).
- Web: an information-sharing system running on the Internet that uses HTML, URLs and HTTP to present hypertext documents (web pages, images, videos).
- People often confuse the two, but technically the Web is one application that runs on the Internet.

## Client–Server Model

- Client requests information or services; the server hosts websites and responds to requests.
- Servers centralize data and are designed to operate 24/7; any internet-connected computer can host a page.
- Clients are devices (PCs, smartphones, tablets) that use browsers (Chrome, Firefox, Safari) to request and display web pages.
- Typical flow: client sends request → server processes → server returns a copy of the page → browser displays it.

## Domain Name System (DNS)

- DNS is the internet's "phone book"; it maps human-readable domain names (e.g., www.example.com) to IP addresses (e.g., 192.0.2.1).
- Early ARPANET used a centralized hosts.txt; DNS (RFC 882/883) introduced a distributed, hierarchical system (1983).

### Domain name structure (example `www.example.com`)
- `www` — subdomain
- `example` — second-level domain
- `com` — top-level domain (TLD)

### Top-Level Domains (TLDs)
- TLDs are the last label and often indicate type or region: `.com`, `.org`, `.gov`, `.edu`, or country codes like `.uk`, `.de`.
- Modern expansion includes many generic TLDs (e.g., `.photography`, `.tech`).

### Types of DNS servers
1. Authoritative Name Server — the official source of DNS records for a domain (A, MX, CNAME, etc.).
2. Recursive Resolver — performs lookups on behalf of clients and caches results to speed future queries.
3. Root Name Servers — top of the DNS hierarchy; direct resolvers to the appropriate TLD servers.

### DNS resolution (summary of steps)
1. User enters `www.example.com` → browser queries the ISP's recursive resolver.
2. Recursive resolver checks cache; if absent, continues.
3. Resolver queries a Root Name Server → gets TLD server info.
4. Resolver queries the TLD DNS Server → gets the domain’s authoritative server address.
5. Resolver queries the Authoritative Name Server → retrieves DNS record (e.g., A record).
6. Recursive resolver returns the IP to the client.
7. Client uses the IP to send an HTTP request to the website's server.

## Hypertext Transfer Protocol (HTTP)

- HTTP enables transfer of web resources (pages, images, etc.) between client and server using a request–response model.
- Invented by Tim Berners-Lee in the early 1990s.

### HTTP request components
- URL, Method, Headers, Request Body (optional).

Example request header (structure):

```
GET /index.html HTTP/1.1
Host: www.example.com
Cookie: SESSIONID=badb655ebd99ed6c8e58c0a1aab44eb9
```

- First line: method, path, HTTP version (e.g., `GET /index.html HTTP/1.1`).
- `Host` header: target server's domain or IP.
- `Cookie` header: example of client-side session data.

### Common HTTP methods
- GET — retrieve a resource.
- POST — send data to server (e.g., form submissions).
- PUT — create or update a specific resource.
- DELETE — remove a resource.
- HEAD — like GET but returns headers only.
- OPTIONS — query supported methods.
- PATCH — partially update a resource.
- CONNECT — establish a tunnel.
- TRACE — loop-back test along the request path.

### HTTP request headers (examples and purpose)
- Host: hostname of the target server.
- User-Agent: client information (browser details).
- Accept: MIME types the client accepts.
- Accept-Language: preferred languages.
- Authorization: authentication tokens.
- Cache-Control / Pragma: caching directives.
- Connection: connection management (e.g., keep-alive).
- Referer: referring page URL.
- Content-Type: MIME type of request body when present.

### HTTP request body
- Included for POST/PUT/PATCH to send form data, files, or structured data (JSON, XML).
- `Content-Type` header tells the server how to parse the body (e.g., `application/json`, `multipart/form-data`).
- Example: file upload using `multipart/form-data` with `POST /v1/photos/upload`.

### HTTP responses
- Server replies with a status line, headers, and optional body (resource content).
- Example: `HTTP/1.1 200 OK` with `Content-Type: application/json` and a JSON body.

Common status codes (examples from source):
- 100 Continue, 101 Switching Protocols
- 200 OK, 201 Created, 202 Accepted, 203 Non-Authoritative Information
- 301 Moved Permanently
- 404 Not Found
- 500 Internal Server Error

## Site-access step-by-step (summary)
1. Open browser and enter URL (e.g., `https://google.com`).
2. Browser performs DNS query to resolve domain → IP.
3. Browser sends HTTP request to the server IP.
4. Server processes and responds with page content (HTML).
5. Browser renders page and requests additional resources (images, CSS, JS).
6. Connection closes after transfer unless `keep-alive` is used.

---


