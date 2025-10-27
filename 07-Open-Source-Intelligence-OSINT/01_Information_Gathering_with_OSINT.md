# 01 - Information Gathering with OSINT

## Introduction

What is OSINT (Open Source Intelligence)?

OSINT stands for Open Source Intelligence. It is the process of gathering, analyzing, and utilizing information from publicly available sources. Unlike traditional intelligence gathering methods, OSINT relies on data obtained from public sources: websites, social media platforms, news sources, public databases, and other online resources.

## Importance and Applications of OSINT

OSINT is used for security assessments, threat intelligence, brand protection, research, and investigative journalism. It helps discover exposed assets, leaked data, and contextual information about targets.

## Gathering Information with Google Dork

Google Dorking is a method of performing advanced searches on Google using specific keywords, operators, and special characters. With this method, you can access information that is usually hard to find or hidden.

### Google Hacking Database (GHDB)

The Google Hacking Database (GHDB) is a resource containing curated Google dorks to find open directories, misconfigurations, hidden files, and other issues. See the GHDB on Exploit-DB for a large collection of dorks.

### Most Commonly Used Google Dorks

| # | Dork | Description | Usage Example |
|---|------|-------------|---------------|
| 1 | site: | Searches within a specific site. | site:example.com |
| 2 | filetype: | Searches for a specific file type. | filetype:pdf |
| 3 | intitle: | Searches for pages with specific words in the title. | intitle:"login" |
| 4 | inurl: | Searches for pages with specific words in the URL. | inurl:admin |
| 5 | cache: | Displays pages stored in Google's cache. | cache:example.com |
| 6 | link: | Finds pages that link to a specific page. | link:example.com |
| 7 | related: | Finds sites similar to a specific site. | related:example.com |
| 8 | intext: | Searches for specific words within the page text. | intext:"password" |
| 9 | allintitle: | Searches for pages with all specified words in the title. | allintitle:login admin |
| 10 | allinurl: | Searches for pages with all specified words in the URL. | allinurl:admin login |
| 11 | allintext: | Searches for all specified words in the text. | allintext:username password |
| 12 | define: | Searches for the definition of a specific word. | define:OSINT |
| 13 | "keyword" | Exact phrase search. | "admin login" |
| 14 | -keyword | Excludes pages containing a specific word. | password -example |
| 15 | OR | Either-or search. | login OR signup |
| 16 | * | Wildcard for any word. | intitle:"admin *" |
| 17 | .. | Number range search. | filetype:pdf 2020..2022 |
| 18 | info: | Displays information about a site. | info:example.com |
| 19 | maps: | Shows map of a location. | maps:New York |
| 20 | stocks: | Shows stock information. | stocks:GOOG |

### Google Dork Usage Examples

- Searching within a specific site: site:example.com "contact information"
- Finding PDF documents: filetype:pdf "confidential"
- Finding open directories: intitle:"index of /"
- Finding admin panels: inurl:admin
- Using Google cache: cache:example.com
- Finding pages linking to a page: link:example.com
- Searching for specific words in page text: intext:"password"
- Finding phpMyAdmin: intext:"phpMyAdmin" "running on" inurl:"main.php"

## Information Gathering from Social Media and Images

Social media and images are critical OSINT sources. Username correlation, profile mining, and image analysis provide high-value leads.

### Gathering Information Using a Username

Tools like instantusername.com can check whether a username exists across multiple platforms. Sherlock is a popular open-source tool to search for usernames across many sites.

Sherlock: https://github.com/sherlock-project/sherlock

### Finding Contact Information

RocketReach (rocketreach.co) and Hunter.io are useful for finding professional contact details and emails.

### Image Analysis

Reverse Image Search: Google Images and TinEye can find other instances of an image and its original source.

Face/Similarity Search: Services like PimEyes can find other images of a person across the web.

Metadata Analysis: ExifTool extracts metadata (EXIF) from images and video files, revealing device, timestamps, and possibly GPS coordinates.

Install ExifTool:

```
sudo apt-get install exiftool
```

Example usage:

```
exiftool IMG_8153.JPG
```

## Information Gathering from Web Applications and DNS

Web applications and DNS enumeration reveal subdomains, record types, MX records, and web technologies.

### Whois

Whois queries reveal domain registration details: owner, registrar, dates, and name servers.

Example:

```
whois google.com
```

### Internet Archive (Wayback Machine)

The Wayback Machine stores historical snapshots of sites and is useful to find past content and possibly exposed files: https://web.archive.org/

### Technologies Used in Websites

Browser extensions like Wappalyzer and WhatRuns and command-line tools like `curl --head` help identify server software and frameworks.

Example:

```
curl --head https://wordpress.org
```

### robots.txt

Check `robots.txt` for disallowed paths that may reveal hidden directories or endpoints:

```
curl --get https://example.com/robots.txt
```

## DNS Enumeration

DNS techniques help expand the target scope by discovering subdomains and records.

Tools and commands:

- DNSdumpster: https://dnsdumpster.com/
- host: `host domain.com`
- dig: `dig domain.com`

Example:

```
host youtube.com
dig youtube.com
```

## Internet Search Engines and Specialized Scanners

Search engines and scanners designed for internet-wide discovery are invaluable.

### Shodan

Shodan indexes internet-connected devices; use filters like `port:`, `product:`, `org:`, `country:` and `vuln:` to find devices and vulnerable services.

### Censys

Censys provides rich details on hosts, certificates, and service metadata for research and vulnerability scouting.

## Leaked Data, Dark Web, and Deep Web Tools

### Leaked Data Tools

- Have I Been Pwned: https://haveibeenpwned.com
- Hunter.io: https://hunter.io
- Email verifiers: e.g., email-checker.net

### Dark Web Tools

- Tor Browser: https://torproject.org
- Ahmia: https://ahmia.fi (search .onion sites)

### Deep Web Tools

- DuckDuckGo (privacy search)
- Not Evil (Tor search)

## OSINT Framework

The OSINT Framework is a categorized index of OSINT tools and resources organized by information type (domains, people, social media, leaks, etc.). Useful for quickly finding the right tool for a task: https://osintframework.com/

## Usage Scenarios and Applications

- Security vulnerability detection
- Threat intelligence and monitoring
- Brand and reputation research
- Journalistic investigations

## OSINT Tools and Techniques

Popular tools include Shodan, Maltego, Recon-ng, Sherlock, ExifTool, Wappalyzer, and many specialized web services. Techniques include web scraping, data mining, social media analysis, and automated reporting.

## Ethical and Legal Considerations

Always comply with laws and respect privacy. Unauthorized data collection or use can be illegal and unethical. Ensure consent and legal authority before conducting OSINT operations.

## OSINT Cycle

The OSINT cycle is a five-phase process: Direction, Collection, Analysis, Evaluation, and Dissemination.

- Direction: Define goals and scope.
- Collection: Gather data from selected open sources.
- Analysis: Correlate, clean, and analyze findings.
- Evaluation: Assess reliability, relevance, and impact.
- Dissemination: Share actionable intelligence in appropriate formats.

## Key Concepts

- Open Source: Publicly accessible information.
- Verification: Corroborate findings across multiple sources.
- Data Mining: Extracting value from large datasets.
- HUMINT: Human-sourced intelligence complementing OSINT.
- Metadata Analysis: Extracting hidden details from files and media.

---

Practice using these techniques ethically on lab targets and always document sources and methods in your reports.


