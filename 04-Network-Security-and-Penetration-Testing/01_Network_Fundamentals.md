# 01 - Network Fundamentals

## Introduction
- Networks connect devices (computers, servers, mobiles) so they can exchange data. The Internet is the largest example.

## Standards & Protocols
- Devices must follow common procedures called protocols (e.g., TCP/IP, Ethernet, WiFi, HTTP, DNS, DHCP).
- Standards organizations mentioned: IEEE (802 standards — Ethernet/Wi‑Fi), IETF (RFCs, TCP/IP work), ISO (e.g., ISO/IEC 27000 series), ITU (telecommunications & radio standards), ANSI (US standards coordination), W3C (web standards like HTML/CSS/XML).

## Types of Networks
- LAN (Local Area Network): limited area (home/office), high speed, resource sharing (printers, files), can use security controls.
- MAN (Metropolitan Area Network): city-scale, high bandwidth, used by ISPs or large campuses; sits between LAN and WAN.
- WAN (Wide Area Network): spans large geographic areas (cities, countries); uses fiber, satellite, telephone links; typically higher cost and lower speeds than LAN.
- Internet: global WAN connecting billions of devices.
- Intranet: private network for an organization, closed to the public.

## Common Networking Devices
- NIC (Network Interface Card): connects a device to a network; each NIC has a unique MAC address; wired and wireless variants.
- Hub: broadcasts incoming data to all ports (simple, causes congestion, insecure).
- Switch: forwards frames only to destination port using MAC addresses; reduces traffic; types: unmanaged, managed, smart.
- Router: connects different networks, routes packets by IP, enables multiple devices to share an internet connection and provides basic traffic control/security.
- Modem: modulator-demodulator — converts ISP analog signals to digital and vice versa; types include dial-up, DSL, cable, fiber, wireless (3G/4G/5G).
- Access Point (AP): enables wireless devices to connect to a wired network (receives Wi‑Fi and forwards over Ethernet).
- Firewall: inspects and filters traffic per rules; types: packet filtering, stateful inspection, application layer (proxy), next-generation (NGFW).

## Transmission Media and Cables
- Coaxial: older; used for cable modems and CCTV (RG categories: RG‑6, RG‑8, RG‑58, RG‑59).
- Twisted pair: common in LANs (UTP, STP). Uses RJ‑45 connectors for Ethernet; telephone uses RJ‑11.
- Fiber optic: transmits via light, high speed, low loss; types: multimode (shorter distances) and singlemode (long distances). Connectors: LC, SC, MTRJ.
- Straight vs crossover cables: straight-through connects unlike devices; crossover connects like devices (Auto‑MDIX often removes this need today).

## Network Topologies
- Star: devices connect to a central hub/switch — easy to add/remove devices; central device is single point of failure.
- Ring: devices form a closed loop; simple connections but single failure impacts network; used in some MANs/LANs.
- Bus: single shared medium (coax); low cost but fault‑finding is harder.
- Tree: hierarchical combination of stars; scalable but higher-level failures impact subnets.
- Mesh: multiple interconnections (full or partial) providing redundancy; used in critical networks/data centers.
- Peer‑to‑Peer: devices have equal status; no central server; simpler additions but management and security are harder at scale.
- Hybrid: mix of topologies to meet complex requirements.

## Communication Modes & Types
- Simplex: one‑way only (e.g., keyboard → computer).
- Half‑duplex: two‑way but not simultaneous (e.g., walkie‑talkie).
- Full‑duplex: simultaneous two‑way communication (e.g., telephone).
- Unicast: single sender → single receiver.
- Multicast: single sender → group of receivers (efficient for many recipients).
- Broadcast: single sender → all devices on the local network (e.g., DHCP requests).

## Network Models: OSI & TCP/IP
- Models organize network functions into layers so different vendors' equipment interoperates.
- OSI (7 layers): Physical, Data Link, Network, Transport, Session, Presentation, Application — useful pedagogically.
- TCP/IP (4 layers): Network Interface (link + physical), Internet, Transport, Application — the practical internet model.

### OSI layer highlights (from provided text)
1. Physical: bit transmission, cables, connectors, simplex/duplex modes, hardware examples (NICs, repeaters, hubs).
2. Data Link: framing, MAC addressing, error checking, flow control; ensures reliable local delivery.
3. Network: logical addressing (IP), routing, packetization, fragmentation/reassembly; routers operate here.
4. Transport: end‑to‑end communication, segmentation/reassembly, connection vs connectionless services (TCP vs UDP), error control, flow control.
5. Session: manages sessions (initiation/termination).
6. Presentation: data representation, compression, encryption, encoding/decoding.
7. Application: user‑facing protocols and services (HTTP, FTP, SMTP, DNS, etc.).

### TCP/IP mapping
- Application: combines OSI's session/presentation/application roles (HTTP, SMTP, DNS, SSH, FTP).
- Transport: TCP (reliable, ordered, connection‑oriented) and UDP (unreliable, low overhead; used for streaming).
- Internet: IP (routing, addressing); includes ICMP for control messages (ping uses Echo Request/Reply).
- Network Interface: physical + data link functions (Ethernet, MAC addressing).

## Important Protocols & Ports (high‑level list from text)
- DNS (port 53 UDP/TCP for zone transfers), DHCP (67/68 UDP), HTTP (80 TCP), HTTPS (443 TCP), FTP (20/21 TCP), SFTP/SSH (22 TCP), SMTP (25 TCP), POP3 (110 TCP), IMAP (143 TCP), NTP (123 UDP), SNMP (161 UDP), LDAP (389 TCP), LDAPS (636 TCP), SMB (445 TCP), RDP (3389 TCP), SIP (5060/5061 TCP), TFTP (69 UDP).

## DNS, SNMP, LDAP, SMB (notes from text)
- DNS resolves domain names to IP addresses (nslookup can query DNS).
- SNMP monitors/manages network devices (CPU, memory, bandwidth) — default TCP/UDP port 161.
- LDAP queries directory services (e.g., Active Directory) — default TCP port 389; LDAPS uses TCP 636.
- SMB provides file/printer sharing in Microsoft environments — TCP port 445.

## Remote Access & File Transfer Protocols
- Telnet: unsecured terminal access (plain text) — TCP 23; largely replaced by SSH.
- SSH: secure remote access using encryption (TCP 22).
- RDP: Microsoft remote desktop protocol — TCP 3389.
- FTP: plain file transfer (ports 20/21), insecure; SFTP uses SSH (TCP 22) for encrypted transfers.

## MAC & IP Addresses
- MAC: physical hardware address (48 bits), manufacturer portion in first 24 bits; FF:FF:FF:FF:FF:FF is broadcast.
- IP: logical network address. IPv4 uses 32 bits divided into four octets (e.g., 192.168.1.10). Two parts: network and host.

## Subnetting, CIDR & Addressing
- Subnet mask separates network vs host bits (e.g., /24 = 255.255.255.0).
- CIDR notation compresses masks (192.168.1.0/24).
- Number of usable hosts formula: 2^(host bits) - 2.
- IP classes (A/B/C) and private ranges (RFC1918): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16; APIPA 169.254.0.0/16.
- Loopback 127.0.0.1 used to test local services.

## FLSM & VLSM (subnetting strategies)
- FLSM: fixed‑size subnets (equal sizes) — simpler but less efficient.
- VLSM: variable sizes per subnet — allocate address space efficiently by fitting subnet size to need (order from largest to smallest when assigning addresses).

## IP Packet & TCP/UDP basics
- IP datagram contains header fields (Version, IHL, TOS, Total Length, Identification, Flags, Fragment Offset, TTL, Protocol, Header Checksum, Source/Destination, Options, Data).
- TCP segment header fields include ports, sequence/ack numbers, flags (SYN/ACK/FIN), window size, checksum — used for reliable, ordered connections.
- TCP three‑way handshake: SYN → SYN‑ACK → ACK.
- UDP: simpler header (Source Port, Destination Port, Length, Checksum) and connectionless behavior.

## ICMP & ARP
- ICMP: control protocol carried by IP; reports delivery issues (Echo Request/Reply used by ping). Ping output gives packet loss and RTT statistics.
- ARP: resolves IP → MAC on local networks; ARP request/reply exchanges populate local ARP cache (`arp -a`).

---
### Exercise
#### What is the network address of the third subnet when dividing the network 192.168.5.0/27 into four subnets?

To divide the network 192.168.5.0/27 into four subnets, we need to borrow bits from the host portion. The original subnet mask is /27, which means there are 32 - 27 = 5 bits for hosts. To create four subnets, we need 2 bits (2^2 = 4) for subnetting.
###### Why do we have to borrow bits?

We borrow bits from the host portion to create additional subnetworks. By extending the subnet mask, we can increase the number of available subnets at the cost of reducing the number of hosts per subnet.

The new subnet mask will be /29 (27 + 2). This gives us 8 IP addresses per subnet (2^(32-29)), with 6 usable addresses (subtracting network and broadcast addresses).

The subnets will be:
1. 192.168.5.0/29
2. 192.168.5.8/29
3. 192.168.5.16/29
4. 192.168.5.24/29

Therefore, the network address of the third subnet is 192.168.5.16/29.
