# CodeAlpha_NetworkSniffer

**CodeAlpha Internship — Task 1: Basic Network Sniffer**

A Python network packet sniffer built from scratch using raw sockets to capture and analyze live network traffic.

## What It Does

This tool captures network packets in real-time and displays detailed information about each one:

- Source and destination MAC addresses (Ethernet layer)
- Source and destination IP addresses (IP layer)
- Protocol detection (TCP, UDP, ICMP)
- Port numbers and payload content
- Export captures to CSV and JSON
- Web dashboard for live monitoring

## Project Roadmap

- [x] Ethernet frame parsing (MAC addresses, protocol)
- [x] IP packet parsing (source/destination IP, TTL)
- [x] TCP/UDP/ICMP protocol parsing (ports, payload)
- [ ] Protocol filtering (capture only TCP, UDP, or ICMP)
- [ ] Export to CSV and JSON
- [ ] Web dashboard with Flask

## Tech Stack

- **Python 3** — core language
- **socket** — raw packet capture
- **struct** — binary data unpacking

## Requirements

- Python 3.8+
- Linux (raw sockets require `AF_PACKET`)
- Root privileges (`sudo`)

## Usage

```bash
sudo python3 sniffer.py
```

## What I Learned

- How network packets are structured in layers (Ethernet → IP → TCP/UDP/ICMP → Payload)
- How to use Python's `struct` module to unpack binary data
- How raw sockets work at the OS level

## Author

Built as part of the [CodeAlpha](https://www.codealpha.tech) Cybersecurity Internship.
