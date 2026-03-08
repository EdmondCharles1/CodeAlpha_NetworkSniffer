# CodeAlpha_NetworkSniffer

**CodeAlpha Internship — Task 1: Basic Network Sniffer**

A Python network packet sniffer built from scratch using raw sockets to capture and analyze live network traffic, with a real-time web dashboard powered by Flask.

## Demo

```
$ sudo python3 sniffer.py
Capturing all packets... (Ctrl+C to stop)

Ethernet Frame:
  Destination: 00:15:5D:1D:1F:45, Source: 00:15:5D:12:FD:D7, Protocol: 8
  IPv4 Packet:
    Version: 4, Header Length: 20, TTL: 128
    Protocol: 17, Source: 172.19.64.1, Target: 172.19.79.255
    UDP Segment:
      Source Port: 138, Destination Port: 138, Length: 4417
```

## Features

### CLI Sniffer (`sniffer.py`)

- Live packet capture using raw sockets (`socket.AF_PACKET`)
- Ethernet frame parsing (MAC addresses)
- IPv4 packet parsing (source/destination IP, TTL)
- TCP segment parsing (ports, sequence, flags: SYN, ACK, FIN, etc.)
- UDP segment parsing (ports, length)
- ICMP packet parsing (type, code, checksum)
- Payload display (decoded UTF-8 or hex)
- Protocol filtering via command line (`tcp`, `udp`, `icmp`)
- Export captured packets to CSV and JSON on `Ctrl+C`

### Web Dashboard (`dashboard.py`)

- Real-time stats (total, TCP, UDP, ICMP, other)
- Protocol distribution bar chart
- Top source IPs ranking
- Live packet table with protocol tags
- Protocol filtering (ALL / TCP / UDP / ICMP)
- Export to JSON and CSV from the browser

## Project Structure

```
CodeAlpha_NetworkSniffer/
├── sniffer.py              # CLI packet sniffer
├── dashboard.py            # Flask web dashboard + sniffer backend
├── requirements.txt        # Python dependencies
├── README.md
├── .gitignore
├── templates/
│   └── index.html          # Dashboard HTML
└── static/
    ├── css/
    │   └── style.css       # Dashboard styles
    └── js/
        └── app.js          # Dashboard logic (API polling, charts, filters)
```

## Requirements

- Python 3.8+
- Linux (raw sockets require `AF_PACKET`)
- Root privileges (`sudo`)
- Flask (`pip install flask`)

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer
pip install -r requirements.txt
```

## Usage

### CLI Sniffer

```bash
# Capture all protocols
sudo python3 sniffer.py

# Capture only TCP packets
sudo python3 sniffer.py tcp

# Capture only UDP packets
sudo python3 sniffer.py udp

# Capture only ICMP packets (open another terminal and run: ping google.com)
sudo python3 sniffer.py icmp
```

Press `Ctrl+C` to stop. Captured packets are automatically exported to `capture.json` and `capture.csv`.

### Web Dashboard

```bash
sudo python3 dashboard.py
```

Open **http://127.0.0.1:5000** in your browser.

## How It Works

### Packet Capture Flow

```
Network Interface
      │
      ▼
Raw Socket (AF_PACKET, SOCK_RAW)
      │
      ▼
┌─────────────────┐
│ Ethernet Frame  | ─── MAC src/dst, Protocol
│  ┌─────────────┐│
│  │ IPv4 Packet  | ─── IP src/dst, TTL, Protocol number
│  │ ┌─────────┐ ││
│  │ │TCP/UDP/ │ ││ ─── Ports, Flags (TCP), Type (ICMP)
│  │ │ICMP     │ ││
│  │ │┌───────┐│ ││
│  │ ││Payload││ ││ ─── Application data
│  │ │└───────┘│ ││
│  │ └─────────┘ ││
│  └─────────────┘│
└─────────────────┘
```

### Dashboard Architecture

```
┌──────────────┐         ┌──────────────┐
│ Sniffer      │         │ Flask Server │
│ (Thread)     │────── ▶│ (API Routes) │
│              │ packets │              │
└──────────────┘         └──────┬───────┘
                                │ JSON
                                ▼
                        ┌──────────────┐
                        │ Browser      │
                        │ (JavaScript) │
                        │ polls /api/* │
                        │ every 1s     │
                        └──────────────┘
```

## Protocol Numbers

| Number | Protocol | Description                              |
| ------ | -------- | ---------------------------------------- |
| 1      | ICMP     | Control messages (ping, errors)          |
| 6      | TCP      | Reliable connection (HTTP, HTTPS, SSH)   |
| 17     | UDP      | Fast, no guarantee (DNS, NTP, streaming) |

## Tech Stack

- **Python 3** — core language
- **socket** — raw packet capture (AF_PACKET)
- **struct** — binary data unpacking
- **Flask** — web server and REST API
- **HTML/CSS/JS** — dashboard frontend

## What I Learned

- How network packets are structured in layers (Ethernet → IP → TCP/UDP/ICMP → Payload)
- How to use Python's `struct` module to unpack binary data
- How raw sockets work at the OS level
- How to extract fields from a single byte using bit shifting (`>> 4`) and masking (`& 15`)
- How TCP flags (SYN, ACK, FIN) control connections
- The difference between TCP (reliable) and UDP (fast)
- How to build a REST API with Flask
- How to run background tasks with Python threads
- How JavaScript `fetch()` polls an API to update a dashboard in real-time

## Security Notice

This tool is designed for **educational purposes** and authorized network analysis only. Capturing network traffic on networks you do not own or have explicit permission to monitor may be illegal. Always ensure you have proper authorization.

## Author

Built by **Claud Edmond Charles** as part of the [CodeAlpha](https://www.codealpha.tech) Cybersecurity Internship.

## License

MIT
