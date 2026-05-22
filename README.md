# Deep Packet Inspection System (DPI Engine)

[![License](https://img.shields.io/github/license/Rekh-225/Deep-Packet-Inspection-System)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)

A production-quality, self-contained deep packet inspection (DPI) engine for **offline PCAP analysis**. It parses Ethernet/IPv4/TCP/UDP headers, extracts TLS SNI / HTTP Host / DNS queries, classifies traffic by application, and applies configurable blocking rules before writing a filtered PCAP.

> **Scope**: This project processes *PCAP files* (not live traffic) and does **not** decrypt TLS. It focuses on fast, deterministic classification using protocol metadata.

## Table of Contents
- [Key Features](#key-features)
- [Architecture](#architecture)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [Example Output](#example-output)
- [Supported Applications](#supported-applications)
- [Rules File Format](#rules-file-format)
- [Testing](#testing)
- [Performance & Scalability](#performance--scalability)
- [Security & Privacy Considerations](#security--privacy-considerations)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

## Key Features
- **Protocol Parsing** — Ethernet, IPv4, TCP, and UDP header parsing
- **Metadata Extraction** — TLS SNI, HTTP `Host`, and DNS query parsing
- **Application Classification** — heuristic mapping of SNI/hostnames to 20+ common apps
- **Rule-Based Blocking** — block by IP, app, domain (substring/wildcard), or port
- **Two Execution Modes** — single-threaded engine and multi-threaded LB/FP pipeline
- **PCAP Output** — writes a filtered PCAP with blocked packets removed
- **Standard Library Only** — no external runtime dependencies

## Architecture

### High-Level Pipeline
```mermaid
flowchart LR
  A[PCAP Reader] --> B[Packet Parser]
  B --> C[DPI Inspection]
  C --> D[Classification]
  D --> E[Rule Manager]
  E -->|Forward| F[PCAP Writer]
  E -->|Drop| G[Discard]

  C --> C1[TLS SNI]
  C --> C2[HTTP Host]
  C --> C3[DNS Query]
```

### Multi-Threaded Pipeline
```mermaid
flowchart LR
  R[Reader Thread]
  R --> LB0[Load Balancer 0]
  R --> LB1[Load Balancer 1]
  LB0 --> FP0[Fast Path 0]
  LB0 --> FP1[Fast Path 1]
  LB1 --> FP2[Fast Path 2]
  LB1 --> FP3[Fast Path 3]
  FP0 --> O[Output Queue]
  FP1 --> O
  FP2 --> O
  FP3 --> O
  O --> W[Writer Thread]
```

### Key Design Notes
- **Five-tuple flow tracking**: all packets in a flow are processed together.
- **Consistent hashing**: ensures flow affinity for multi-threaded processing.
- **Deterministic decisions**: blocking rules are evaluated in a fixed order for consistency.

## How It Works
1. **Parse headers** to extract Ethernet/IPv4/TCP/UDP metadata.
2. **Inspect payload** for TLS ClientHello (SNI), HTTP Host, and DNS queries.
3. **Classify traffic** using SNI/host/port heuristics (fallback to port if needed).
4. **Apply rules** (IP → Port → App → Domain) to decide forward/drop.
5. **Write output** PCAP containing only forwarded packets.

## Project Structure
```
├── dpi/                        Core engine package
│   ├── __init__.py             Package exports
│   ├── types.py                Enums, data classes, SNI→App mapping
│   ├── pcap_io.py              PCAP file reader and writer
│   ├── packet_parser.py        Ethernet/IPv4/TCP/UDP protocol parsing
│   ├── sni_extractor.py        TLS SNI, HTTP Host, DNS extractors
│   ├── rule_manager.py         Blocking rules (IP, App, Domain, Port)
│   ├── connection_tracker.py   Flow table and connection state
│   ├── engine.py               Single-threaded DPI engine
│   └── engine_mt.py            Multi-threaded DPI engine
│
├── cli.py                      Command-line interface
├── generate_test_pcap.py       Test PCAP generator
├── test_dpi.pcap               Sample capture for testing
├── tests/                      Unit + integration tests
├── requirements.txt            Dependencies (stdlib only)
└── README.md
```

## Requirements
- **Python 3.8+**
- No external dependencies (standard library only)

## Installation
```bash
git clone https://github.com/Rekh-225/Deep-Packet-Inspection-System.git
cd Deep-Packet-Inspection-System
```

## Quick Start
```bash
python cli.py test_dpi.pcap output.pcap
```

### Block Specific Traffic
```bash
# Block an application
python cli.py capture.pcap filtered.pcap --block-app YouTube

# Block an IP address
python cli.py capture.pcap filtered.pcap --block-ip 192.168.1.50

# Block a domain (substring match)
python cli.py capture.pcap filtered.pcap --block-domain tiktok

# Combine multiple rules
python cli.py capture.pcap filtered.pcap \
  --block-app YouTube \
  --block-app TikTok \
  --block-ip 192.168.1.50 \
  --block-domain malware.example.com
```

### Multi-Threaded Mode
```bash
# Default: 2 load balancers, 2 fast-path threads per LB (4 total)
python cli.py capture.pcap filtered.pcap --mode mt

# Custom thread count
python cli.py capture.pcap filtered.pcap --mode mt --lbs 4 --fps 4
```

## CLI Usage
```text
usage: cli.py [-h] [--block-ip IP] [--block-app APP] [--block-domain DOMAIN]
              [--block-port PORT] [--rules-file FILE]
              [--mode {simple,mt}] [--lbs N] [--fps N]
              input output

positional arguments:
  input                 Input PCAP file path
  output                Output PCAP file path (filtered)

blocking rules:
  --block-ip IP         Block traffic from source IP (can be repeated)
  --block-app APP       Block application: YouTube, Facebook, TikTok, etc.
  --block-domain DOMAIN Block domain by substring match (can be repeated)
  --block-port PORT     Block destination port (can be repeated)
  --rules-file FILE     Load blocking rules from a file

engine mode:
  --mode {simple,mt}    simple (single-threaded) or mt (multi-threaded)
  --lbs N               Number of load balancer threads (mt mode, default: 2)
  --fps N               Fast-path threads per LB (mt mode, default: 2)
```

## Example Output
```text
[RuleManager] Blocked app: YouTube
[RuleManager] Blocked app: TikTok
[RuleManager] Blocked domain: tiktok

╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v2.0                          ║
╚══════════════════════════════════════════════════════════════╝

Opened PCAP file: test_dpi.pcap
  Version: 2.4
  Snaplen: 65535 bytes
  Link type: 1 (Ethernet)

[DPI] Processing packets...

[BLOCKED] 192.168.1.100 -&gt; 142.250.185.110 (YouTube: www.youtube.com)
[BLOCKED] 192.168.1.100 -&gt; 99.86.0.100 (TikTok: www.tiktok.com)

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                     ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:              77                           ║
║ Forwarded:                  75                           ║
║ Dropped:                     2                           ║
║ Active Flows:               43                           ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                    ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                 39  50.6% ##########            ║
║ Unknown               16  20.8% ####                  ║
║ DNS                    4   5.2% #                     ║
║ YouTube                1   1.3%                       ║
║ Facebook               1   1.3%                       ║
║ Netflix                1   1.3%                       ║
║ TikTok                 1   1.3%                       ║
║ ...                                                        ║
╚══════════════════════════════════════════════════════════════╝

[Detected Applications/Domains]
  - www.youtube.com -&gt; YouTube
  - www.netflix.com -&gt; Netflix
  - twitter.com -&gt; Twitter/X
  - github.com -&gt; GitHub
```

## Supported Applications
| Application | Detection Method |
|---|---|
| YouTube | TLS SNI (youtube, ytimg, youtu.be) |
| Google | TLS SNI (google, googleapis, gstatic) |
| Facebook | TLS SNI (facebook, fbcdn, meta.com) |
| Instagram | TLS SNI (instagram, cdninstagram) |
| Twitter/X | TLS SNI (twitter, twimg, x.com) |
| Netflix | TLS SNI (netflix, nflxvideo) |
| TikTok | TLS SNI (tiktok, bytedance) |
| Discord | TLS SNI (discord, discordapp) |
| Spotify | TLS SNI (spotify, scdn.co) |
| Zoom | TLS SNI (zoom) |
| Telegram | TLS SNI (telegram, t.me) |
| WhatsApp | TLS SNI (whatsapp, wa.me) |
| GitHub | TLS SNI (github, githubusercontent) |
| Amazon/AWS | TLS SNI (amazon, amazonaws, cloudfront) |
| Microsoft | TLS SNI (microsoft, azure, office) |
| Apple | TLS SNI (apple, icloud, itunes) |
| Cloudflare | TLS SNI (cloudflare) |
| DNS | Port 53 (UDP/TCP) |
| HTTP | Port 80 + Host header parsing |
| HTTPS | Port 443 (fallback when SNI unavailable) |

## Rules File Format
The engine supports loading/saving rules in a simple INI-like format:
```ini
[BLOCKED_IPS]
192.168.1.50

[BLOCKED_APPS]
YouTube
TikTok

[BLOCKED_DOMAINS]
*.facebook.com
malware.example.com

[BLOCKED_PORTS]
443
```

**Notes**
- Domain rules support **substring** and **wildcard** matching (e.g., `*.example.com`).
- Rule evaluation order: **IP → Port → App → Domain**.

## Testing
```bash
python -m unittest discover -s tests
```

## Performance & Scalability
- The multi-threaded engine distributes flows across fast-path threads via consistent hashing.
- Throughput scales with CPU cores for flow-heavy PCAPs; real-world performance depends on capture size and traffic mix.

## Security & Privacy Considerations
- DPI inspects metadata (SNI/Host/DNS) that may include sensitive identifiers.
- Use only on traffic you are authorized to analyze.
- This tool does **not** decrypt TLS and does not attempt to bypass encryption.

## Limitations
- **IPv4 only** (non-IPv4 frames are ignored).
- **Offline PCAP processing** only (no live capture).
- **Heuristic classification** based on SNI/hostnames/ports; false positives are possible.

## Contributing
Issues and pull requests are welcome. For large changes, please open an issue first to discuss scope and design.

## License
Licensed under the [MIT License](LICENSE).
