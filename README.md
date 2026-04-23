# DPI Engine — Deep Packet Inspection System

A Python-based deep packet inspection engine that reads network captures (PCAP files), classifies traffic by application using protocol-level analysis, and applies configurable blocking rules.

## Features

- **Protocol Parsing** — Dissects Ethernet, IPv4, TCP, and UDP headers from raw packet bytes
- **TLS SNI Extraction** — Identifies applications by extracting the Server Name Indication from TLS Client Hello handshakes
- **HTTP Host Detection** — Extracts the `Host` header from unencrypted HTTP requests
- **DNS Query Analysis** — Parses DNS queries to detect domain lookups
- **Traffic Classification** — Automatically identifies 20+ applications: YouTube, Facebook, Netflix, TikTok, Discord, Spotify, Zoom, and more
- **Blocking Rules** — Block traffic by IP address, application, domain (with wildcard support), or port
- **Dual Engine Modes** — Single-threaded (simple) and multi-threaded (LB → FP pipeline) architectures
- **PCAP Output** — Produces a filtered PCAP file with blocked packets removed

## Architecture

```
                    ┌──────────────────┐
                    │   PCAP Reader    │  Reads raw packets from file
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  Packet Parser   │  Ethernet → IPv4 → TCP/UDP
                    └────────┬─────────┘
                             │
              ┌──────────────▼──────────────┐
              │      DPI Inspection         │
              │  ┌─────────────────────┐    │
              │  │  SNI Extractor      │    │  TLS Client Hello → hostname
              │  │  HTTP Host Extract  │    │  HTTP GET → Host header
              │  │  DNS Extractor      │    │  DNS query → domain name
              │  └─────────────────────┘    │
              └──────────────┬──────────────┘
                             │
                    ┌────────▼─────────┐
                    │  Classification  │  hostname → App (YouTube, etc.)
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  Rule Manager    │  Check block rules (IP/App/Domain)
                    └────────┬─────────┘
                             │
                      ┌──────┴──────┐
                      ▼             ▼
                  FORWARD         DROP
                      │
              ┌───────▼───────┐
              │  PCAP Writer  │  Write allowed packets to output
              └───────────────┘
```

### Multi-Threaded Architecture

```
    Reader ──┬──► LB0 ──┬──► FP0 ──┐
             │          └──► FP1 ──┤
             └──► LB1 ──┬──► FP2 ──┤──► Output Queue ──► Writer
                        └──► FP3 ──┘
```

- **Load Balancers (LB)** distribute packets to Fast Path threads using consistent hashing on the five-tuple
- **Fast Path (FP)** threads perform DPI inspection and rule matching
- Consistent hashing ensures all packets of the same flow land on the same FP thread

## Requirements

- **Python 3.8+**
- No external dependencies (uses Python standard library only)

## Installation

```bash
git clone https://github.com/yourusername/DPI.git
cd DPI
```

That's it — no `pip install` required.

## Usage

### Basic Processing

```bash
python cli.py input.pcap output.pcap
```

### Blocking Traffic

```bash
# Block an application
python cli.py capture.pcap filtered.pcap --block-app YouTube

# Block an IP address
python cli.py capture.pcap filtered.pcap --block-ip 192.168.1.50

# Block a domain
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

### Generating Test Data

```bash
python generate_test_pcap.py
# Creates test_dpi.pcap with sample TLS, HTTP, DNS, and blocked IP traffic
```

### All Options

```
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
  --block-domain DOMAIN Block domain by substring match
  --block-port PORT     Block destination port
  --rules-file FILE     Load blocking rules from a file

engine mode:
  --mode {simple,mt}    simple (single-threaded) or mt (multi-threaded)
  --lbs N               Number of load balancer threads (mt mode, default: 2)
  --fps N               Fast-path threads per LB (mt mode, default: 2)
```

## Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                     ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:              77                           ║
║ Forwarded:                  71                           ║
║ Dropped:                     6                           ║
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
║ ...                                                        ║
╚══════════════════════════════════════════════════════════════╝

[Detected Applications/Domains]
  - www.youtube.com -> YouTube
  - www.netflix.com -> Netflix
  - twitter.com -> Twitter/X
  - github.com -> GitHub
```

## Supported Applications

| Application | Detection Method |
|---|---|
| YouTube | TLS SNI (`youtube`, `ytimg`, `youtu.be`) |
| Google | TLS SNI (`google`, `googleapis`, `gstatic`) |
| Facebook | TLS SNI (`facebook`, `fbcdn`, `meta.com`) |
| Instagram | TLS SNI (`instagram`, `cdninstagram`) |
| Twitter/X | TLS SNI (`twitter`, `twimg`, `x.com`) |
| Netflix | TLS SNI (`netflix`, `nflxvideo`) |
| TikTok | TLS SNI (`tiktok`, `bytedance`) |
| Discord | TLS SNI (`discord`, `discordapp`) |
| Spotify | TLS SNI (`spotify`, `scdn.co`) |
| Zoom | TLS SNI (`zoom`) |
| Telegram | TLS SNI (`telegram`, `t.me`) |
| WhatsApp | TLS SNI (`whatsapp`, `wa.me`) |
| GitHub | TLS SNI (`github`, `githubusercontent`) |
| Amazon/AWS | TLS SNI (`amazon`, `amazonaws`, `cloudfront`) |
| Microsoft | TLS SNI (`microsoft`, `azure`, `office`) |
| Apple | TLS SNI (`apple`, `icloud`, `itunes`) |
| Cloudflare | TLS SNI (`cloudflare`) |
| DNS | Port 53 (UDP/TCP) |
| HTTP | Port 80 + Host header parsing |
| HTTPS | Port 443 (fallback when SNI cannot be extracted) |

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
├── requirements.txt            Dependencies (stdlib only)
└── README.md
```

## How It Works

### 1. Packet Parsing
Raw bytes are parsed layer by layer using Python's `struct` module:
- **Ethernet** (14 bytes): Source/destination MAC, EtherType
- **IPv4** (20+ bytes): Source/destination IP, protocol, TTL, IP Header Length (IHL)
- **TCP** (20+ bytes): Source/destination port, flags, sequence numbers
- **UDP** (8 bytes): Source/destination port, length

### 2. Deep Packet Inspection
The engine inspects the **payload** of each packet:
- **TLS Client Hello**: Parses the TLS handshake structure, walks the extensions list, and extracts the SNI extension (type `0x0000`) to find the target hostname
- **HTTP Request**: Searches for the `Host:` header in plaintext HTTP
- **DNS Query**: Decodes the DNS wire format to extract the queried domain name

### 3. Flow Tracking
Packets are grouped into **flows** using the **five-tuple** (source IP, destination IP, source port, destination port, protocol). Each flow maintains:
- Classification state (app type, detected SNI/hostname)
- Blocking status
- Packet/byte counters

### 4. Consistent Hashing (Multi-threaded)
In multi-threaded mode, the five-tuple is hashed to select both the Load Balancer and Fast Path thread. This ensures **all packets of the same flow are processed by the same thread**, enabling correct stateful flow tracking without locks on the flow table.

## License

MIT
