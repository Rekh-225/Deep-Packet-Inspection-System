# Deep Packet Inspection (DPI) Engine

A high-performance, multi-threaded Deep Packet Inspection engine written in C++17. Reads network captures in PCAP format, classifies application traffic via TLS SNI and HTTP host extraction, enforces configurable blocking rules, and writes filtered output — all through a pipelined, lock-minimised architecture.

---

## Features

- **Application Classification** — identifies YouTube, Netflix, Facebook, Twitter, Instagram, WhatsApp, Zoom, and more from live-layer-7 payload inspection
- **TLS SNI Extraction** — reads the Server Name Indication field from TLS Client Hello messages to classify HTTPS traffic without decryption
- **HTTP Host Extraction** — parses the `Host:` header in plain HTTP requests as a fallback classification path
- **Configurable Blocking Rules** — block by IP address, application type, or domain substring; rules are applied per-flow
- **Multi-threaded Pipeline** — Reader → Load Balancer threads → Fast Path threads → Output Writer; consistent hashing ensures all packets of a flow are processed by the same thread
- **PCAP I/O** — reads standard `.pcap` captures (Wireshark, tcpdump) and writes a filtered PCAP with only allowed traffic
- **Per-flow Statistics** — packet/byte counters and a full classification report printed after processing
- **Cross-platform** — builds on Linux, macOS, and Windows (MSVC, MinGW, WSL)

---

## Architecture

```
┌──────────────┐
│ Reader Thread │  (reads PCAP packets)
└──────┬───────┘
       │  hash(5-tuple) % N_LB
  ┌────┴────┐
  │ LB  LB  │  Load Balancer threads
  └────┬────┘
       │  hash(5-tuple) % N_FP
┌──────┴──────────┐
│ FP0  FP1  FP2  FP3 │  Fast Path threads — DPI, flow tracking, blocking
└──────┬──────────┘
       │
┌──────┴────────┐
│ Output Writer  │  (writes filtered PCAP)
└───────────────┘
```

Each Fast Path thread owns a private flow table, so connection state is updated without locks. Load Balancers use the same five-tuple hash to guarantee that every packet of a connection lands on the same Fast Path thread.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | C++17 |
| Build system | CMake 3.16+ |
| Concurrency | `std::thread`, `std::mutex`, `std::condition_variable` |
| Packet I/O | Custom PCAP reader/writer (no external libs required) |
| Packet parsing | Ethernet → IPv4 → TCP/UDP header chain |
| TLS inspection | Manual TLS record / handshake parser |

No third-party runtime dependencies — the engine links only against the C++ standard library.

---

## Project Structure

```
Deep-Packet-Inspection-System/
├── include/
│   ├── types.h               # FiveTuple, AppType, Flow, RawPacket
│   ├── pcap_reader.h         # PCAP global header / packet header structs
│   ├── packet_parser.h       # Ethernet, IP, TCP/UDP parsing
│   ├── sni_extractor.h       # TLS Client Hello SNI parser
│   ├── rule_manager.h        # Blocking rule storage and lookup
│   ├── connection_tracker.h  # Per-flow state management
│   ├── load_balancer.h       # LB thread interface
│   ├── fast_path.h           # FP thread interface
│   ├── thread_safe_queue.h   # Bounded, blocking concurrent queue
│   └── dpi_engine.h          # Top-level engine orchestrator
│
├── src/
│   ├── main_working.cpp      # Single-threaded entry point (learning / small captures)
│   ├── dpi_mt.cpp            # Multi-threaded entry point (production)
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   ├── types.cpp
│   └── ...
│
├── generate_test_pcap.py     # Python script to generate synthetic test captures
├── test_dpi.pcap             # Sample capture with mixed application traffic
├── CMakeLists.txt
└── WINDOWS_SETUP.md          # Detailed Windows build guide
```

---

## Building

### Prerequisites

- **Linux / macOS**: GCC 9+ or Clang 10+ with C++17 support
- **Windows**: Visual Studio 2022, MinGW-w64, or WSL2 (see [`WINDOWS_SETUP.md`](WINDOWS_SETUP.md))
- CMake 3.16+ (optional — direct compiler invocation also works)

### Linux / macOS

```bash
# Clone and enter the repo
git clone https://github.com/Rekh-225/Deep-Packet-Inspection-System.git
cd Deep-Packet-Inspection-System

# Build the multi-threaded engine
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

### Windows (MSVC)

```cmd
cl /EHsc /std:c++17 /O2 /I include /Fe:dpi_engine.exe ^
    src\dpi_mt.cpp ^
    src\pcap_reader.cpp ^
    src\packet_parser.cpp ^
    src\sni_extractor.cpp ^
    src\types.cpp
```

> For full Windows instructions see [`WINDOWS_SETUP.md`](WINDOWS_SETUP.md).

---

## Usage

```bash
# Inspect a capture — classify and forward all traffic
./dpi_engine input.pcap output.pcap

# Block a specific application
./dpi_engine input.pcap output.pcap --block-app YouTube

# Block multiple applications and a specific IP
./dpi_engine input.pcap output.pcap --block-app YouTube --block-app Netflix --block-ip 192.168.1.50

# Block a domain (substring match)
./dpi_engine input.pcap output.pcap --block-domain tiktok.com

# Tune the thread pool (default: 2 LBs, 4 FPs)
./dpi_engine input.pcap output.pcap --lbs 4 --fps 8
```

### Generating Test Traffic

```bash
python generate_test_pcap.py   # creates test_dpi.pcap
./dpi_engine test_dpi.pcap filtered.pcap
```

---

## Sample Output

```
[DPI Engine] Processing: test_dpi.pcap
[DPI Engine] Using 2 Load Balancers, 4 Fast Paths

=== DPI Report ===
Total packets   : 1 024
Forwarded       : 876
Dropped (blocked): 148

Application Breakdown:
  YouTube    :  312 packets  (30.5%)
  Netflix    :  224 packets  (21.9%)
  Facebook   :  188 packets  (18.4%)
  HTTPS Other:  152 packets  (14.8%)
  HTTP       :   96 packets   (9.4%)
  Unknown    :   52 packets   (5.1%)

Output written to: filtered.pcap
```

---

## How It Works

### Five-Tuple Flow Tracking

Every packet is identified by its **five-tuple** (src IP, dst IP, src port, dst port, protocol). All packets sharing a five-tuple belong to the same connection. The engine hashes this tuple to route packets consistently to one Fast Path thread, which holds the mutable flow state.

### TLS SNI Extraction

For HTTPS traffic (destination port 443), the engine inspects the first bytes of the TCP payload. If the record content type is `0x16` (Handshake) and the handshake type is `0x01` (Client Hello), it navigates the extension list to locate extension type `0x0000` (SNI) and reads the hostname — in plaintext, before encryption begins.

### Blocking Pipeline

1. Packet arrives at a Fast Path thread
2. Flow state is looked up (or created)
3. SNI / Host is extracted if not already known for this flow
4. Application type is resolved from the hostname
5. Blocking rules are checked: IP blacklist → app blacklist → domain substring list
6. Allowed packets are forwarded to the output queue; blocked packets are counted and discarded

---

## License

This project is open for personal and educational use.
