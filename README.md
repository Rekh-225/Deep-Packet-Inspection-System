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
             └──► LB1 ──┬──► FP2 ──┤──► Output Queue ──► Writer ──► out.pcap
                        └──► FP3 ──┘
      └── unsupported / malformed packets ──────────────►┘
```

- **Load Balancers (LB)** dispatch packets to the Fast Path threads they own
- **Fast Path (FP)** threads perform DPI inspection and rule matching, each with its own flow table
- **Writer** restores input order and is the only thread that touches the output file
- Both engines share one implementation of classification and rule evaluation (`dpi/inspection.py`), and the test suite asserts that they produce byte-identical output and identical statistics

#### Lifecycle (how completion is determined)

There are no fixed sleeps or timed shutdowns. Completion is established by explicit stage signals:

1. **Admission.** The reader assigns every packet a contiguous `packet_id` in file order and takes one permit from a bounded *window* semaphore (`queue_size`, default 10 000) before admitting it. Supported packets (IPv4 TCP/UDP) go to an LB; unsupported and malformed packets are sent straight to the writer as *completions*. When the window is full, the reader blocks. This is the only backpressure mechanism, and it bounds every queue and the writer's reorder buffer.
2. **End of input.** The reader sends one end-of-input sentinel to every LB. Each LB forwards the sentinel to every FP it owns and exits. Each FP posts a *done* marker on the output queue and exits. Queues are FIFO, so a marker always trails every completion that stage produced.
3. **Ordered retirement.** The writer buffers completions by `packet_id` and retires them strictly in input order, releasing one window permit per retired packet. Filtered, unsupported and malformed packets produce completions too, so ids are contiguous and the writer never waits for an id that will not arrive. It finishes when it has received a done marker from every FP.
4. **Finalisation.** The main thread joins every thread (in short polls, so Ctrl-C is delivered promptly), checks that the accounting reconciles (`total == retained + filtered + unsupported + malformed`), and only then moves the uniquely named temporary file (`.<output>.XXXXXX.partial`, created exclusively in the destination directory) to `<output>`. Pre-existing files — including any user file that merely ends in `.partial` — are never opened or deleted; the destination is replaced only by a successful commit.

**Failure and cancellation.** Every blocking queue/semaphore operation polls a shared stop flag, so an exception in any stage — even with every queue full — unwinds all the others without deadlock. A worker, reader or writer exception, the flow limit, `engine.cancel()`, or an accounting mismatch discards the temporary output and raises `ProcessingError` (the specific subclass is preserved — `FlowCapacityExceeded`, `PcapFormatError`, `PcapWriteError`). Ctrl-C at *any* point — startup, reading, sentinel signalling, joining a slow worker, finalisation — cancels, unblocks and joins every stage (tolerating repeated interrupts), closes the reader, removes the temporary output, and raises `ProcessingCancelled`; if cleanup itself fails, the message names the file left behind rather than claiming success. A Ctrl-C that arrives after the output was committed leaves the completed output in place. The CLI maps these to exit status 1 / 130.

**Flow-state capacity.** Both engines share one global `--max-flows` limit (default 200 000) through a single `FlowCapacity` counter — one flow table in the simple engine, one per fast path in the MT engine, all drawing from the same limit — so the amount of state retained does not depend on the thread layout. Flow state is never evicted silently: dropping a blocked flow's classification would let later packets of that flow through, and the two engines would then diverge. When admitting one more flow would exceed the limit, the run fails with `FlowCapacityExceeded` (exit 1), reports the limit, and commits nothing.

**Aborted-run accounting.** When a run fails or is cancelled the engine reports, precisely: *admitted* (packets read and given an id), *decided* (admitted packets whose outcome was determined by the reader or a fast path — a decision may still be waiting in the reorder buffer), *retired* (decided packets the writer processed in order; only these appear in the terminal categories), *decided but not yet retired*, *undecided* (admitted − decided), and whether the input was fully read (the number of unread packets is otherwise unknown and is not guessed). `failed_packets` = admitted − retired, so `reconciles()` still holds.

#### Routing and flow affinity

`flow_hash` is a CRC-32 of the *canonical* five-tuple (the two `(ip, port)` endpoints sorted, plus protocol), so both directions of a connection hash identically. The LB is `h % num_lbs` and the FP within that LB is `(h // num_lbs) % fps_per_lb`; the quotient makes the second choice independent of the first so every FP is reachable. (The previous implementation used `h % num_lbs` and `h % fps_per_lb`, which are correlated — with the default 2×2 layout two of the four FPs never received a packet.)

*Directional vs bidirectional:* **routing** is bidirectional (A→B and B→A always land on the same FP), but **flow state** is directional — the flow table key is the exact `(src, dst, sport, dport, proto)` tuple, so the two directions of a TCP connection are tracked, classified and blocked separately. This matches the single-threaded engine: a rule that matches the client's TLS Client Hello blocks the client→server direction from that packet on; server→client packets are not blocked. That is existing behaviour and is preserved deliberately.

#### Packet accounting

Every packet read lands in exactly one category, and the report shows all of them:

| Category | Meaning | In output? |
|---|---|---|
| Retained (`forwarded_packets`) | IPv4 TCP/UDP, no rule matched | yes |
| Rule-filtered (`dropped_packets`) | IPv4 TCP/UDP, flow matched a rule | no |
| Unsupported (`unsupported_packets`) | parsed but not IPv4 + TCP/UDP (ARP, IPv6, ICMP, VLAN-tagged, …) | **no** |
| Malformed (`malformed_packets`) | headers truncated / inconsistent | **no** |
| Failed (`failed_packets`) | admitted but not retired when the run aborted (see *Aborted-run accounting* for the decided/undecided split) | run fails |

Unsupported and malformed packets are **not** written: the engine only forwards traffic it was able to inspect. With no blocking rules, a capture consisting only of supported packets is reproduced exactly; a capture containing other protocols is not, and the report says so. `DPIStats.reconciles()` is checked by the MT engine before an output is committed.

## Requirements

- **Python 3.8+**
- No external dependencies (uses Python standard library only)

## Installation

```bash
git clone https://github.com/Rekh-225/Deep-Packet-Inspection-System.git
cd Deep-Packet-Inspection-System
python -m pip install .        # installs the `dpi-engine` command (stdlib only, no dependencies)
dpi-engine --version
```

Running from the checkout without installing also works: `python cli.py …` or
`python -m dpi …`. All three invocations take the same arguments.

The concise guide is [`docs/USAGE.md`](docs/USAGE.md); sample captures with
expected results are in [`samples/`](samples/README.md); `python demo.py` runs
them and writes filtered captures plus reports to `demo_out/`.

## Usage

### Basic Processing

```bash
dpi-engine input.pcap output.pcap
```

### Blocking Traffic

```bash
# Block an application
dpi-engine capture.pcap filtered.pcap --block-app YouTube

# Block an IP address
dpi-engine capture.pcap filtered.pcap --block-ip 192.168.1.50

# Block a domain
dpi-engine capture.pcap filtered.pcap --block-domain tiktok

# Combine multiple rules
dpi-engine capture.pcap filtered.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain malware.example.com
```

### Multi-Threaded Mode

```bash
# Default: 2 load balancers, 2 fast-path threads per LB (4 total)
dpi-engine capture.pcap filtered.pcap --mode mt

# Custom thread count
dpi-engine capture.pcap filtered.pcap --mode mt --lbs 4 --fps 4
```

Both modes produce byte-identical output for the same input and rules. The `mt` mode exists to demonstrate a correct pipelined design (bounded queues, ordered output, explicit completion); because the work is pure Python under the GIL and every packet crosses three queues, **it is not faster than `simple` mode**. Measured after the review repairs on a 51 000-packet synthetic capture (best of 3, one Windows laptop, Python 3.13): `simple` ≈ 46 kpps; `mt` ≈ 27–29 kpps for every layout from 1×1 to 2×4 (details and history in `benchmarks/README.md`). Measure on your own hardware before assuming otherwise.

### Exit Status

| Code | Meaning |
|---|---|
| 0 | complete output written, and every requested report |
| 1 | processing failed (unreadable/unsupported/truncated input, unwritable output, worker error, flow limit exceeded, accounting mismatch) — no output file is left at the destination |
| 2 | usage error, or the `--rules-file` could not be loaded |
| 3 | **capture completed; report failed** — the output PCAP is complete and in place, but at least one requested report could not be written; stderr lists which outputs exist and which failed |
| 130 | cancelled (Ctrl-C) before the output was committed — no output file is left |

### Limits

| Limit | Option | Default | Bounds |
|---|---|---|---|
| Packet window | `--queue-size N` (mt) | 10 000 | packets admitted but not yet retired, i.e. every stage queue and the writer's reorder buffer |
| Active flow state | `--max-flows N` | 200 000 | tracked flows for the whole run, **identical in both modes**; exceeding it is a controlled failure (exit 1), never silent eviction |
| Report detail | `--max-report-detail N` | 10 000 | detected names and blocked-flow entries kept for the console/report; overflow is counted and shown as truncated |
| Report flow list | `--report-max-flows N` | 1 000 | flows listed in JSON/HTML; the true total is always recorded |

`queue_size` is not a bound on total process memory: flow state grows with distinct flows up to `--max-flows`, and report detail up to `--max-report-detail`.

### Generating Test Data

```bash
python generate_test_pcap.py
# Creates test_dpi.pcap with sample TLS, HTTP, DNS, and blocked IP traffic
```

### Running the Tests

```bash
python -m unittest discover -s tests -v                      # full suite
DPI_SKIP_INSTALL_TEST=1 python -m unittest discover -s tests # skip the ~25 s clean-venv install test
python benchmarks/bench.py                                   # throughput and classification agreement (see benchmarks/README.md)
python tools/make_release.py                                 # local release archive under release/ (never uploaded)
```

The suite runs in CI (`.github/workflows/ci.yml`) on Linux and Windows across Python 3.8–3.13, then installs the package into a clean interpreter and smoke-tests the `dpi-engine` command in both modes, including a failing run exiting nonzero.

**Sample provenance.** `samples/captures/` are synthetic, generated deterministically by `samples/make_samples.py` from IANA documentation addresses; expected results in `samples/expected.json` are stated by construction and checked by `tests/test_samples.py`. Details: [`samples/README.md`](samples/README.md).

**Fixture provenance.** `test_dpi.pcap` is produced by `generate_test_pcap.py`, a standalone packet crafter that does not use the DPI parser. `tests/fixtures.py` is a second, independent, fully deterministic crafter (no randomness) whose fixtures carry expectations stated by construction (e.g. "44 supported, 3 unsupported, 1 malformed"). Engine tests compare against those numbers and against the single-threaded engine, not against previously recorded MT output. The only value pinned from the implementation itself is the CRC-32 `flow_hash` regression check, and the test says so.

### Reports

```bash
dpi-engine capture.pcap filtered.pcap --block-app YouTube \
    --report-json run.json --report-html run.html [--report-max-flows 500]
```

Reports list every flow (bounded by `--report-max-flows`, default 1000, with
the true total recorded) with its endpoints, packet/byte counts, the observed
TLS SNI / HTTP Host / DNS query name (kept separate), the heuristic
classification (`Unknown` is kept distinct from a positive match), the rule
that matched, the final action, plus the run's accounting and rules. The HTML
is static (no scripts, restrictive CSP) and every captured string is escaped
and clipped. Reports are written only after a complete, reconciled run.
Examples: [`samples/reports/`](samples/reports/).

Classification is a heuristic pattern match on names and ports. It indicates
which service a flow *appears* to contact; it is **not** evidence of malicious
traffic, and the reports say so.

### All Options

```
usage: dpi-engine [-h] [--version] [--block-ip IP] [--block-app APP]
                  [--block-domain DOMAIN] [--block-port PORT] [--rules-file FILE]
                  [--mode {simple,mt}] [--lbs N] [--fps N] [--queue-size N]
                  [--report-json FILE] [--report-html FILE]
                  [--report-max-flows N] [--report-no-timestamp]
                  input output

positional arguments:
  input                 Input PCAP file path
  output                Output PCAP file path (filtered)

blocking rules:
  --block-ip IP         Block traffic from source IP (can be repeated)
  --block-app APP       Block application: YouTube, Facebook, TikTok, etc.
  --block-domain DOMAIN Block domain by substring match, or *.suffix wildcard
  --block-port PORT     Block destination port
  --rules-file FILE     Load blocking rules from a file

engine mode:
  --mode {simple,mt}    simple (single-threaded) or mt (multi-threaded)
  --lbs N               Number of load balancer threads (mt mode, default: 2)
  --fps N               Fast-path threads per LB (mt mode, default: 2)
  --queue-size N        Max packets in flight (mt mode, default: 10000)

reports (written only after a successful run):
  --report-json FILE    Write a JSON report to FILE
  --report-html FILE    Write a static HTML report to FILE
  --report-max-flows N  List at most N flows in reports (default: 1000)
  --report-no-timestamp Omit the generation timestamp (reproducible output)
```

### Supported Input

Classic `.pcap` only (magic `0xA1B2C3D4`, either byte order, microsecond
timestamps, Ethernet link type). pcapng, nanosecond pcap, other link types,
files shorter than the 24-byte header, records longer than 65 535 bytes and
truncated captures are **rejected with exit status 1** and a specific message
— a truncated capture is never processed "up to the cut". See
[`docs/USAGE.md`](docs/USAGE.md) for the full list of supported protocol cases.

## Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                     ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:              77                           ║
║ Retained (written):         71                           ║
║ Rule-filtered:               6                           ║
║ Unsupported:                 0                           ║
║ Malformed:                   0                           ║
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
│   ├── inspection.py           Shared classify + rule decision logic, packet categories
│   ├── engine.py               Single-threaded DPI engine (reference)
│   ├── engine_mt.py            Multi-threaded DPI engine
│   ├── report.py               Bounded JSON / escaped static HTML reports
│   ├── cli.py                  Command-line interface (`dpi-engine` entry point)
│   └── __main__.py             `python -m dpi`
│
├── tests/                      unittest suite
│   ├── fixtures.py             Independent deterministic packet/PCAP builders
│   ├── test_engine_mt.py       Routing, ordering, lifecycle, failures, equivalence
│   ├── test_report.py          Report consistency, bounds, escaping
│   ├── test_samples.py         Sample expectations and rejected-input contract
│   ├── test_cli.py             Exit-status contract
│   ├── test_install.py         Clean-venv `pip install .` + `dpi-engine`
│   └── ...                     Unit tests per module
├── samples/                    Synthetic captures, rules, expected.json, sample reports
├── docs/USAGE.md               Concise usage guide and supported-input contract
├── docs/REVIEW_REPAIRS.md      Findings from the local review, root causes, contracts
├── LICENSE                     MIT
├── benchmarks/                 bench.py + README with the last measured run
├── tools/make_release.py       Builds a local release archive under release/
├── demo.py                     Short demo over the samples (writes demo_out/)
├── .github/workflows/ci.yml    CI: tests + install + CLI smoke tests on Linux/Windows
├── pyproject.toml              Packaging (setuptools, stdlib only)
├── cli.py                      Compatibility launcher for `python cli.py`
├── generate_test_pcap.py       Legacy test PCAP generator
├── test_dpi.pcap               Legacy sample capture used by unit tests
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
In multi-threaded mode, the canonical five-tuple is hashed once; the LB index and the FP index are derived from independent parts of that hash (see *Routing and flow affinity* above). This ensures **all packets of the same flow — in both directions — are processed by the same thread**, enabling correct stateful flow tracking without locks on the flow table.

## Parser Limits

The engine is a teaching-scale inspector. Be aware of what it does **not** do:

- **Link layer:** only Ethernet (`LINKTYPE_ETHERNET` = 1) captures are accepted; any other PCAP link type is rejected when the file is opened (exit 1). Frames whose EtherType is not IPv4 (802.1Q VLAN tags, ARP, PPPoE, MPLS, …) are *unsupported*.
- **Network layer:** IPv4 only. IPv6 is *unsupported*. The header is validated before anything else is read: version 4, IHL ≥ 5, total length ≥ IHL×4 and ≤ captured bytes — otherwise the packet is *malformed*. Transport parsing is confined to the declared total length, so Ethernet padding is never treated as payload. IPv4 fragments (MF set or non-zero offset) are *unsupported* — no transport header is read from fragment payload, and fragments are not reassembled.
- **Transport:** TCP and UDP only; ICMP and everything else is *unsupported*. TCP data offset must be ≥ 5 and the header must fit in the IP payload; UDP length must be ≥ 8 and fit in the IP payload — otherwise *malformed*. Payload is bounded by the IP total length (TCP) or the UDP length. There is **no TCP stream reassembly**: a TLS Client Hello or HTTP request that is split across segments, or that does not start at the beginning of a segment, will not be recognised.
- **Malformed vs unsupported:** structural checks come first. A packet whose headers are inconsistent with each other or with the captured bytes is *malformed* even if it would also have been unsupported. Both are counted and excluded from the output. A PCAP record whose original length exceeds its captured length is fine as long as the IP datagram itself is complete within the captured bytes.
- **Application data:** a payload that fails validation (truncated or inconsistent TLS record/handshake/extension/SNI lengths, incomplete DNS question, over-long or non-ASCII names) yields **no name** — never a partial one — and cannot match a domain rule. This does not change the packet's category: it is still a valid TCP/UDP packet, so it is retained (or filtered by IP/port/app rules) and its flow keeps the port heuristic (`HTTPS`/`HTTP`/`DNS`).
- **TLS:** SNI is read from a Client Hello only when it appears on destination port 443 in a single segment, with every length field (record, handshake, extensions, extension, SNI list, name) consistent. Names are ASCII, 1–255 bytes. Other ports, session resumption without SNI, ESNI/ECH, and QUIC are not classified beyond a port-based `HTTPS` fallback. (`QUICSNIExtractor` exists but is not wired into the engines.)
- **HTTP:** the `Host` header is read from requests on destination port 80 whose method is one of GET/POST/PUT/HEAD/DELETE/PATCH/OPTIONS; ASCII, ≤ 255 characters. Other ports and HTTP/2 are not parsed.
- **DNS:** the first question name is decoded from UDP/TCP port-53 payloads that are standard queries (QR=0, QDCOUNT>0) with a complete QNAME (labels 1–63 bytes, terminating zero) followed by QTYPE and QCLASS; ≤ 253 characters. Compression pointers in the question are rejected. DNS-over-TCP carries a 2-byte length prefix that the extractor does not skip, so names in TCP DNS are generally not extracted (the flow is still classified `DNS` by port). Responses and DoH/DoT are not handled.
- **PCAP format:** classic `.pcap` with microsecond timestamps in either byte order. Nanosecond-magic files and `.pcapng` are rejected.
- **Rules:** domain rules are case-insensitive substring matches (or `*.suffix` wildcards) against the extracted SNI / Host / DNS name; IP rules match the **source** IP only; port rules match the **destination** port only.

Unsupported and malformed packets are counted and excluded from the output — see *Packet accounting*.

## License

MIT — see [`LICENSE`](LICENSE). Copyright (c) 2026 Rekh-225.
