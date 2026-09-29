# dpi-engine — usage guide

Offline deep packet inspection of PCAP captures: classifies flows by TLS SNI /
HTTP Host / DNS query name, applies blocking rules, writes a filtered PCAP, and
optionally writes JSON / HTML reports. Standard library only, Python ≥ 3.8.

## Install

```bash
python -m pip install .            # from a checkout; installs the `dpi-engine` command
# or, without installing:
python cli.py ...                  # repo checkout
python -m dpi ...                  # after install, or from the checkout
```

Verify: `dpi-engine --version` → `dpi-engine 2.1.0`.

## Run

```bash
dpi-engine INPUT.pcap OUTPUT.pcap [rules] [engine] [reports]
```

| Group | Option | Meaning |
|---|---|---|
| rules | `--block-ip IP` | drop flows whose **source** IP matches (repeatable) |
| | `--block-app NAME` | drop flows heuristically classified as NAME, e.g. `YouTube`, `Netflix`, `DNS`, `HTTPS` (repeatable) |
| | `--block-domain TEXT` | case-insensitive substring of the observed SNI / Host / DNS name, or `*.suffix` wildcard (repeatable) |
| | `--block-port N` | drop flows whose **destination** port is N (repeatable) |
| | `--rules-file FILE` | load rules from a file (format below) |
| engine | `--mode simple\|mt` | single-threaded (default) or multi-threaded pipeline |
| | `--lbs N --fps N` | mt layout: load balancers × fast paths per LB (default 2×2) |
| | `--queue-size N` | mt: max packets in flight (default 10000) |
| | `--max-flows N` | global limit on tracked flows for the run, identical in both modes (default 200000); exceeding it fails the run |
| reports | `--report-json FILE` | machine-readable report |
| | `--report-html FILE` | static, script-free HTML report |
| | `--report-max-flows N` | list at most N flows (default 1000); the total is always recorded |
| | `--max-report-detail N` | keep at most N detected names / blocked-flow entries for console and report detail (default 10000); overflow is counted and shown as truncated |
| | `--report-no-timestamp` | omit `generated_at` for reproducible files |

Both engine modes produce **byte-identical** output and identical statistics.
`mt` is a demonstration of a correct pipelined design and is slower than
`simple` in Python (see `benchmarks/README.md`).

### Rules file

```
[BLOCKED_IPS]
192.0.2.66

[BLOCKED_APPS]
YouTube
Netflix

[BLOCKED_DOMAINS]
evil.test
*.tracker.example

[BLOCKED_PORTS]
53
```

### Exit status

| Code | Meaning |
|---|---|
| 0 | complete output written, and every requested report |
| 1 | processing failed: unreadable / unsupported / truncated input, unwritable output, worker error, flow limit exceeded (`--max-flows`), accounting mismatch. **No output file is left at the destination.** |
| 2 | usage error, or rules file could not be loaded |
| 3 | **capture completed; report failed.** The output PCAP is complete and in place; at least one requested report could not be written. stderr lists each output as `written` or `FAILED` with the reason. No partial report is left at the report path. |
| 130 | cancelled (Ctrl-C) before the output was committed; no output left. (Ctrl-C after the commit leaves the completed output and exits 0.) |

Automation can rely on: status 0 or 3 ⇒ the capture at the output path is
complete; status 1, 2 or 130 ⇒ nothing is at the output path.

### Limits

| Limit | Option | Default | What it bounds |
|---|---|---|---|
| packet window | `--queue-size` (mt) | 10 000 | admitted-but-unretired packets: every stage queue and the reorder buffer |
| active flow state | `--max-flows` | 200 000 | flows tracked in the whole run, the same in both modes; one more flow ⇒ controlled failure, never silent eviction |
| report detail | `--max-report-detail` | 10 000 | detected names and blocked-flow entries kept for display; aggregate counts stay exact |
| report flow list | `--report-max-flows` | 1 000 | flows listed in JSON/HTML; the total is always recorded |

These are separate limits; `--queue-size` alone is not a bound on total process memory.

## What is supported

**Input format.** Classic `.pcap` only: magic `0xA1B2C3D4` (either byte order),
microsecond timestamps, link type 1 (Ethernet). The following are rejected with
exit status 1 and a specific message: pcapng, nanosecond-resolution pcap
(`0xA1B23C4D`), any other link type, a file shorter than the 24-byte header, a
record whose captured length exceeds 65 535, and any file that ends inside a
record header or body (truncated captures are refused, not processed "up to
the cut").

**Packets that are inspected.** Ethernet II frame → IPv4 (version 4, IHL ≥ 5,
total length consistent with the header and fully captured; options skipped via
IHL; not a fragment) → TCP (data offset ≥ 5, header within the IP payload) or
UDP (length ≥ 8 and within the IP payload). Transport parsing is confined to the
declared IP total length, so Ethernet padding is never treated as payload.
Every such packet is classified, rule-checked, and either written (*retained*)
or dropped (*rule-filtered*).

**Packets that are not inspected.** Anything else is **counted and excluded
from the output**:

- *malformed* — header fields inconsistent with each other or with the captured
  bytes (e.g. IPv4 total length larger than the bytes captured, UDP length
  larger than the IP payload, TCP header longer than the IP payload). Checked
  first, so a malformed fragment is malformed, not unsupported.
- *unsupported* — well-formed but not something this tool inspects: non-IPv4
  EtherType (ARP, IPv6, VLAN-tagged frames), non-TCP/UDP IP protocols (ICMP), and
  **IPv4 fragments** (MF set or non-zero offset — no transport header is read
  from fragment payload, since reassembly is out of scope).

A PCAP record whose original wire length exceeds its captured length is
processed normally as long as the IP datagram is complete within the captured
bytes; the output keeps both lengths and the timestamp exactly.

The report and the console summary show these counts, and the accounting
`total = retained + filtered + unsupported + malformed` is verified before an
output is committed.

**Application data that cannot be parsed** (a TLS record, handshake, extension
or SNI list whose lengths disagree or run past the record; a DNS question
without a terminating label, QTYPE and QCLASS, or using compression; an empty,
over-long or non-ASCII name) yields **no name**, never a partial one, and
therefore cannot match a domain rule. This does not change the packet's
category — it is still a valid TCP/UDP packet, so it is retained (or filtered by
IP / port / app rules) and its flow keeps the port heuristic (`HTTPS`, `HTTP`,
`DNS`). The report shows such flows with empty observed names.

**Protocol cases recognised for names.**

| Protocol | Condition | What is extracted |
|---|---|---|
| TLS | TCP, destination port 443, a complete Client Hello record at the start of one segment; record, handshake, extensions, extension, SNI-list and name lengths all consistent | SNI `host_name` (ASCII, 1–255 bytes) |
| HTTP | TCP, destination port 80, request line starting GET/POST/PUT/HEAD/DELETE/PATCH/OPTIONS in one segment | `Host:` header (port suffix stripped; ASCII, ≤ 255 chars) |
| DNS | UDP or TCP port 53, standard query (QR=0, QDCOUNT>0) with a complete QNAME, terminator, QTYPE and QCLASS | first question name (≤ 253 chars; compression pointers rejected) |

Not handled: TCP reassembly (a Client Hello split across segments is missed),
TLS on other ports, QUIC, HTTP/2, DNS responses, DNS-over-TCP length prefix,
IPv4 fragments (excluded as unsupported). Flows are **directional**: A→B and
B→A are separate flows; a rule matched on the client's Client Hello blocks the
client→server direction from that packet on, and never the server→client
direction. Packets of a flow that arrive **before** the packet that classifies
it are forwarded.

**Flow-state capacity.** Both modes draw from one global `--max-flows` counter,
so results never depend on the thread layout. Flow state is never evicted
(evicting a blocked flow would let its later packets through); when one more
flow would exceed the limit the run fails with exit 1 and a message naming the
limit, and no output is committed.

## Reports

`--report-json` writes `dpi-engine-report/1`: tool version, run settings,
rules in effect, accounting, packets/flows by heuristic class, and a bounded
list of flows with endpoints, packet/byte counts, the observed `tls_sni` /
`http_host` / `dns_query` (kept separate), the heuristic classification
(`app`, `known`, `method`), the matching rule (`type`, `detail`) or `null`, and
the final `action` (`forward` / `drop`).

`--report-html` renders the same data as a static page with no scripts and a
restrictive CSP. Every captured string is HTML-escaped and clipped to 255
characters; control characters are replaced.

Classification is a **heuristic**: a name or port matched a static pattern
table. `Unknown` means no heuristic matched. A match tells you which service a
flow appears to contact; it is **not** evidence of malicious traffic, and the
reports say so.

## Samples and demo

```bash
python demo.py                     # runs the sample captures, writes demo_out/
python samples/make_samples.py --check
```

See `samples/README.md` for each capture's contents and expected results.

## Tests and benchmark

```bash
python -m unittest discover -s tests -v          # full suite (includes a clean-venv install test)
DPI_SKIP_INSTALL_TEST=1 python -m unittest discover -s tests   # skip the slow install test
python benchmarks/bench.py                        # throughput + classification agreement
```
