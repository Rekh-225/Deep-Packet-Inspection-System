# Sample captures

Everything in `samples/captures/` is **synthetic**. The frames are assembled
byte-by-byte by `samples/make_samples.py` (using the builders in
`tests/fixtures.py`), with fixed timestamps, fixed TLS randoms and fixed DNS
transaction ids, so regeneration is byte-identical:

```bash
python samples/make_samples.py          # (re)write the files
python samples/make_samples.py --check  # verify they match the generator
```

No real traffic was captured. Addresses are from the IANA documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`); MACs are locally
administered. The hostnames are well-known service names used to exercise the
classifier — the samples do not contact those services. The files may be
redistributed freely.

Expected results live in `samples/expected.json`; they are stated **by
construction** from the packet lists below, not recorded from the engine.
`tests/test_samples.py` checks both engines against them and checks that the
rejected files are rejected with the documented message and exit status.

## Accepted captures

### `mixed_supported.pcap` — 44 packets, 26 flows

| Content | Packets | Notes |
|---|---|---|
| 8 TLS connections (`www.google.com`, `www.youtube.com`, `www.facebook.com`, `twitter.com`, `www.netflix.com`, `github.com`, `www.tiktok.com`, `www.example.org`) | 8 × 4 = 32 | SYN, SYN-ACK (server→client), ACK, Client Hello with SNI |
| 2 HTTP connections (`example.com`, `httpbin.org`) | 2 × 2 = 4 | SYN, `GET / HTTP/1.1` with `Host:` |
| 3 DNS queries (`www.google.com`, `www.youtube.com`, `api.twitter.com`) | 3 | UDP to `192.0.2.53:53` |
| 5 bare SYNs from `192.0.2.66` to `198.51.100.99:443` | 5 | one flow each |

Flows by heuristic class with no rules: the 8 client→server TLS flows are
classified from their SNI (Google, YouTube, Facebook, Twitter/X, Netflix,
GitHub, TikTok, and `www.example.org` → `HTTPS` because no pattern matched);
the 8 server→client SYN-ACK flows are `Unknown`; the 2 HTTP flows are `HTTPS`
(see *quirk* below); the 3 DNS flows are `DNS`; the 5 bare SYNs are `HTTPS` by
port fallback.

| Run | Rules | Rule-filtered | Retained | Why |
|---|---|---|---|---|
| `none` | — | 0 | 44 | |
| `block_streaming` | `samples/rules/block_streaming.rules` (apps YouTube, Netflix, TikTok) | 3 | 41 | only the Client Hello packet of each flow is dropped: the flow is classified on that packet, and the SYN/ACK before it were already forwarded; the server→client direction is a separate flow and is never blocked |
| `block_client_and_dns` | `samples/rules/block_client_and_dns.rules` (IP 192.0.2.66, port 53) | 8 | 36 | 5 SYNs from the blocked source + 3 DNS queries to port 53 |
| `block_domain_google` | `--block-domain google` | 2 | 42 | the `www.google.com` Client Hello and the `www.google.com` DNS query |

### `mixed_unsupported.pcap` — 48 packets

`mixed_supported.pcap` with four packets inserted: an ARP frame, an IPv6
frame, an ICMP echo (all *unsupported* — not IPv4 TCP/UDP) and an IPv4 header
cut off after 12 bytes (*malformed*). Expected: `unsupported = 3`,
`malformed = 1`, and the same filtered counts as above. The output capture
contains exactly the 44 supported packets minus any filtered ones, in input
order — the 4 others are **not** written.

### `hostile_names.pcap` — 15 packets, 8 flows

Names that contain HTML/JS metacharacters, plus name-length boundary cases:

| Flow | Name | Result |
|---|---|---|
| TLS Client Hello (4 pkts) | `<script>alert(1)</script>.evil.test` | extracted, class `HTTPS` (no pattern) |
| HTTP `Host:` (2 pkts) | `evil.test"><script>alert(2)</script>` | extracted, class `HTTPS` (quirk below) |
| DNS query (1 pkt) | `<img src=x>.evil.test` | extracted, class `DNS` |
| TLS Client Hello (4 pkts) | 245 × `a` + `.long.test` (255 chars, the RFC 6066 maximum) | extracted, not clipped |
| TLS Client Hello (4 pkts) | 290 × `b` + `.long.test` (300 chars) | **rejected** by the extractor; flow stays `HTTPS` by port with no observed name |

The 4 server→client SYN-ACK flows are `Unknown`, giving 8 flows: `Unknown` 3,
`HTTPS` 4, `DNS` 1.

With `samples/rules/block_evil_domain.rules` (`evil.test`), exactly 3 packets
are filtered (the Client Hello, the GET, and the DNS query). HTML reports must
show these names escaped; `tests/test_report.py` asserts no raw `<script`,
`onerror` or `<img` survives.

### `empty.pcap`

A valid 24-byte global header and no packets. Accepted; produces an empty
output capture and a report with zero flows.

## Rejected inputs (exit status 1, no output file)

| File | Why | Message contains |
|---|---|---|
| `truncated_body.pcap` | last packet body 10 bytes short | `truncated capture` |
| `truncated_header.pcap` | 7 stray bytes after the last packet | `truncated capture` |
| `oversized_record.pcap` | record header claims 70 000 captured bytes | `exceeds 65535` |
| `nanosecond_magic.pcap` | nanosecond-resolution pcap (`0xA1B23C4D`) | `nanosecond` |
| `pcapng_stub.pcapng` | pcapng section header | `pcapng` |
| `linktype_raw.pcap` | link type 101 (raw IP) | `Unsupported link type 101` |
| `short_header.pcap` | 10-byte file | `Not a PCAP file` |

A truncated capture is rejected rather than processed up to the cut, so an
incomplete input can never produce an output that looks complete.

## Known classifier quirk (documented, not changed)

An HTTP `Host:` that matches no pattern is labelled `HTTPS`, because
`sni_to_app_type()` returns `HTTPS` for "a name was seen but not recognised"
regardless of whether it came from TLS or HTTP. The report's `observed.http_host`
field shows where the name actually came from. Changing the label would alter
existing rule semantics (`--block-app HTTPS`), so it is left as is.

## Sample reports

`samples/reports/` contains reports produced by `demo.py` from these captures
(`--report-no-timestamp`, so they are reproducible). Open the `.html` files in a
browser; they are static and contain no scripts.
