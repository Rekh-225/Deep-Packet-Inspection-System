# Benchmark

```bash
python benchmarks/bench.py                                   # default input, 3 reps
python benchmarks/bench.py --sites 6000 --reps 5 --json benchmarks/last_run.json
python benchmarks/bench.py --input path/to/your.pcap         # throughput only
```

`bench.py` generates a deterministic synthetic capture, times each engine
configuration end to end (read → parse → classify → rules → write filtered
pcap), verifies that every configuration produces byte-identical output and
identical statistics to the simple engine, and then — separately — checks the
engine's per-flow heuristic class against the generator's ground truth.

The script prints the machine, Python and input details alongside the numbers.
Quote them together; numbers from one machine do not transfer to another.

## Measured run (this repository's last local run)

Recorded in `benchmarks/last_run.json`.

| | |
|---|---|
| Machine | Windows 11 (10.0.26200), AMD64 Family 25 Model 68 (Zen 3 class), 12 logical CPUs |
| Python | CPython 3.13.14, GIL enabled |
| Input | generated: 3000 sites × (1 TLS flow with Client Hello + 10 bulk ACKs, 1 HTTP flow, 1 DNS query) = **51 000 packets, 4.13 MB**, 12 000 client flows + 3000 server→client flows |
| Rules | `--block-app YouTube` (4125 packets filtered: 375 YouTube flows × 11 packets) |
| Reps | 3, best / median |

### Throughput

| Configuration | best | median | packets/s | MB/s | identical output+stats |
|---|---|---|---|---|---|
| simple | 1.097 s | 1.126 s | 46 469 | 3.77 | (reference) |
| mt 1×1 | 1.797 s | 1.821 s | 28 383 | 2.30 | yes |
| mt 1×2 | 1.784 s | 1.848 s | 28 586 | 2.32 | yes |
| mt 2×2 | 1.820 s | 1.829 s | 28 027 | 2.27 | yes |
| mt 2×4 | 1.861 s | 1.901 s | 27 406 | 2.22 | yes |

Measured after the review repairs (strict IPv4/TCP/UDP boundary validation,
length-bounded payload slicing, global flow-capacity accounting, strict TLS/DNS
parsing). Compared with the pre-repair run on the same machine the simple
engine is about 25 % slower (was ≈ 60 k pkt/s) and the mt engine somewhat
faster (was ≈ 22–24 k pkt/s); the correctness work was not tuned for speed.

On this input and machine the multi-threaded engine is **~1.6× slower** than
the single-threaded one and does not improve with more threads. The work is
pure Python under the GIL, and every packet crosses three bounded queues plus
the ordering buffer; the mt mode exists to demonstrate a correct pipelined
design, not to be faster. No claim is made about other inputs or machines.

### Classification agreement (not throughput, not real-world accuracy)

12 000 / 12 000 labelled flows (100 %) received the class the generator
expected: 3000 via `tls_sni`, 3000 via `http_host`, 3000 via `dns_port`, and
3000 server→client flows correctly left `Unknown`.

This is agreement with the pattern table on clean, single-segment synthetic
traffic whose hostnames were chosen from that same table. It shows the pipeline
labels flows consistently at scale; it says nothing about how often real
traffic is identified, and it must not be quoted as an accuracy figure.
