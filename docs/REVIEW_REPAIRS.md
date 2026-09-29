# Local review repairs — findings, root causes, contracts

Applies to branch `fix/mt-engine-lifecycle` (reviewed HEAD `1aa9558`). All ten
findings of the local review were reproduced with independent fixtures before
being fixed; each has a regression test.

| # | Finding | Root cause | Fix | Regression test |
|---|---|---|---|---|
| 1 | Flow eviction made rule enforcement depend on engine topology | `ConnectionTracker` silently evicted at 100 000 flows *per tracker*; simple had one tracker, MT one per fast path | `FlowCapacity`: one lock-protected global limit (`--max-flows`, default 200 000) shared by every tracker; eviction removed; exceeding it raises `FlowCapacityExceeded` and commits nothing | `tests/test_flow_capacity.py` (below / at / beyond in simple, 1×1, 2×2, 2×4; the 100,002-packet reproduction) |
| 2 | IPv4 / UDP / fragment boundaries unvalidated | parser never read IPv4 total length, flags/offset, or UDP length; payload ran to the frame end | validate version, IHL, total length vs header and captured bytes; confine transport to the IP datagram; validate TCP data offset / UDP length against the IP payload; fragments → unsupported with no transport parse; engines slice payload by `payload_length` | `tests/test_packet_boundaries.py` |
| 3 | Ctrl-C during join skipped cancellation and cleanup | the `KeyboardInterrupt` handler wrapped only the read loop; `_join_all` ran in `finally` unprotected; single long `join()` not interruptible on Windows | whole start/read/signal/join/finalise lifecycle under one interrupt handler; polling joins; `_emergency_shutdown` (cancel, re-join tolerating repeated interrupts, discard, collect cleanup problems); simple engine and CLI map interrupts to `ProcessingCancelled` / 130; interrupt after commit keeps the completed output | `tests/test_cancellation.py::TestInterruptPhases` |
| 4 | Malformed TLS/DNS produced positive names | TLS walker clamped to `len(payload)` instead of the declared record/handshake; DNS returned labels collected so far | TLS: record, handshake, extensions, extension, SNI list and name lengths all enforced, ASCII 1..255; DNS: complete labels, terminator, QTYPE+QCLASS required, compression rejected, ≤ 253 chars; HTTP Host ASCII ≤ 255 | `tests/test_app_metadata_bounds.py` |
| 5 | Output lost PCAP original length | `PacketJob` had no `orig_len`; writer wrote `len(data)` twice | `PacketJob.orig_len`; `PcapWriter.write_packet(..., orig_len)`; both engines pass the record's value | `tests/test_record_metadata.py` |
| 6 | Fixed `.partial` path; raw `OSError` on replace | `open(<out>.partial, "wb")` truncated any existing file; `os.replace` errors escaped | `tempfile.mkstemp` (exclusive, unique) in the destination directory; `commit()`/`discard()` normalise to `PcapWriteError`, best-effort close before unlink, name any leftover temp; engines report leftovers in their messages | `tests/test_pcap_io.py::TestPcapWriterAtomic` |
| 7 | Aborted runs called every unretired packet "undecided" | only `total − retired` was computed | counters: admitted (reader), decided (reader skips + per-FP `processed`, single-writer each), retired (writer); `abort_summary` and messages report decided-but-unretired vs undecided and whether input was fully read | `tests/test_cancellation.py::TestAbortedRunAccounting` |
| 8 | Detections / blocked history unbounded | per-FP lists grew per detection; report built `list(all flows)` | `DetectionLog` and per-FP `detail_limit` (`--max-report-detail`, default 10 000) with overflow counters; merge keeps the first N by packet id; console and JSON show truncation; `build_report` streams aggregates and uses `heapq.nsmallest` for the listed flows | `tests/test_bounds_and_report_failures.py::TestBoundedDetail` |
| 9 | Report failure contradicted the exit contract | reports written after commit but exit 1 documented as "no output left" | exit **3** = capture completed; report failed; stderr lists each output as written/FAILED; reports written via temp + `os.replace`; `build_report` exceptions are report failures, not processing failures | `tests/test_bounds_and_report_failures.py::TestReportFailureContract`, `tests/test_cli.py` |
| 10 | README said link type "not enforced"; no LICENSE; stale archive | docs lagged behind code | README corrected; `LICENSE` (MIT, Copyright (c) 2026 Rekh-225, confirmed by the owner); `pyproject.toml` points at the file; archive regenerated after all tests pass | `tools/make_release.py` run + checksum verification |

## Contracts

### Completed-run accounting

Every admitted packet ends in exactly one terminal category:
`total_packets = forwarded (retained) + dropped (rule-filtered) + unsupported + malformed`.
The MT engine verifies this and `retired == admitted` before committing.

### Aborted-run accounting (failure or cancellation)

| Term | Definition |
|---|---|
| admitted | packets read from the input and assigned an id in this run |
| decided | admitted packets whose outcome was determined — by the reader (unsupported/malformed) or by a fast path (retain/filter). A decision may still be waiting in the reorder buffer |
| retired | decided packets the writer processed in input order; only these are counted in the terminal categories |
| decided but not yet retired | decided − retired |
| undecided | admitted − decided (queued, or in progress when the run stopped) |
| input fully read | whether the reader reached end of input; otherwise the number of unread packets is **unknown** and is not reported |
| cancelled / failed | run-level status: `cancelled` if `cancel()` / Ctrl-C stopped it, `failed` if a stage raised |

`stats.failed_packets = admitted − retired` (every admitted packet not
represented in the output), so `reconciles()` still holds for aborted runs.
In the single-threaded engine decided == retired always, so at most one packet
(the one in progress) can be undecided.

### Flow-state capacity

One `FlowCapacity(max_flows)` per run, shared by all trackers. Creating a flow
beyond the limit raises `FlowCapacityExceeded` (a `ProcessingError`); the
temporary output is discarded; both engines raise the same class with the same
limit in the message. No eviction, so filtering semantics are identical under
pressure in every layout. Default 200 000; `--max-flows N`.

### Report failure

Exit 3 means: the capture at the output path is complete; at least one
requested report failed. stderr:

```
capture completed; report failed
  capture:      written  <output>
  JSON report:  written  <path>
  HTML report:  FAILED   <path>  (<reason>)
```

Reports are written to a temp file and moved into place, so a report path
never holds a partial report. Status 0 or 3 ⇒ capture complete; 1, 2, 130 ⇒
nothing at the output path.

### Separate limits

| Limit | Option | Default |
|---|---|---|
| packets admitted but not retired (queues + reorder buffer) | `--queue-size` | 10 000 |
| active flow state, whole run, both modes | `--max-flows` | 200 000 |
| detected names / blocked-flow entries kept for display | `--max-report-detail` | 10 000 |
| flows listed in reports | `--report-max-flows` | 1 000 |

`--queue-size` is not a total-process-memory bound.

### Malformed vs unsupported vs unparseable application data

Structural checks first: inconsistent headers ⇒ *malformed* (excluded). Well
formed but not IPv4 TCP/UDP, or an IPv4 fragment ⇒ *unsupported* (excluded).
Application payload that fails validation ⇒ **no name**; the packet's category
is unchanged (retained or filtered by IP/port/app rules), the flow keeps its
port heuristic.

## Not changed (documented)

- HTTP `Host:` values with no pattern match are labelled `HTTPS` (existing
  `sni_to_app_type` semantics; changing it would alter `--block-app HTTPS`).
- Flow state is directional; the server→client direction is never blocked.
- `output.pcap` in the working tree was modified before this work and is left
  untouched; it is excluded from the intended change list.
