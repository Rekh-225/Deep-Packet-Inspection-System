"""
Run reports: bounded JSON and static HTML.

A report lists, per flow: endpoints, observed DNS / HTTP / TLS names,
heuristic classification (with "Unknown" kept distinct from a positive
match), the rule that matched (if any), the final action, and the summary
accounting for the whole run.

Bounds
------
* At most ``max_flows`` flows are listed (in first-seen order); the report
  records how many exist and whether the list was truncated.
* Every captured string is clipped to ``MAX_NAME_LEN`` characters and has
  control characters replaced before it is emitted.
* The HTML is static (no scripts), and every captured value is passed through
  ``html.escape`` in both text and attribute context.

Wording
-------
Classification is a heuristic match of observed names / ports against a static
pattern table.  It says which service a flow *appears* to contact.  It is not
evidence that traffic is malicious, and "Unknown" only means no heuristic
matched.  The report text repeats this so it cannot be misread.
"""

from __future__ import annotations

import heapq
import html
import json
import os
import tempfile
from typing import Any, Dict, Iterable, List, Optional

from dpi import __version__
from dpi.types import AppType, Connection, ConnectionState, DPIStats, ip_to_str

SCHEMA = "dpi-engine-report/1"
MAX_NAME_LEN = 255
DEFAULT_MAX_FLOWS = 1000

DISCLAIMER = (
    "Classification is a heuristic match of observed TLS SNI / HTTP Host / DNS query names and "
    "ports against a static pattern table. It indicates which service a flow appears to contact. "
    "It is not evidence that traffic is malicious. 'Unknown' means no heuristic matched, nothing more."
)
EXCLUSION_NOTE = (
    "Unsupported (non-IPv4 TCP/UDP) and malformed packets were not inspected and are not in the "
    "output capture; they are counted here so the accounting reconciles."
)

_PROTO_NAMES = {6: "TCP", 17: "UDP"}


# =============================================================================
# String hygiene
# =============================================================================

def clean_text(value: Optional[str], limit: int = MAX_NAME_LEN) -> Optional[str]:
    """Clip to *limit* characters and replace control characters with U+FFFD."""
    if not value:
        return None
    out = "".join(ch if ch.isprintable() else "\ufffd" for ch in value)
    if len(out) > limit:
        out = out[:limit] + "\u2026"
    return out


def _esc(value: Any) -> str:
    """HTML-escape any value for text or attribute context."""
    return html.escape("" if value is None else str(value), quote=True)


# =============================================================================
# Report model
# =============================================================================

def flow_record(conn: Connection) -> Dict[str, Any]:
    t = conn.tuple
    blocked = conn.state == ConnectionState.BLOCKED
    known = conn.app_type is not AppType.UNKNOWN
    return {
        "first_packet_id": conn.first_packet_id,
        "last_packet_id": conn.last_packet_id,
        "src": {"ip": ip_to_str(t.src_ip), "port": t.src_port},
        "dst": {"ip": ip_to_str(t.dst_ip), "port": t.dst_port},
        "protocol": _PROTO_NAMES.get(t.protocol, str(t.protocol)),
        "packets": conn.packets_in + conn.packets_out,
        "bytes": conn.bytes_in + conn.bytes_out,
        "observed": {
            "tls_sni": clean_text(conn.tls_sni),
            "http_host": clean_text(conn.http_host),
            "dns_query": clean_text(conn.dns_query),
        },
        "classification": {
            "app": conn.app_type.value,
            "known": known,
            "method": conn.classified_by if known else "none",
            "heuristic": True,
        },
        "rule": (
            {"type": conn.block_rule_type, "detail": clean_text(conn.block_rule_detail)}
            if blocked else None
        ),
        "action": "drop" if blocked else "forward",
    }


def _accounting(stats: DPIStats) -> Dict[str, Any]:
    return {
        "total_packets": stats.total_packets,
        "total_bytes": stats.total_bytes,
        "tcp_packets": stats.tcp_packets,
        "udp_packets": stats.udp_packets,
        "retained": stats.forwarded_packets,
        "rule_filtered": stats.dropped_packets,
        "unsupported": stats.unsupported_packets,
        "malformed": stats.malformed_packets,
        "failed": stats.failed_packets,
        "reconciles": stats.reconciles(),
    }


def build_report(
    engine: Any,
    input_path: str,
    output_path: str,
    max_flows: int = DEFAULT_MAX_FLOWS,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build the report dictionary from a finished engine (simple or mt).

    The engine must expose ``mode``, ``stats``, ``rule_manager``,
    ``connections()`` and ``app_stats``.
    """
    if max_flows < 0:
        raise ValueError("max_flows must be >= 0")

    # Aggregates are computed in one streaming pass; only the first ``max_flows``
    # flows (by first packet id) are materialised, via a bounded heap.
    per_flow_apps: Dict[str, int] = {}
    per_flow_action = {"forward": 0, "drop": 0}
    total_flows = 0
    for c in engine.connections():
        total_flows += 1
        per_flow_apps[c.app_type.value] = per_flow_apps.get(c.app_type.value, 0) + 1
        per_flow_action["drop" if c.state == ConnectionState.BLOCKED else "forward"] += 1
    listed = heapq.nsmallest(max_flows, engine.connections(), key=lambda c: c.first_packet_id)
    flows = [flow_record(c) for c in listed]

    detections = getattr(engine, "detections", None)
    detail = {
        "limit": getattr(engine, "max_report_detail", None),
        "detections_total": detections.total if detections else None,
        "detections_listed": len(detections.items) if detections else None,
        "detections_truncated": detections.truncated if detections else False,
    }

    run: Dict[str, Any] = {"mode": engine.mode, "input": input_path, "output": output_path}
    if engine.mode == "mt":
        run["threads"] = {"load_balancers": engine.num_lbs, "fast_paths_per_lb": engine.fps_per_lb}

    return {
        "schema": SCHEMA,
        "tool": {"name": "dpi-engine", "version": __version__},
        "generated_at": generated_at,
        "run": run,
        "rules": engine.rule_manager.describe(),
        "accounting": _accounting(engine.stats),
        "packets_by_app": {app.value: n for app, n in sorted(
            engine.app_stats.items(), key=lambda kv: (-kv[1], kv[0].value))},
        "flows_by_app": dict(sorted(per_flow_apps.items(), key=lambda kv: (-kv[1], kv[0]))),
        "flows_by_action": per_flow_action,
        "flows": {
            "total": total_flows,
            "listed": len(flows),
            "truncated": len(flows) < total_flows,
            "max_flows": max_flows,
            "items": flows,
        },
        "detail": detail,
        "notes": [DISCLAIMER, EXCLUSION_NOTE],
    }


# =============================================================================
# Writers
# =============================================================================

def to_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=True, sort_keys=False) + "\n"


def _write_text_atomically(text: str, path: str) -> None:
    """
    Write to a uniquely named temp file in the destination directory and move
    it into place, so a failure never leaves a partial report at ``path``.
    Raises ``OSError``; a temp that cannot be removed is named in the error.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", suffix=".partial", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except OSError as e:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError as cleanup:
            raise OSError(f"{e}; temporary file left at {tmp} ({cleanup})") from e
        raise


def write_json(report: Dict[str, Any], path: str) -> None:
    _write_text_atomically(to_json(report), path)


_CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:1.5rem;color:#222;background:#fff}
h1,h2{margin:.6em 0 .3em}
.note{background:#fff8e1;border-left:4px solid #f0b429;padding:.6em .9em;margin:.8em 0}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{border:1px solid #ccd;padding:.3em .5em;text-align:left;vertical-align:top;word-break:break-all}
th{background:#eef}
tr.drop td{background:#fdecea}
.unknown{color:#666;font-style:italic}
.kv td:first-child{font-weight:600;width:16em}
code{font-family:ui-monospace,Consolas,monospace}
"""


def to_html(report: Dict[str, Any]) -> str:
    acc = report["accounting"]
    run = report["run"]
    flows = report["flows"]
    rules = report["rules"]

    def kv_rows(pairs: Iterable) -> str:
        return "".join(f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>" for k, v in pairs)

    def rules_rows() -> str:
        rows = []
        for kind in ("ips", "apps", "domains", "ports"):
            values = rules.get(kind) or []
            rows.append(f"<tr><td>{_esc(kind)}</td><td>{_esc(', '.join(str(v) for v in values)) or '&mdash;'}</td></tr>")
        return "".join(rows)

    def flow_rows() -> str:
        out = []
        for fl in flows["items"]:
            obs = fl["observed"]
            cls = fl["classification"]
            rule = fl["rule"]
            app_html = (f"{_esc(cls['app'])} <small>({_esc(cls['method'])})</small>" if cls["known"]
                        else '<span class="unknown">Unknown (no heuristic matched)</span>')
            rule_html = f"{_esc(rule['type'])}: {_esc(rule['detail'])}" if rule else "&mdash;"
            out.append(
                f'<tr class="{_esc(fl["action"])}">'
                f"<td>{_esc(fl['first_packet_id'])}</td>"
                f"<td><code>{_esc(fl['src']['ip'])}:{_esc(fl['src']['port'])}</code></td>"
                f"<td><code>{_esc(fl['dst']['ip'])}:{_esc(fl['dst']['port'])}</code></td>"
                f"<td>{_esc(fl['protocol'])}</td>"
                f"<td>{_esc(fl['packets'])}</td>"
                f"<td>{_esc(obs['dns_query']) or '&mdash;'}</td>"
                f"<td>{_esc(obs['http_host']) or '&mdash;'}</td>"
                f"<td>{_esc(obs['tls_sni']) or '&mdash;'}</td>"
                f"<td>{app_html}</td>"
                f"<td>{rule_html}</td>"
                f"<td>{_esc(fl['action'])}</td>"
                "</tr>"
            )
        return "".join(out)

    truncated_note = (
        f'<p class="note">Flow list truncated: showing {_esc(flows["listed"])} of {_esc(flows["total"])} flows '
        f'(max_flows={_esc(flows["max_flows"])}).</p>' if flows["truncated"] else ""
    )
    threads = run.get("threads")
    run_pairs = [("Mode", run["mode"]), ("Input", run["input"]), ("Output", run["output"])]
    if threads:
        run_pairs.append(("Threads", f"{threads['load_balancers']} LB x {threads['fast_paths_per_lb']} FP"))
    run_pairs += [("Tool", f"{report['tool']['name']} {report['tool']['version']}"),
                  ("Generated", report["generated_at"] or "(not recorded)")]

    acc_pairs = [
        ("Total packets read", acc["total_packets"]), ("Total bytes", acc["total_bytes"]),
        ("Retained (written)", acc["retained"]), ("Rule-filtered", acc["rule_filtered"]),
        ("Unsupported (not inspected, not written)", acc["unsupported"]),
        ("Malformed (not written)", acc["malformed"]), ("Failed / undecided", acc["failed"]),
        ("Reconciles", "yes" if acc["reconciles"] else "NO"),
    ]

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>DPI Engine report &mdash; {_esc(run['input'])}</title>
<style>{_CSS}</style></head>
<body>
<h1>DPI Engine report</h1>
<p class="note">{_esc(report['notes'][0])}</p>
<h2>Run</h2>
<table class="kv">{kv_rows(run_pairs)}</table>
<h2>Rules in effect</h2>
<table class="kv">{rules_rows()}</table>
<h2>Accounting</h2>
<table class="kv">{kv_rows(acc_pairs)}</table>
<p class="note">{_esc(report['notes'][1])}</p>
<h2>Packets by heuristic class</h2>
<table class="kv">{kv_rows(report['packets_by_app'].items()) or '<tr><td colspan="2">none</td></tr>'}</table>
<h2>Flows ({_esc(flows['listed'])} listed, {_esc(flows['total'])} total; {_esc(report['flows_by_action']['drop'])} dropped)</h2>
{truncated_note}
<table>
<thead><tr><th>#</th><th>Source</th><th>Destination</th><th>Proto</th><th>Pkts</th>
<th>DNS query</th><th>HTTP Host</th><th>TLS SNI</th><th>Heuristic class</th><th>Matching rule</th><th>Action</th></tr></thead>
<tbody>{flow_rows()}</tbody>
</table>
</body></html>
"""


def write_html(report: Dict[str, Any], path: str) -> None:
    _write_text_atomically(to_html(report), path)
