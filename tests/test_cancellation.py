"""
Review findings 3 and 7.

Finding 3: KeyboardInterrupt at any lifecycle point (startup, reading, sentinel
signalling, joining while a worker is gated, finalisation) must cancel, unblock
and join every stage, close resources, discard the temporary output, and raise
ProcessingCancelled (CLI status 130).  Repeated interrupts and cleanup errors
must not leak threads or mask the outcome.

Finding 7: aborted-run accounting distinguishes admitted / decided / retired /
undecided instead of calling every unretired packet "undecided".

Interrupts are injected deterministically by patching the specific call the
main thread is executing at that phase.  Gated workers wait on an Event OR the
engine's ``stopping`` flag, so cancellation always releases them.
"""

import contextlib
import io
import os
import tempfile
import threading
import unittest
from unittest import mock

from dpi import engine_mt
from dpi.cli import EXIT_CANCELLED, main as cli_main
from dpi.engine import DPIEngine
from dpi.engine_mt import DPIEngineMT
from dpi.packet_parser import PacketParser
from dpi.pcap_io import PcapWriter
from dpi.types import ProcessingCancelled, ProcessingError

from tests import fixtures as fx

WAIT = 20.0


def _pipeline_threads():
    return [t.name for t in threading.enumerate() if t.name.startswith(("FP-", "LB-", "Writer"))]


class CancelBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.in_path = os.path.join(self.dir.name, "in.pcap")
        self.out = os.path.join(self.dir.name, "out.pcap")
        fx.write_pcap(self.in_path, fx.many_flows_fixture(8, 4).packets)   # 32 packets
        self.assertEqual(_pipeline_threads(), [])

    def tearDown(self):
        self.dir.cleanup()

    def gate_hook(self, eng_ref, packet_id=0):
        """Hook that blocks the FP owning ``packet_id`` until released or the engine is stopping."""
        gate = threading.Event()
        reached = threading.Event()

        def hook(fp_id, job):
            if job.packet_id == packet_id:
                reached.set()
                while not gate.is_set() and not eng_ref[0].stopping.is_set():
                    gate.wait(0.02)
        return hook, gate, reached

    def run_quiet(self, eng):
        with contextlib.redirect_stdout(io.StringIO()):
            eng.process_file(self.in_path, self.out)

    def assert_clean(self, eng):
        self.assertEqual(_pipeline_threads(), [], "worker or writer still alive after cancellation")
        self.assertFalse(os.path.exists(self.out))
        self.assertEqual([f for f in os.listdir(self.dir.name) if f.endswith(".partial")], [])
        self.assertTrue(eng.stopping.is_set())


class TestInterruptPhases(CancelBase):
    def test_interrupt_during_join_with_gated_worker(self):
        """The review's case: Ctrl-C while the main thread waits for a slow FP."""
        ref = [None]
        hook, gate, reached = self.gate_hook(ref)
        eng = DPIEngineMT(1, 2, inspect_hook=hook, queue_size=64)
        ref[0] = eng
        original_join = engine_mt._Stage.join
        fired = []

        def join_once_interrupted(stage, timeout):
            if not fired and reached.is_set():
                fired.append(stage.name)
                raise KeyboardInterrupt
            return original_join(stage, timeout)

        with mock.patch.object(engine_mt._Stage, "join", join_once_interrupted):
            with self.assertRaises(ProcessingCancelled) as cm:
                self.run_quiet(eng)
        self.assertEqual(len(fired), 1)
        self.assertTrue(eng.reader_finished.is_set(), "interrupt must have happened after reading")
        self.assertIn("interrupted", str(cm.exception))
        self.assert_clean(eng)
        a = eng.abort_summary
        self.assertEqual(a["admitted"], 32)
        self.assertTrue(a["input_fully_read"])
        self.assertTrue(a["cancelled"])
        self.assertEqual(eng.stats.failed_packets, 32 - a["retired"])
        self.assertTrue(eng.stats.reconciles())

    def test_interrupt_during_reading(self):
        eng = DPIEngineMT(2, 2, queue_size=4)
        calls = {"n": 0}
        original = engine_mt._Control.acquire

        def acquire_interrupted(ctrl, sem):
            calls["n"] += 1
            if calls["n"] == 5:
                raise KeyboardInterrupt
            return original(ctrl, sem)

        with mock.patch.object(engine_mt._Control, "acquire", acquire_interrupted):
            with self.assertRaises(ProcessingCancelled) as cm:
                self.run_quiet(eng)
        self.assertFalse(eng.reader_finished.is_set())
        self.assertIn("input not fully read; unread count unknown", str(cm.exception))
        self.assert_clean(eng)
        self.assertEqual(eng.abort_summary["admitted"], 4)

    def test_interrupt_during_sentinel_signalling(self):
        eng = DPIEngineMT(2, 1, queue_size=64)
        original = engine_mt._Control.put

        def put_interrupted(ctrl, q, item):
            if item is engine_mt._END:
                raise KeyboardInterrupt
            return original(ctrl, q, item)

        with mock.patch.object(engine_mt._Control, "put", put_interrupted):
            with self.assertRaises(ProcessingCancelled):
                self.run_quiet(eng)
        self.assertTrue(eng.reader_finished.is_set())
        self.assert_clean(eng)

    def test_interrupt_during_startup(self):
        eng = DPIEngineMT(1, 1)
        with mock.patch.object(PcapWriter, "open", side_effect=KeyboardInterrupt):
            with self.assertRaises(ProcessingCancelled):
                self.run_quiet(eng)
        self.assert_clean(eng)
        self.assertEqual(eng.abort_summary["admitted"], 0)

    def test_interrupt_during_finalisation_before_commit(self):
        eng = DPIEngineMT(1, 1)
        with mock.patch.object(PcapWriter, "commit", side_effect=KeyboardInterrupt):
            with self.assertRaises(ProcessingCancelled):
                self.run_quiet(eng)
        self.assert_clean(eng)
        self.assertEqual(eng.abort_summary["retired"], 32)
        self.assertEqual(eng.abort_summary["undecided"], 0)

    def test_interrupt_after_commit_keeps_completed_output(self):
        eng = DPIEngineMT(1, 1)
        with mock.patch.object(DPIEngineMT, "_print_report", side_effect=KeyboardInterrupt):
            self.run_quiet(eng)          # returns normally: output already committed
        self.assertTrue(os.path.exists(self.out))
        self.assertEqual(len(fx.read_pcap(self.out)), 32)
        self.assertEqual(_pipeline_threads(), [])

    def test_repeated_interrupts_during_shutdown(self):
        """A second Ctrl-C while the cancellation path is joining must still end cleanly."""
        ref = [None]
        hook, gate, reached = self.gate_hook(ref)
        eng = DPIEngineMT(1, 2, inspect_hook=hook, queue_size=64)
        ref[0] = eng
        original_join = engine_mt._Stage.join
        fired = []

        def join_interrupted_twice(stage, timeout):
            if len(fired) < 2 and reached.is_set():
                fired.append(stage.name)
                raise KeyboardInterrupt
            return original_join(stage, timeout)

        with mock.patch.object(engine_mt._Stage, "join", join_interrupted_twice):
            with self.assertRaises(ProcessingCancelled):
                self.run_quiet(eng)
        self.assertEqual(len(fired), 2)
        self.assert_clean(eng)

    def test_cleanup_error_is_reported_not_masked(self):
        ref = [None]
        hook, gate, reached = self.gate_hook(ref)
        eng = DPIEngineMT(1, 1, inspect_hook=hook, queue_size=64)
        ref[0] = eng
        original_join = engine_mt._Stage.join
        fired = []

        def join_once(stage, timeout):
            if not fired and reached.is_set():
                fired.append(1)
                raise KeyboardInterrupt
            return original_join(stage, timeout)

        # (a) the temp cannot be unlinked: discard() reports the leftover path, cancellation still wins
        with mock.patch.object(engine_mt._Stage, "join", join_once), \
             mock.patch("dpi.pcap_io.os.unlink", side_effect=OSError("unlink denied (injected)")):
            with self.assertRaises(ProcessingCancelled) as cm:
                self.run_quiet(eng)
        msg = str(cm.exception)
        self.assertIn("interrupted", msg)
        self.assertIn("temporary file left at", msg)
        self.assertIn("unlink denied", msg)
        self.assertEqual(_pipeline_threads(), [])
        leftovers = [f for f in os.listdir(self.dir.name) if f.endswith(".partial")]
        self.assertEqual(len(leftovers), 1, "the reported leftover must really exist")
        self.assertIn(leftovers[0], msg)
        os.unlink(os.path.join(self.dir.name, leftovers[0]))   # handle was closed, so this works

    def test_cleanup_exception_is_reported_not_masked(self):
        """(b) discard() itself blows up: still ProcessingCancelled, with the cleanup error attached."""
        ref = [None]
        hook, gate, reached = self.gate_hook(ref)
        eng = DPIEngineMT(1, 1, inspect_hook=hook, queue_size=64)
        ref[0] = eng
        original_join = engine_mt._Stage.join
        fired = []

        def join_once(stage, timeout):
            if not fired and reached.is_set():
                fired.append(1)
                raise KeyboardInterrupt
            return original_join(stage, timeout)

        with mock.patch.object(engine_mt._Stage, "join", join_once), \
             mock.patch.object(PcapWriter, "_remove_temp", side_effect=RuntimeError("cleanup exploded")):
            with self.assertRaises(ProcessingCancelled) as cm:
                self.run_quiet(eng)
        self.assertIn("cleanup failed: RuntimeError: cleanup exploded", str(cm.exception))
        self.assertEqual(_pipeline_threads(), [])
        for f in os.listdir(self.dir.name):        # close() ran inside discard(), so removal works
            if f.endswith(".partial"):
                os.unlink(os.path.join(self.dir.name, f))

    def test_simple_engine_interrupt_is_processing_cancelled(self):
        eng = DPIEngine()
        calls = {"n": 0}
        original = PacketParser.parse

        def parse_interrupted(data, ts_sec=0, ts_usec=0):
            calls["n"] += 1
            if calls["n"] == 10:
                raise KeyboardInterrupt
            return original(data, ts_sec=ts_sec, ts_usec=ts_usec)

        with mock.patch.object(PacketParser, "parse", staticmethod(parse_interrupted)):
            with self.assertRaises(ProcessingCancelled) as cm:
                self.run_quiet(eng)
        self.assertFalse(os.path.exists(self.out))
        self.assertEqual([f for f in os.listdir(self.dir.name) if f.endswith(".partial")], [])
        self.assertIn("admitted 10 packet(s)", str(cm.exception))
        self.assertEqual(eng.stats.failed_packets, 1)
        self.assertTrue(eng.stats.reconciles())

    def test_cli_returns_130_for_interrupt_in_either_mode(self):
        for mode in ("simple", "mt"):
            with self.subTest(mode=mode):
                calls = {"n": 0}
                original = PacketParser.parse

                def parse_interrupted(data, ts_sec=0, ts_usec=0):
                    calls["n"] += 1
                    if calls["n"] == 3:
                        raise KeyboardInterrupt
                    return original(data, ts_sec=ts_sec, ts_usec=ts_usec)

                err = io.StringIO()
                with mock.patch.object(PacketParser, "parse", staticmethod(parse_interrupted)), \
                     contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    rc = cli_main([self.in_path, self.out, "--mode", mode])
                self.assertEqual(rc, EXIT_CANCELLED)
                self.assertIn("Cancelled", err.getvalue())
                self.assertFalse(os.path.exists(self.out))
                self.assertEqual(_pipeline_threads(), [])


class TestAbortedRunAccounting(CancelBase):
    def test_gated_first_packet_then_worker_failure(self):
        """
        Review reproduction: hold packet 0, let other packets complete into the
        reorder buffer, then fail another FP.  Decided packets must not be
        reported as undecided.
        """
        # 8 single-packet flows: packet 0 on one FP, packets 1..7 all on the other FP (1 LB x 2 FPs).
        from dpi.engine_mt import route
        from dpi.inspection import make_tuple
        first = fx.tcp_packet(fx.CLIENT, "10.6.0.1", 40000, 443, fx.TCP_SYN)
        fp_a = route(make_tuple(PacketParser.parse(first)), 1, 2)
        others = []
        port = 41000
        while len(others) < 7:
            p = fx.tcp_packet(fx.CLIENT, "10.6.0.2", port, 443, fx.TCP_SYN)
            if route(make_tuple(PacketParser.parse(p)), 1, 2) != fp_a:
                others.append(p)
            port += 1
        fx.write_pcap(self.in_path, [first] + others)
        ref = [None]
        hook_gate, gate, reached = self.gate_hook(ref, packet_id=0)
        seen = []
        fail_at = threading.Event()

        def hook(fp_id, job):
            hook_gate(fp_id, job)
            if job.packet_id != 0:
                seen.append(job.packet_id)
                if len(seen) == 5:
                    fail_at.set()
                    raise RuntimeError("injected after five decisions")
                if len(seen) > 5:
                    fail_at.wait(WAIT)

        eng = DPIEngineMT(1, 2, inspect_hook=hook, queue_size=64)
        ref[0] = eng
        with self.assertRaises(ProcessingError) as cm:
            self.run_quiet(eng)
        self.assertEqual(_pipeline_threads(), [])
        a = eng.abort_summary
        msg = str(cm.exception)
        self.assertEqual(a["admitted"], 8)
        self.assertEqual(a["retired"], 0, "packet 0 never retired, so nothing could be retired in order")
        # Four decisions completed on the failing FP before its fifth packet raised; once the
        # pipeline was stopping the gated FP was released and decided packet 0 as well (its
        # completion was then refused by the cancelled output queue).  The failing packet and
        # the two packets still queued behind it were never decided.
        self.assertEqual(a["decided"], 5)
        self.assertEqual(a["decided_unretired"], 5)
        self.assertEqual(a["undecided"], 3)
        self.assertFalse(a["cancelled"])
        self.assertEqual(len(a["errors"]), 1)
        self.assertIn("injected after five decisions", a["errors"][0])
        self.assertNotIn("8 undecided", msg)
        self.assertIn(f"{a['decided']} decided", msg)
        self.assertIn(f"{a['undecided']} undecided", msg)
        self.assertIn("input fully read", msg)
        self.assertEqual(eng.stats.failed_packets, 8)
        self.assertTrue(eng.stats.reconciles())
        self.assertEqual(a["decided"], sum(fp.processed for fp in eng._fps))


if __name__ == "__main__":
    unittest.main()
