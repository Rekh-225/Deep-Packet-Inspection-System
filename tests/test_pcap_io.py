"""
Unit tests for dpi.pcap_io module.

Tests PCAP reading, writing, and round-trip integrity.
"""

import os
import struct
import tempfile
import unittest

from dpi.pcap_io import (
    PcapReader,
    PcapWriter,
    PcapGlobalHeader,
    PCAP_MAGIC_NATIVE,
    GLOBAL_HEADER_SIZE,
    PACKET_HEADER_SIZE,
)


class TestPcapReader(unittest.TestCase):
    """Test PCAP file reading."""

    PCAP_PATH = os.path.join(os.path.dirname(__file__), "..", "test_dpi.pcap")

    def test_open_valid_file(self):
        reader = PcapReader()
        self.assertTrue(reader.open(self.PCAP_PATH))
        self.assertTrue(reader.is_open)
        self.assertIsNotNone(reader.global_header)
        self.assertEqual(reader.global_header.magic_number, PCAP_MAGIC_NATIVE)
        self.assertEqual(reader.global_header.version_major, 2)
        self.assertEqual(reader.global_header.version_minor, 4)
        self.assertEqual(reader.global_header.network, 1)  # Ethernet
        reader.close()

    def test_open_nonexistent_file(self):
        reader = PcapReader()
        self.assertFalse(reader.open("does_not_exist.pcap"))
        self.assertFalse(reader.is_open)

    def test_read_all_packets(self):
        reader = PcapReader()
        reader.open(self.PCAP_PATH)
        count = 0
        for pkt in reader:
            count += 1
            self.assertIsNotNone(pkt.header)
            self.assertGreater(len(pkt.data), 0)
            self.assertEqual(len(pkt.data), pkt.header.incl_len)
        reader.close()
        self.assertGreater(count, 0)

    def test_context_manager(self):
        with PcapReader() as reader:
            reader.open(self.PCAP_PATH)
            packets = list(reader)
            self.assertGreater(len(packets), 0)
        self.assertFalse(reader.is_open)


class TestPcapWriter(unittest.TestCase):
    """Test PCAP file writing."""

    def test_write_and_read_back(self):
        """Write packets and verify they can be read back identically."""
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        tmp.close()

        try:
            # Write
            writer = PcapWriter()
            self.assertTrue(writer.open(tmp.name))
            writer.write_packet(1000, 500, b"\x00\x01\x02\x03\x04\x05")
            writer.write_packet(1001, 100, b"\xAA\xBB\xCC")
            writer.close()

            # Read back
            reader = PcapReader()
            reader.open(tmp.name)
            packets = list(reader)
            reader.close()

            self.assertEqual(len(packets), 2)

            self.assertEqual(packets[0].header.ts_sec, 1000)
            self.assertEqual(packets[0].header.ts_usec, 500)
            self.assertEqual(packets[0].data, b"\x00\x01\x02\x03\x04\x05")

            self.assertEqual(packets[1].header.ts_sec, 1001)
            self.assertEqual(packets[1].data, b"\xAA\xBB\xCC")
        finally:
            os.unlink(tmp.name)

    def test_round_trip(self):
        """Read a real PCAP, write it out, and verify identical packets."""
        src = os.path.join(os.path.dirname(__file__), "..", "test_dpi.pcap")
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        tmp.close()

        try:
            # Read original
            reader = PcapReader()
            reader.open(src)
            original_packets = list(reader)
            hdr = reader.global_header
            reader.close()

            # Write copy
            writer = PcapWriter()
            writer.open(tmp.name, global_header=hdr)
            for pkt in original_packets:
                writer.write_packet(pkt.header.ts_sec, pkt.header.ts_usec, pkt.data)
            writer.close()

            # Read copy
            reader2 = PcapReader()
            reader2.open(tmp.name)
            copied_packets = list(reader2)
            reader2.close()

            # Verify
            self.assertEqual(len(original_packets), len(copied_packets))
            for orig, copy in zip(original_packets, copied_packets):
                self.assertEqual(orig.header.ts_sec, copy.header.ts_sec)
                self.assertEqual(orig.header.ts_usec, copy.header.ts_usec)
                self.assertEqual(orig.data, copy.data)
        finally:
            os.unlink(tmp.name)


class TestPcapWriterAtomic(unittest.TestCase):
    """
    Atomic mode (review finding 6): a uniquely named, exclusively created temp
    file in the destination directory; nothing appears at the destination until
    commit(); pre-existing files are never touched; all failures are
    PcapWriteError and name any file left behind.
    """

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "out.pcap")
        self.legacy_partial = self.path + PcapWriter.PARTIAL_SUFFIX

    def tearDown(self):
        self.dir.cleanup()

    def _temp_files(self):
        return sorted(f for f in os.listdir(self.dir.name) if f.endswith(PcapWriter.PARTIAL_SUFFIX))

    def test_commit_moves_temp_into_place(self):
        w = PcapWriter()
        self.assertTrue(w.open(self.path, atomic=True))
        temp = w.temp_path
        self.assertNotEqual(temp, self.path)
        self.assertEqual(os.path.dirname(temp), os.path.dirname(os.path.abspath(self.path)))
        self.assertTrue(os.path.basename(temp).startswith(".out.pcap."))
        w.write_packet(1, 2, b"\x01\x02", 6)
        self.assertTrue(os.path.exists(temp))
        self.assertFalse(os.path.exists(self.path))
        w.commit()
        self.assertFalse(os.path.exists(temp))
        self.assertEqual(self._temp_files(), [])
        r = PcapReader()
        self.assertTrue(r.open(self.path))
        pkts = list(r)
        r.close()
        self.assertEqual([(p.data, p.header.orig_len) for p in pkts], [(b"\x01\x02", 6)])

    def test_two_writers_get_distinct_temps(self):
        a, b = PcapWriter(), PcapWriter()
        self.assertTrue(a.open(self.path, atomic=True))
        self.assertTrue(b.open(self.path, atomic=True))
        self.assertNotEqual(a.temp_path, b.temp_path)
        a.discard(); b.discard()
        self.assertEqual(self._temp_files(), [])

    def test_discard_removes_temp_and_reports_none(self):
        w = PcapWriter()
        self.assertTrue(w.open(self.path, atomic=True))
        w.write_packet(1, 2, b"\x01\x02")
        self.assertIsNone(w.discard())
        self.assertEqual(self._temp_files(), [])
        self.assertFalse(os.path.exists(self.path))

    def test_preexisting_partial_named_file_is_never_touched(self):
        """A user file that happens to be called <out>.partial must survive open, write, discard and commit."""
        with open(self.legacy_partial, "wb") as f:
            f.write(b"user data")
        w = PcapWriter()
        self.assertTrue(w.open(self.path, atomic=True))
        self.assertNotEqual(w.temp_path, self.legacy_partial)
        w.write_packet(1, 2, b"\x01")
        w.discard()
        with open(self.legacy_partial, "rb") as f:
            self.assertEqual(f.read(), b"user data")
        w2 = PcapWriter()
        w2.open(self.path, atomic=True)
        w2.commit()
        with open(self.legacy_partial, "rb") as f:
            self.assertEqual(f.read(), b"user data")

    def test_preexisting_destination_survives_failure_and_is_replaced_only_on_commit(self):
        with open(self.path, "wb") as f:
            f.write(b"stale")
        w = PcapWriter()
        w.open(self.path, atomic=True)
        w.write_packet(1, 2, b"\x01")
        w.discard()
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), b"stale")
        w = PcapWriter()
        w.open(self.path, atomic=True)
        w.commit()
        self.assertEqual(os.path.getsize(self.path), GLOBAL_HEADER_SIZE)

    def test_replace_failure_is_pcap_write_error_and_temp_removed(self):
        from unittest import mock
        from dpi.pcap_io import PcapWriteError
        w = PcapWriter()
        w.open(self.path, atomic=True)
        temp = w.temp_path
        with mock.patch("dpi.pcap_io.os.replace", side_effect=OSError("replace denied (injected)")):
            with self.assertRaises(PcapWriteError) as cm:
                w.commit()
        self.assertIn("replace denied", str(cm.exception))
        self.assertIn("temporary file removed", str(cm.exception))
        self.assertFalse(os.path.exists(temp))
        self.assertFalse(os.path.exists(self.path))

    def test_replace_failure_with_cleanup_failure_names_leftover(self):
        from unittest import mock
        from dpi.pcap_io import PcapWriteError
        w = PcapWriter()
        w.open(self.path, atomic=True)
        temp = w.temp_path
        with mock.patch("dpi.pcap_io.os.replace", side_effect=OSError("replace denied (injected)")), \
             mock.patch("dpi.pcap_io.os.unlink", side_effect=OSError("unlink denied (injected)")):
            with self.assertRaises(PcapWriteError) as cm:
                w.commit()
        msg = str(cm.exception)
        self.assertIn("replace denied", msg)              # original error preserved
        self.assertIn(f"temporary file left at {temp}", msg)
        self.assertIn("unlink denied", msg)
        self.assertIsInstance(cm.exception.__cause__, OSError)
        os.unlink(temp)

    def test_close_failure_is_pcap_write_error(self):
        from unittest import mock
        from dpi.pcap_io import PcapWriteError
        w = PcapWriter()
        w.open(self.path, atomic=True)
        with mock.patch.object(w._file, "flush", side_effect=OSError("flush failed (injected)")):
            with self.assertRaises(PcapWriteError) as cm:
                w.commit()
        self.assertIn("flush failed", str(cm.exception))
        self.assertEqual(self._temp_files(), [])
        self.assertFalse(os.path.exists(self.path))

    def test_non_atomic_commit_is_plain_close(self):
        w = PcapWriter()
        w.open(self.path)
        w.commit()
        self.assertTrue(os.path.exists(self.path))
        self.assertEqual(self._temp_files(), [])

    def test_unwritable_directory_reports_error(self):
        w = PcapWriter()
        self.assertFalse(w.open(os.path.join(self.dir.name, "no", "dir", "x.pcap"), atomic=True))
        self.assertIn("Cannot open output file", w.last_error)


if __name__ == "__main__":
    unittest.main()
