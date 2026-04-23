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


if __name__ == "__main__":
    unittest.main()
