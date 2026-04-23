"""
PCAP file reader and writer.

Handles the binary PCAP file format used by Wireshark / tcpdump:
  - Global header (24 bytes): magic, version, snaplen, link type
  - Per-packet header (16 bytes): timestamp, captured length, original length
  - Per-packet data (variable): the raw network bytes
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, BinaryIO


# PCAP magic numbers
PCAP_MAGIC_NATIVE  = 0xA1B2C3D4   # Native byte order
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1   # Swapped byte order

# Struct format strings
GLOBAL_HEADER_FMT_LE = "<IHHiIII"   # Little-endian (28 bytes read, 24 used)
GLOBAL_HEADER_FMT_BE = ">IHHiIII"   # Big-endian
PACKET_HEADER_FMT_LE = "<IIII"      # 16 bytes
PACKET_HEADER_FMT_BE = ">IIII"

GLOBAL_HEADER_SIZE = 24
PACKET_HEADER_SIZE = 16


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class PcapGlobalHeader:
    """PCAP file global header (first 24 bytes)."""
    magic_number:  int
    version_major: int
    version_minor: int
    thiszone:      int
    sigfigs:       int
    snaplen:       int
    network:       int


@dataclass
class PcapPacketHeader:
    """Per-packet header (16 bytes before each packet's data)."""
    ts_sec:   int   # Timestamp seconds
    ts_usec:  int   # Timestamp microseconds
    incl_len: int   # Bytes saved in file
    orig_len: int   # Original packet length on wire


@dataclass
class RawPacket:
    """A single captured packet: header metadata + raw bytes."""
    header: PcapPacketHeader
    data:   bytes


# =============================================================================
# PCAP Reader
# =============================================================================

class PcapReader:
    """
    Reads packets from a PCAP file.

    Supports both native and swapped byte-order PCAP files.
    Can be used as a context manager::

        with PcapReader("capture.pcap") as reader:
            for packet in reader:
                process(packet)
    """

    def __init__(self) -> None:
        self._file: Optional[BinaryIO] = None
        self._global_header: Optional[PcapGlobalHeader] = None
        self._needs_swap: bool = False
        self._pkt_hdr_fmt: str = PACKET_HEADER_FMT_LE

    # --- Lifecycle ---

    def open(self, filename: str) -> bool:
        """Open a PCAP file and read the global header. Returns True on success."""
        self.close()
        try:
            self._file = open(filename, "rb")
        except OSError as e:
            print(f"Error: Could not open file: {filename} ({e})")
            return False

        raw = self._file.read(GLOBAL_HEADER_SIZE)
        if len(raw) < GLOBAL_HEADER_SIZE:
            print("Error: Could not read PCAP global header")
            self.close()
            return False

        # Peek at the magic number to determine byte order
        magic = struct.unpack_from("<I", raw, 0)[0]

        if magic == PCAP_MAGIC_NATIVE:
            self._needs_swap = False
            fmt = GLOBAL_HEADER_FMT_LE
            self._pkt_hdr_fmt = PACKET_HEADER_FMT_LE
        elif magic == PCAP_MAGIC_SWAPPED:
            self._needs_swap = True
            fmt = GLOBAL_HEADER_FMT_BE
            self._pkt_hdr_fmt = PACKET_HEADER_FMT_BE
        else:
            print(f"Error: Invalid PCAP magic number: 0x{magic:08X}")
            self.close()
            return False

        fields = struct.unpack(fmt, raw)
        self._global_header = PcapGlobalHeader(*fields)

        print(f"Opened PCAP file: {filename}")
        print(f"  Version: {self._global_header.version_major}."
              f"{self._global_header.version_minor}")
        print(f"  Snaplen: {self._global_header.snaplen} bytes")
        link = self._global_header.network
        print(f"  Link type: {link}{' (Ethernet)' if link == 1 else ''}")

        return True

    def close(self) -> None:
        """Close the file handle."""
        if self._file and not self._file.closed:
            self._file.close()
        self._file = None
        self._global_header = None
        self._needs_swap = False

    # --- Reading ---

    def read_next_packet(self) -> Optional[RawPacket]:
        """Read and return the next packet, or None at EOF / on error."""
        if self._file is None:
            return None

        raw_hdr = self._file.read(PACKET_HEADER_SIZE)
        if len(raw_hdr) < PACKET_HEADER_SIZE:
            return None  # EOF

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            self._pkt_hdr_fmt, raw_hdr
        )

        # Sanity check
        if incl_len > 65535:
            print(f"Error: Invalid packet length: {incl_len}")
            return None

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            print("Error: Could not read packet data")
            return None

        header = PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len)
        return RawPacket(header=header, data=data)

    # --- Properties ---

    @property
    def global_header(self) -> Optional[PcapGlobalHeader]:
        return self._global_header

    @property
    def is_open(self) -> bool:
        return self._file is not None and not self._file.closed

    # --- Iteration & Context Manager ---

    def __iter__(self):
        while True:
            pkt = self.read_next_packet()
            if pkt is None:
                return
            yield pkt

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# =============================================================================
# PCAP Writer
# =============================================================================

class PcapWriter:
    """
    Writes packets to a PCAP file.

    Usage::

        with PcapWriter("output.pcap") as writer:
            writer.write_packet(ts_sec, ts_usec, data)
    """

    def __init__(self) -> None:
        self._file: Optional[BinaryIO] = None

    def open(self, filename: str, global_header: Optional[PcapGlobalHeader] = None) -> bool:
        """Open a PCAP file for writing. Writes the global header."""
        self.close()
        try:
            self._file = open(filename, "wb")
        except OSError as e:
            print(f"Error: Cannot open output file: {filename} ({e})")
            return False

        if global_header:
            self._write_global_header(global_header)
        else:
            # Default header: Ethernet, 65535 snaplen
            default = PcapGlobalHeader(
                magic_number=PCAP_MAGIC_NATIVE,
                version_major=2,
                version_minor=4,
                thiszone=0,
                sigfigs=0,
                snaplen=65535,
                network=1,
            )
            self._write_global_header(default)

        return True

    def _write_global_header(self, hdr: PcapGlobalHeader) -> None:
        data = struct.pack(
            GLOBAL_HEADER_FMT_LE,
            hdr.magic_number,
            hdr.version_major,
            hdr.version_minor,
            hdr.thiszone,
            hdr.sigfigs,
            hdr.snaplen,
            hdr.network,
        )
        self._file.write(data)

    def write_packet(self, ts_sec: int, ts_usec: int, data: bytes) -> None:
        """Write a single packet (header + data) to the output file."""
        if self._file is None:
            return
        pkt_hdr = struct.pack(
            PACKET_HEADER_FMT_LE,
            ts_sec,
            ts_usec,
            len(data),
            len(data),
        )
        self._file.write(pkt_hdr)
        self._file.write(data)

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.close()
        self._file = None

    @property
    def is_open(self) -> bool:
        return self._file is not None and not self._file.closed

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
