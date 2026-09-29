"""
PCAP file reader and writer.

Handles the binary PCAP file format used by Wireshark / tcpdump:
  - Global header (24 bytes): magic, version, snaplen, link type
  - Per-packet header (16 bytes): timestamp, captured length, original length
  - Per-packet data (variable): the raw network bytes
"""

from __future__ import annotations

import os
import struct
import tempfile
from dataclasses import dataclass
from typing import Optional, BinaryIO

from dpi.types import ProcessingError


# PCAP magic numbers
PCAP_MAGIC_NATIVE  = 0xA1B2C3D4   # Native byte order
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1   # Swapped byte order

# Recognised-but-unsupported magics, reported with a specific message
PCAP_MAGIC_NSEC_NATIVE  = 0xA1B23C4D   # nanosecond-resolution pcap
PCAP_MAGIC_NSEC_SWAPPED = 0x4D3CB2A1
PCAPNG_MAGIC            = 0x0A0D0D0A   # pcapng Section Header Block

LINKTYPE_ETHERNET = 1
MAX_PACKET_LEN = 65535          # largest incl_len accepted (matches the default snaplen)


class PcapFormatError(ProcessingError):
    """The input is not a PCAP file this tool supports, or it is truncated/corrupt."""


class PcapWriteError(ProcessingError):
    """The output could not be written, finished, or moved into place."""

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
        self._packets_read: int = 0
        self.last_error: str = ""

    # --- Lifecycle ---

    def open(self, filename: str) -> bool:
        """
        Open a PCAP file and read the global header. Returns True on success.

        Returns False (after printing the reason) for: unreadable path, short
        header, unknown magic, nanosecond pcap, pcapng, and non-Ethernet link
        types.  ``last_error`` holds the message.
        """
        self.close()
        self.last_error = ""
        try:
            self._file = open(filename, "rb")
        except OSError as e:
            return self._fail(f"Could not open file: {filename} ({e})")

        raw = self._file.read(GLOBAL_HEADER_SIZE)
        if len(raw) < GLOBAL_HEADER_SIZE:
            return self._fail(f"Not a PCAP file (only {len(raw)} bytes, need a 24-byte global header)")

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
        elif magic in (PCAP_MAGIC_NSEC_NATIVE, PCAP_MAGIC_NSEC_SWAPPED):
            return self._fail("Unsupported format: nanosecond-resolution pcap (magic 0xA1B23C4D). "
                              "Convert with `editcap -F pcap` / `tshark -F pcap`.")
        elif magic == PCAPNG_MAGIC:
            return self._fail("Unsupported format: pcapng. Convert with `editcap -F pcap` / `tshark -F pcap`.")
        else:
            return self._fail(f"Not a PCAP file: unknown magic number 0x{magic:08X}")

        fields = struct.unpack(fmt, raw)
        self._global_header = PcapGlobalHeader(*fields)

        link = self._global_header.network
        if link != LINKTYPE_ETHERNET:
            return self._fail(f"Unsupported link type {link}: only Ethernet (LINKTYPE_ETHERNET = 1) is parsed")

        print(f"Opened PCAP file: {filename}")
        print(f"  Version: {self._global_header.version_major}."
              f"{self._global_header.version_minor}")
        print(f"  Snaplen: {self._global_header.snaplen} bytes")
        print(f"  Link type: {link} (Ethernet)")

        return True

    def _fail(self, message: str) -> bool:
        self.last_error = message
        print(f"Error: {message}")
        self.close()
        return False

    def close(self) -> None:
        """Close the file handle."""
        if self._file and not self._file.closed:
            self._file.close()
        self._file = None
        self._global_header = None
        self._needs_swap = False
        self._packets_read = 0

    # --- Reading ---

    def read_next_packet(self) -> Optional[RawPacket]:
        """
        Read and return the next packet, or ``None`` at a clean EOF.

        Raises ``PcapFormatError`` if the file ends inside a packet header or
        packet body, or if a record claims an impossible length.  A truncated
        capture is therefore never mistaken for a complete one.
        """
        if self._file is None:
            return None

        raw_hdr = self._file.read(PACKET_HEADER_SIZE)
        if not raw_hdr:
            return None  # clean EOF
        if len(raw_hdr) < PACKET_HEADER_SIZE:
            raise PcapFormatError(
                f"truncated capture: {len(raw_hdr)} trailing byte(s) after packet #{self._packets_read}, "
                f"expected a {PACKET_HEADER_SIZE}-byte record header"
            )

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            self._pkt_hdr_fmt, raw_hdr
        )

        if incl_len > MAX_PACKET_LEN:
            raise PcapFormatError(
                f"corrupt record header for packet #{self._packets_read}: captured length {incl_len} "
                f"exceeds {MAX_PACKET_LEN}"
            )

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            raise PcapFormatError(
                f"truncated capture: packet #{self._packets_read} declares {incl_len} bytes "
                f"but only {len(data)} remain"
            )

        self._packets_read += 1
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

    With ``atomic=True`` packets are written to ``<filename>.partial`` and only
    With ``atomic=True`` packets are written to a uniquely named, exclusively
    created temporary file in the destination directory (``.<name>.XXXXXX.partial``)
    and only moved to ``filename`` by ``commit()``; ``discard()`` removes the
    temporary file.  Pre-existing files -- including any file that merely ends
    in ``.partial`` -- are never opened, truncated or deleted; the destination
    itself is replaced only by a successful ``commit()``.

    All write / flush / close / replace failures are raised as
    ``PcapWriteError`` (a ``ProcessingError``).  When cleanup of the temporary
    file also fails, the error message names the file that was left behind.
    """

    PARTIAL_SUFFIX = ".partial"

    def __init__(self) -> None:
        self._file: Optional[BinaryIO] = None
        self._final_path: Optional[str] = None
        self._write_path: Optional[str] = None
        self._atomic: bool = False
        self.last_error: str = ""

    @property
    def temp_path(self) -> Optional[str]:
        """Path being written (the temporary file in atomic mode)."""
        return self._write_path

    def open(
        self,
        filename: str,
        global_header: Optional[PcapGlobalHeader] = None,
        atomic: bool = False,
    ) -> bool:
        """Open a PCAP file for writing. Writes the global header. Returns False on failure."""
        self.close()
        self._final_path = filename
        self._atomic = atomic
        self.last_error = ""
        try:
            if atomic:
                directory = os.path.dirname(os.path.abspath(filename)) or "."
                fd, self._write_path = tempfile.mkstemp(
                    prefix="." + os.path.basename(filename) + ".", suffix=self.PARTIAL_SUFFIX, dir=directory,
                )
                self._file = os.fdopen(fd, "wb")
            else:
                self._write_path = filename
                self._file = open(filename, "wb")
        except OSError as e:
            self.last_error = f"Cannot open output file: {filename} ({e})"
            print(f"Error: {self.last_error}")
            self._file = None
            self._final_path = self._write_path = None
            return False

        try:
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
        except OSError as e:
            self.last_error = f"Cannot write output header: {filename} ({e})"
            print(f"Error: {self.last_error}")
            self.discard()
            return False

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

    def write_packet(self, ts_sec: int, ts_usec: int, data: bytes, orig_len: Optional[int] = None) -> None:
        """
        Write a single packet (header + data) to the output file.

        ``orig_len`` is the original wire length from the input record; it
        defaults to ``len(data)`` when the packet was not snapped.  Timestamps
        are written as read (this tool only handles microsecond-resolution
        files, so no conversion is applied).
        """
        if self._file is None:
            return
        pkt_hdr = struct.pack(
            PACKET_HEADER_FMT_LE,
            ts_sec,
            ts_usec,
            len(data),
            len(data) if orig_len is None else orig_len,
        )
        self._file.write(pkt_hdr)
        self._file.write(data)

    def close(self) -> None:
        """Close the handle (errors ignored); does not move or delete anything."""
        if self._file and not self._file.closed:
            try:
                self._file.close()
            except OSError:
                pass
        self._file = None

    def commit(self) -> None:
        """
        Flush, close, and (if atomic) move the temporary file into place.

        Raises ``PcapWriteError`` if flushing/closing or the replacement fails;
        the temporary file is removed when possible and named in the message
        when it is not.
        """
        write_path, final_path = self._write_path, self._final_path
        try:
            if self._file and not self._file.closed:
                self._file.flush()
                self._file.close()
        except OSError as e:
            self.close()   # best-effort close so the temp can be removed (errors ignored)
            leftover = self._remove_temp()
            raise PcapWriteError(self._describe(f"could not finish writing {write_path}: {e}", leftover)) from e
        self._file = None

        if self._atomic and write_path and final_path:
            try:
                os.replace(write_path, final_path)
            except OSError as e:
                leftover = self._remove_temp()
                raise PcapWriteError(
                    self._describe(f"could not move {write_path} into place at {final_path}: {e}", leftover)
                ) from e
        self._final_path = self._write_path = None

    def discard(self) -> Optional[str]:
        """
        Close and delete whatever was written so far.

        Returns ``None`` when nothing is left behind, otherwise a message naming
        the file that could not be removed (never raises).
        """
        self.close()
        leftover = self._remove_temp()
        self._final_path = self._write_path = None
        return leftover

    def _remove_temp(self) -> Optional[str]:
        path = self._write_path
        if not path or not os.path.exists(path):
            return None
        try:
            os.unlink(path)
            return None
        except OSError as e:
            return f"temporary file left at {path} ({e})"

    @staticmethod
    def _describe(message: str, leftover: Optional[str]) -> str:
        return f"{message}; {leftover}" if leftover else f"{message}; temporary file removed"

    @property
    def is_open(self) -> bool:
        return self._file is not None and not self._file.closed

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
