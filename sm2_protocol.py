"""
SM2 Pro wire protocol - reverse-engineered from Scanmatik Android APK 2.21.35

Frame format:
    [CMD, LEN_LO, LEN_HI, CHECKSUM, ...PAYLOAD]

Checksum:
    (cmd + 0x55 + len_hi + len_lo) & 0xFF

Source: com.scanmatik.sm2lib.AndroidBth0.nativeCb_request()
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

# Protocol constant baked into checksum
CHECKSUM_SALT = 0x55

# Header size (cmd + len_lo + len_hi + checksum)
HEADER_SIZE = 4

# Max payload per frame (16-bit length field)
MAX_PAYLOAD = 65535


@dataclass
class SM2Frame:
    """A single SM2 Pro protocol frame."""
    cmd: int
    payload: bytes

    @property
    def length(self) -> int:
        return len(self.payload)

    def encode(self) -> bytes:
        """Encode frame to wire bytes."""
        length = len(self.payload)
        if length > MAX_PAYLOAD:
            raise ValueError(f"Payload too large: {length} > {MAX_PAYLOAD}")
        len_lo = length & 0xFF
        len_hi = (length >> 8) & 0xFF
        checksum = (self.cmd + CHECKSUM_SALT + len_hi + len_lo) & 0xFF
        return bytes([self.cmd, len_lo, len_hi, checksum]) + self.payload

    @staticmethod
    def checksum(cmd: int, length: int) -> int:
        """Compute checksum for given command and payload length."""
        len_lo = length & 0xFF
        len_hi = (length >> 8) & 0xFF
        return (cmd + CHECKSUM_SALT + len_hi + len_lo) & 0xFF

    @staticmethod
    def verify_header(header: bytes) -> tuple[int, int, bool]:
        """
        Parse and verify a 4-byte header.
        Returns (cmd, payload_length, checksum_valid).
        """
        if len(header) < HEADER_SIZE:
            raise ValueError(f"Header too short: {len(header)} < {HEADER_SIZE}")
        cmd = header[0]
        length = header[1] | (header[2] << 8)
        expected = SM2Frame.checksum(cmd, length)
        return cmd, length, (expected == header[3])

    @staticmethod
    def decode(data: bytes) -> Optional['SM2Frame']:
        """
        Decode a complete frame from bytes.
        Returns None if checksum invalid.
        """
        cmd, length, valid = SM2Frame.verify_header(data[:HEADER_SIZE])
        if not valid:
            return None
        if len(data) < HEADER_SIZE + length:
            return None
        return SM2Frame(cmd=cmd, payload=data[HEADER_SIZE:HEADER_SIZE + length])


class SM2StreamDecoder:
    """
    Streaming decoder for SM2 Pro protocol.
    Feed bytes incrementally, get complete frames out.
    """

    def __init__(self):
        self._buffer = bytearray()
        self._frames: list[SM2Frame] = []

    def feed(self, data: bytes) -> list[SM2Frame]:
        """Feed raw bytes, return list of complete decoded frames."""
        self._buffer.extend(data)
        frames = []

        while len(self._buffer) >= HEADER_SIZE:
            cmd, length, valid = SM2Frame.verify_header(bytes(self._buffer[:HEADER_SIZE]))

            if not valid:
                # Bad checksum — skip one byte and try to resync
                # (matches the while loop in nativeCb_request that
                #  re-reads 4 bytes on checksum mismatch)
                self._buffer.pop(0)
                continue

            total = HEADER_SIZE + length
            if len(self._buffer) < total:
                break  # Need more data

            frame = SM2Frame(
                cmd=cmd,
                payload=bytes(self._buffer[HEADER_SIZE:total])
            )
            frames.append(frame)
            del self._buffer[:total]

        return frames

    def reset(self):
        """Clear internal buffer."""
        self._buffer.clear()


# ============================================================
# Status codes from libcom.scanmatik.sm2lib.so string table
# Exact numeric values TBD — order suggests sequential assignment
# ============================================================

SMSTATUS_NAMES = [
    "SMSTATUS_SUCCESS",
    "SMSTATUS_INVALID_PARAMETER",
    "SMSTATUS_TXTIMEOUT",
    "SMSTATUS_INVALID_RESPONSE",
    "SMSTATUS_INVALID_INTERFACE",
    "SMSTATUS_RADIOLINK_DENIED",
    "SMSTATUS_UNSUCCESSFUL",
    "SMSTATUS_APPINITFAILED",
    "SMSTATUS_DEVICE_NOT_FOUND",
    "SMSTATUS_ABORTED",
    "SMSTATUS_NO_RESPONSE",
    "SMSTATUS_LOW_RESOURCES",
    "SMSTATUS_REQUEST_REJECTED",
    "SMSTATUS_OPERATION_WAS_NEVER_PERFORMED",
    "SMSTATUS_INVALID_LENGTH",
    "SMSTATUS_NO_RADIO_DONGLE_FOUND",
    "SMSTATUS_FILE_IO_ERROR",
    "SMSTATUS_NO_USB_HOST_HARDWARE_FOUND",
    "SMSTATUS_UNSUPPORTED",
    "SMSTATUS_DEVICE_IN_USE_BY_ANOTHER_PROCCESS",
    "SMSTATUS_WIRELESS_CREDENTIALS_WRONG",
]


def format_frame(frame: SM2Frame, direction: str = "??") -> str:
    """Pretty-print a frame for debugging."""
    payload_hex = frame.payload.hex(' ') if frame.payload else "(empty)"
    payload_ascii = ''.join(
        chr(b) if 32 <= b < 127 else '.'
        for b in frame.payload
    )
    return (
        f"[{direction}] cmd=0x{frame.cmd:02X} len={frame.length} "
        f"cksum=0x{SM2Frame.checksum(frame.cmd, frame.length):02X} "
        f"| {payload_hex}"
        f" | {payload_ascii}"
    )
