"""
SM2 Pro binary wire protocol — encoder/decoder.

CONFIRMED via Android APK reverse engineering (Scanmatik_Android_2.21.35.apk)
and live hardware probing on 2026-02-22.

Frame format (from AndroidBth0.nativeCb_request lines 505-526):

    Offset  Size  Field
    ──────────────────────────────
    0       1     Command byte
    1       2     Payload length (little-endian)
    3       1     Checksum
    4       N     Payload data

Checksum (from Java source, verbatim):

    byte b = bArr[0];                                    // command byte
    int i = (bArr[1] & 255) | ((bArr[2] & 255) << 8);  // payload length LE16
    bArr[3] = (byte) (b + 85 + (i >> 8) + (i & 255));  // checksum

    85 decimal = 0x55 hex — protocol salt baked into every checksum.

Response convention (from probing):
    rx_cmd = 0x00 → SUCCESS
    rx_cmd = 0x01 → NACK / unknown command
    rx_cmd = sent_cmd → ACK (command accepted by channel)
    rx_cmd = 0x5E → Idle status (response to 0x80)

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import struct
import logging
import enum
from typing import Optional, List, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
#  Protocol Constants — CONFIRMED from APK RE + hardware probing
# ══════════════════════════════════════════════════════════════

CHECKSUM_SALT = 0x55
HEADER_SIZE = 4  # cmd(1) + len_lo(1) + len_hi(1) + checksum(1)


class Cmd(enum.IntEnum):
    """
    SM2 Pro command bytes.

    System commands (0x80-0x89) confirmed via probing 2026-02-22.
    Channel commands (0x8A+) accept payloads; need vehicle bus to verify.
    Commands 0x00-0x7F are below the command space (device returns NACK).
    """
    # — System (confirmed) —
    STATUS          = 0x80  # Returns 0x5E when idle
    ECHO            = 0x82  # Sm2Lib_EchoV2 — echoes payload back
    DEVICE_INFO     = 0x83  # Returns 18-byte device info
    CLEAR_FIFO      = 0x86  # Sm2Lib_Clear_FifoV2
    POWER_DOWN      = 0x87  # Shuts off device entirely — DO NOT USE normally
    INIT            = 0x88  # Device init / ready

    # — Channel / CAN (accept payloads, need vehicle bus to verify) —
    CAN_OPEN        = 0x8A  # Channel open / configure
    CAN_SEND        = 0x8B  # Send CAN frame
    CAN_RECV        = 0x8C  # Receive CAN frame (async from device)
    CAN_CLOSE       = 0x8D  # Channel close
    CAN_SET_FILTER  = 0x8E  # Set acceptance filter
    CAN_CLEAR_FILTER = 0x8F # Clear filters
    CAN_STATUS      = 0x90  # Channel status query

    # — Response codes (in rx_cmd byte) —
    SUCCESS         = 0x00  # Command succeeded
    NACK            = 0x01  # Unknown command or invalid params
    STATUS_IDLE     = 0x5E  # Response to STATUS when no session active


class CANMode(enum.IntEnum):
    """CAN controller operating modes."""
    NORMAL      = 0
    LISTEN_ONLY = 1
    LOOPBACK    = 2


class CANBitrate(enum.IntEnum):
    """Standard CAN bitrates."""
    CAN_10K   = 10000
    CAN_20K   = 20000
    CAN_33K   = 33333
    CAN_50K   = 50000
    CAN_83K   = 83333
    CAN_100K  = 100000
    CAN_125K  = 125000
    CAN_250K  = 250000
    CAN_500K  = 500000
    CAN_1M    = 1000000


# ══════════════════════════════════════════════════════════════
#  Data Structures
# ══════════════════════════════════════════════════════════════

@dataclass
class CANFrame:
    """A CAN bus frame."""
    arbitration_id: int
    data: bytes
    is_extended_id: bool = False
    is_remote_frame: bool = False
    timestamp: float = 0.0

    def __repr__(self) -> str:
        return (f"CANFrame(id=0x{self.arbitration_id:03X}, "
                f"data={self.data.hex(' ')}, ext={self.is_extended_id})")


@dataclass
class DeviceInfo:
    """
    SM2 Pro device information parsed from 0x83 response.

    Known payload (18 bytes, confirmed via probing):
        30 87 A7 00 00 00 00 00 00 00 00 00 76 09 00 00 02 03

        Bytes 0-2:   Hardware ID (30 87 A7)
        Bytes 3-11:  Reserved / zeros
        Bytes 12-13: Firmware version LE16 (76 09 = 0x0976)
        Bytes 14-15: Reserved / zeros
        Bytes 16-17: Hardware revision (02 03)
    """
    raw: bytes = field(default_factory=bytes)
    hardware_id: int = 0
    firmware_version: int = 0
    hardware_rev: int = 0

    @property
    def firmware_str(self) -> str:
        if self.firmware_version:
            major = (self.firmware_version >> 8) & 0xFF
            minor = self.firmware_version & 0xFF
            return f"{major}.{minor}"
        return "unknown"

    @property
    def hardware_str(self) -> str:
        if self.hardware_rev:
            major = (self.hardware_rev >> 8) & 0xFF
            minor = self.hardware_rev & 0xFF
            return f"{major}.{minor}"
        return "unknown"

    @property
    def hardware_id_hex(self) -> str:
        if self.raw and len(self.raw) >= 3:
            return self.raw[:3].hex(' ')
        return "unknown"


# ══════════════════════════════════════════════════════════════
#  Checksum
# ══════════════════════════════════════════════════════════════

def sm2_checksum(cmd: int, length: int) -> int:
    """
    Compute SM2 Pro frame checksum.

    Formula (from Java source):
        checksum = (cmd + 0x55 + len_hi + len_lo) & 0xFF
    """
    len_lo = length & 0xFF
    len_hi = (length >> 8) & 0xFF
    return (cmd + CHECKSUM_SALT + len_hi + len_lo) & 0xFF


def verify_checksum(data: bytes) -> bool:
    """Verify checksum of a received frame (minimum 4 bytes)."""
    if len(data) < HEADER_SIZE:
        return False
    cmd = data[0]
    length = data[1] | (data[2] << 8)
    return sm2_checksum(cmd, length) == data[3]


# ══════════════════════════════════════════════════════════════
#  Frame Building / Parsing
# ══════════════════════════════════════════════════════════════

def build_frame(cmd: int, payload: bytes = b'') -> bytes:
    """
    Build a complete SM2 Pro protocol frame.

    Returns:
        [CMD, LEN_LO, LEN_HI, CHECKSUM, ...PAYLOAD]
    """
    length = len(payload)
    len_lo = length & 0xFF
    len_hi = (length >> 8) & 0xFF
    ck = sm2_checksum(cmd, length)
    return bytes([cmd, len_lo, len_hi, ck]) + payload


def parse_frame(data: bytes) -> Optional[Tuple[int, int, bool, bytes]]:
    """
    Parse a received frame.

    Returns:
        Tuple of (cmd, length, checksum_valid, payload) or None.
    """
    if len(data) < HEADER_SIZE:
        return None
    cmd = data[0]
    length = data[1] | (data[2] << 8)
    valid = verify_checksum(data)
    payload = b''
    if len(data) >= HEADER_SIZE + length:
        payload = data[HEADER_SIZE:HEADER_SIZE + length]
    return (cmd, length, valid, payload)


# ══════════════════════════════════════════════════════════════
#  Protocol Codec
# ══════════════════════════════════════════════════════════════

class SM2Codec:
    """
    Stateful encoder/decoder for SM2 Pro protocol.

    Handles frame building, response parsing, and streaming
    reassembly of partial USB packets.
    """

    def __init__(self):
        self._rx_buffer = bytearray()

    # — Encode commands —

    def encode_echo(self, payload: bytes = b'ECHO') -> bytes:
        return build_frame(Cmd.ECHO, payload)

    def encode_device_info(self) -> bytes:
        return build_frame(Cmd.DEVICE_INFO)

    def encode_init(self) -> bytes:
        return build_frame(Cmd.INIT)

    def encode_clear_fifo(self) -> bytes:
        return build_frame(Cmd.CLEAR_FIFO)

    def encode_status(self) -> bytes:
        return build_frame(Cmd.STATUS)

    def encode_can_open(self, bitrate: int = 500000,
                        mode: int = CANMode.NORMAL) -> bytes:
        """
        Encode CAN channel open (0x8A).

        Payload format: [channel(1), mode(1), baud_le32(4)]
        (Best-guess; will be refined with vehicle bus testing.)
        """
        payload = struct.pack('<BBI', 0x00, mode, bitrate)
        return build_frame(Cmd.CAN_OPEN, payload)

    def encode_can_close(self) -> bytes:
        return build_frame(Cmd.CAN_CLOSE)

    def encode_can_send(self, frame: CANFrame) -> bytes:
        """
        Encode CAN frame for transmission (0x8B).

        Payload: arb_id_le32(4) + flags(1) + dlc(1) + data(0-8)
        """
        flags = 0
        if frame.is_extended_id:
            flags |= 0x01
        if frame.is_remote_frame:
            flags |= 0x02
        data = frame.data[:8]
        payload = struct.pack('<IBB', frame.arbitration_id, flags, len(data))
        payload += data
        return build_frame(Cmd.CAN_SEND, payload)

    def encode_can_filter(self, arb_id: int, mask: int = 0x7FF) -> bytes:
        payload = struct.pack('<II', arb_id, mask)
        return build_frame(Cmd.CAN_SET_FILTER, payload)

    def encode_can_clear_filter(self) -> bytes:
        return build_frame(Cmd.CAN_CLEAR_FILTER)

    def encode_command(self, cmd: int, payload: bytes = b'') -> bytes:
        return build_frame(cmd, payload)

    # — Decode responses —

    def decode_response(self, data: bytes) -> Optional[Tuple[int, bytes]]:
        """Decode a single response frame. Returns (cmd, payload) or None."""
        result = parse_frame(data)
        if result is None:
            return None
        cmd, length, valid, payload = result
        if not valid:
            logger.warning("Checksum mismatch: %s", data[:8].hex(' '))
        return (cmd, payload)

    def decode_device_info(self, payload: bytes) -> DeviceInfo:
        """Parse device info from 0x83 response payload."""
        info = DeviceInfo(raw=payload)
        if len(payload) >= 3:
            info.hardware_id = (payload[0] | (payload[1] << 8)
                                | (payload[2] << 16))
        if len(payload) >= 14:
            info.firmware_version = payload[12] | (payload[13] << 8)
        if len(payload) >= 18:
            info.hardware_rev = payload[16] | (payload[17] << 8)
        return info

    def decode_can_frame(self, payload: bytes) -> Optional[CANFrame]:
        """Decode received CAN frame: arb_id_le32(4) + flags(1) + dlc(1) + data."""
        if len(payload) < 6:
            return None
        arb_id, flags, dlc = struct.unpack('<IBB', payload[:6])
        dlc = min(dlc, 8)
        return CANFrame(
            arbitration_id=arb_id,
            data=payload[6:6 + dlc],
            is_extended_id=bool(flags & 0x01),
            is_remote_frame=bool(flags & 0x02),
        )

    # — Streaming decoder —

    def feed(self, data: bytes) -> List[Tuple[int, bytes]]:
        """
        Feed raw USB data into the streaming decoder.

        Returns list of (cmd, payload) for each complete frame.
        """
        self._rx_buffer.extend(data)
        frames: List[Tuple[int, bytes]] = []

        while len(self._rx_buffer) >= HEADER_SIZE:
            length = self._rx_buffer[1] | (self._rx_buffer[2] << 8)
            total = HEADER_SIZE + length

            if length > 65535:
                logger.warning("Implausible length %d, discarding byte", length)
                del self._rx_buffer[0]
                continue

            if len(self._rx_buffer) < total:
                break

            frame_bytes = bytes(self._rx_buffer[:total])
            del self._rx_buffer[:total]

            if verify_checksum(frame_bytes):
                frames.append((frame_bytes[0], frame_bytes[HEADER_SIZE:]))
            else:
                logger.debug("Checksum fail: %s", frame_bytes[:8].hex(' '))

        return frames

    def reset_buffer(self) -> None:
        self._rx_buffer.clear()

    @property
    def buffer_size(self) -> int:
        return len(self._rx_buffer)
