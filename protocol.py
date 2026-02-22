"""
Protocol encoder/decoder for the SM2 Pro binary protocol.

STATUS: FRAMEWORK COMPLETE — AWAITING USB CAPTURE DATA
=======================================================
The protocol constants in this module are hypothesized based on
analysis of similar STM32-based J2534 adapters. They will be updated
with confirmed values once USB traffic captures are analyzed.

All protocol knowledge was obtained through clean room reverse
engineering of a legitimately purchased device. No proprietary code
or documentation was used. See LEGAL.md.

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import struct
import logging
import enum
from typing import Optional, List, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ═════════════════════════════════════════════════════════
#  Protocol Constants (updated from captures via sm2can-capture)
# ═════════════════════════════════════════════════════════

class Command(enum.IntEnum):
    """
    Protocol command codes.

    These are placeholder values. They will be replaced with confirmed
    values from USB capture analysis. The numbering follows common
    patterns in STM32-based J2534 adapters.
    """
    # ── Device Management ──
    IDENTIFY        = 0x01
    RESET           = 0x02
    GET_VERSION     = 0x03
    GET_SERIAL      = 0x04
    SET_LED         = 0x05
    GET_VOLTAGE     = 0x06

    # ── CAN Channel ──
    CAN_OPEN        = 0x10
    CAN_CLOSE       = 0x11
    CAN_SET_BITRATE = 0x12
    CAN_SET_FILTER  = 0x13
    CAN_CLEAR_FILTER = 0x14
    CAN_GET_STATUS  = 0x15
    CAN_SET_MODE    = 0x16

    # ── CAN Data ──
    CAN_SEND        = 0x20
    CAN_RECV        = 0x21
    CAN_SEND_MULTI  = 0x22

    # ── ISO-TP ──
    ISOTP_SEND      = 0x30
    ISOTP_RECV      = 0x31

    # ── J2534 PassThru ──
    PT_CONNECT      = 0x40
    PT_DISCONNECT   = 0x41
    PT_READ_MSGS    = 0x42
    PT_WRITE_MSGS   = 0x43
    PT_START_FILTER = 0x44
    PT_STOP_FILTER  = 0x45
    PT_IOCTL        = 0x46

    # ── Responses ──
    ACK             = 0x80
    NACK            = 0x81
    ASYNC_EVENT     = 0x82


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


class CANMode(enum.IntEnum):
    """CAN controller operating modes."""
    NORMAL      = 0
    LISTEN_ONLY = 1
    LOOPBACK    = 2


class ErrorCode(enum.IntEnum):
    """Protocol error codes (placeholder)."""
    OK              = 0x00
    UNKNOWN_CMD     = 0x01
    INVALID_PARAM   = 0x02
    CHANNEL_CLOSED  = 0x03
    BUS_ERROR       = 0x04
    TX_TIMEOUT      = 0x05
    BUFFER_FULL     = 0x06
    NOT_SUPPORTED   = 0x07
    HARDWARE_ERROR  = 0x08


# ═════════════════════════════════════════════════════════
#  Data Structures
# ═════════════════════════════════════════════════════════

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
    """SM2 Pro device information."""
    firmware_version: str = ""
    hardware_version: str = ""
    serial_number: str = ""
    voltage: float = 0.0
    protocol_version: int = 0


# ═════════════════════════════════════════════════════════
#  Checksum Functions
# ═════════════════════════════════════════════════════════

def _checksum_xor(data: bytes) -> int:
    """XOR checksum — XOR all bytes together."""
    result = 0
    for b in data:
        result ^= b
    return result & 0xFF


def _checksum_sum(data: bytes) -> int:
    """SUM checksum — sum all bytes mod 256."""
    return sum(data) & 0xFF


def _checksum_none(data: bytes) -> int:
    """No checksum — always returns 0."""
    return 0


# Map of checksum names to functions (used by ProtocolDetector)
CHECKSUM_FUNCTIONS = {
    'xor': _checksum_xor,
    'sum': _checksum_sum,
    'none': _checksum_none,
}


# ═════════════════════════════════════════════════════════
#  Protocol Codec
# ═════════════════════════════════════════════════════════

class ProtocolCodec:
    """
    Encoder/decoder for the binary protocol.

    Hypothesized frame format:

        Offset  Size  Field
        ────────────────────────────
        0       1     Header / sync byte
        1       2     Payload length (big-endian)
        3       1     Command code
        4       N     Payload data
        4+N     1     Checksum

    The checksum function and header byte are configurable to support
    protocol variant auto-detection.
    """

    HEADER_BYTE = 0xAA
    MIN_FRAME_SIZE = 5   # header(1) + len(2) + cmd(1) + checksum(1)

    def __init__(self, checksum_fn=None):
        """
        Args:
            checksum_fn: Callable(bytes) -> int. Defaults to XOR.
        """
        self._rx_buffer = bytearray()
        self._checksum_fn = checksum_fn or _checksum_xor

    def encode_command(self, cmd: int, data: bytes = b'') -> bytes:
        """
        Encode a command into a protocol frame.

        Args:
            cmd: Command code.
            data: Payload bytes.

        Returns:
            Complete frame ready to send over USB.
        """
        payload_len = 1 + len(data)  # cmd byte + data
        frame = bytearray()
        frame.append(self.HEADER_BYTE)
        frame.extend(struct.pack('>H', payload_len))
        frame.append(cmd & 0xFF)
        frame.extend(data)
        frame.append(self._checksum_fn(frame))
        return bytes(frame)

    def decode_frame(self, raw: bytes) -> Optional[Tuple[int, bytes]]:
        """
        Decode a received frame.

        Returns:
            Tuple of (command_code, payload_data), or None if invalid.
        """
        if len(raw) < self.MIN_FRAME_SIZE:
            return None

        if raw[0] != self.HEADER_BYTE:
            # Try to find header in the data
            idx = raw.find(bytes([self.HEADER_BYTE]))
            if idx < 0:
                logger.debug("No header byte 0x%02X in: %s",
                            self.HEADER_BYTE, raw.hex(' '))
                return None
            raw = raw[idx:]
            if len(raw) < self.MIN_FRAME_SIZE:
                return None

        payload_len = struct.unpack('>H', raw[1:3])[0]
        expected_total = 3 + payload_len + 1  # header + len_field + payload + checksum

        if len(raw) < expected_total:
            logger.debug("Incomplete frame: have %d, need %d",
                        len(raw), expected_total)
            return None

        frame_data = raw[:expected_total]
        expected_cksum = self._checksum_fn(frame_data[:-1])

        if frame_data[-1] != expected_cksum:
            logger.warning(
                "Checksum mismatch: got 0x%02X, expected 0x%02X "
                "(checksum algorithm may need updating)",
                frame_data[-1], expected_cksum
            )
            # Still return data — checksum algo might be wrong during RE

        cmd = frame_data[3]
        payload = frame_data[4:-1]
        return (cmd, bytes(payload))

    def feed(self, data: bytes) -> List[Tuple[int, bytes]]:
        """
        Feed raw USB data into the decoder buffer.

        Handles partial frames across USB packets.

        Returns:
            List of (command, payload) tuples for each complete frame.
        """
        self._rx_buffer.extend(data)
        frames: List[Tuple[int, bytes]] = []

        while len(self._rx_buffer) >= self.MIN_FRAME_SIZE:
            # Find header
            idx = self._rx_buffer.find(bytes([self.HEADER_BYTE]))
            if idx < 0:
                self._rx_buffer.clear()
                break
            if idx > 0:
                logger.debug("Discarding %d bytes before header", idx)
                del self._rx_buffer[:idx]

            if len(self._rx_buffer) < 3:
                break

            payload_len = struct.unpack('>H', self._rx_buffer[1:3])[0]
            total_len = 3 + payload_len + 1

            if total_len > 1024:
                # Sanity check — probably misaligned
                logger.warning("Implausible frame length %d, skipping byte", total_len)
                del self._rx_buffer[0]
                continue

            if len(self._rx_buffer) < total_len:
                break  # Partial frame, wait for more

            frame = bytes(self._rx_buffer[:total_len])
            del self._rx_buffer[:total_len]

            result = self.decode_frame(frame)
            if result:
                frames.append(result)

        return frames

    def reset_buffer(self) -> None:
        """Clear the receive buffer."""
        self._rx_buffer.clear()

    # ── CAN Frame Encoding ──

    def encode_can_open(self, bitrate: int, mode: int = CANMode.NORMAL) -> bytes:
        """Encode a CAN channel open command."""
        data = struct.pack('>IB', bitrate, mode)
        return self.encode_command(Command.CAN_OPEN, data)

    def encode_can_close(self) -> bytes:
        """Encode a CAN channel close command."""
        return self.encode_command(Command.CAN_CLOSE)

    def encode_can_send(self, frame: CANFrame) -> bytes:
        """Encode a CAN frame for transmission."""
        flags = 0
        if frame.is_extended_id:
            flags |= 0x01
        if frame.is_remote_frame:
            flags |= 0x02

        data = struct.pack('>IBB',
                           frame.arbitration_id, flags, len(frame.data))
        data += frame.data
        return self.encode_command(Command.CAN_SEND, data)

    def decode_can_frame(self, payload: bytes) -> Optional[CANFrame]:
        """Decode a received CAN frame from response payload."""
        if len(payload) < 6:
            return None

        arb_id, flags, dlc = struct.unpack('>IBB', payload[:6])
        if dlc > 8:
            logger.warning("Invalid DLC %d in CAN frame", dlc)
            dlc = min(dlc, 8)

        frame_data = payload[6:6 + dlc]

        return CANFrame(
            arbitration_id=arb_id,
            data=frame_data,
            is_extended_id=bool(flags & 0x01),
            is_remote_frame=bool(flags & 0x02),
        )

    def encode_identify(self) -> bytes:
        """Encode a device identification request."""
        return self.encode_command(Command.IDENTIFY)

    def encode_get_version(self) -> bytes:
        """Encode a firmware version request."""
        return self.encode_command(Command.GET_VERSION)


# ═════════════════════════════════════════════════════════
#  Protocol Auto-Detection
# ═════════════════════════════════════════════════════════

class ProtocolDetector:
    """
    Automatically detect the protocol variant by trying multiple
    frame formats against the device.

    Different firmware versions or manufacturers may use slightly
    different formats (different header byte, checksum algorithm, etc.).
    """

    VARIANTS = [
        (0xAA, 'xor',  "Header=0xAA, XOR checksum"),
        (0x55, 'xor',  "Header=0x55, XOR checksum"),
        (0xAA, 'sum',  "Header=0xAA, SUM checksum"),
        (0x55, 'sum',  "Header=0x55, SUM checksum"),
        (0x02, 'xor',  "Header=0x02, XOR checksum"),
        (0xFE, 'xor',  "Header=0xFE, XOR checksum"),
        (0x5A, 'xor',  "Header=0x5A, XOR checksum"),
        (None, 'none', "No header, no checksum"),
    ]

    def __init__(self, transport):
        self.transport = transport

    def detect(self) -> Optional[ProtocolCodec]:
        """
        Try each variant and return a configured codec for the one
        that gets a response.

        Returns:
            Configured ProtocolCodec, or None if nothing works.
        """
        for header, cksum_name, desc in self.VARIANTS:
            logger.info("Trying variant: %s", desc)

            cksum_fn = CHECKSUM_FUNCTIONS.get(cksum_name, _checksum_xor)
            codec = ProtocolCodec(checksum_fn=cksum_fn)

            if header is not None:
                codec.HEADER_BYTE = header

            frame = codec.encode_identify()
            resp = self.transport.write_read(frame, timeout_ms=500)

            if resp:
                logger.info("Device responded to variant: %s", desc)
                logger.info("Response: %s", resp.hex(' '))
                return codec

        logger.warning("No protocol variant produced a response")
        return None
