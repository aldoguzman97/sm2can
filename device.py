"""
SM2Device — High-level API for the SM2 Pro CAN adapter.

Combines the USB transport with the protocol codec to provide
a simple, thread-safe interface for CAN bus operations.

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import time
import struct
import logging
import threading
from typing import Optional
from collections import deque

from sm2can.usb_transport import USBTransport, USBTransportError
from sm2can.protocol import (
    ProtocolCodec, ProtocolDetector, Command, CANFrame, CANMode, DeviceInfo
)

logger = logging.getLogger(__name__)


class SM2DeviceError(Exception):
    """Raised when an SM2 Pro operation fails."""


class SM2Device:
    """
    High-level interface to the SM2 Pro CAN adapter.

    Example::

        dev = SM2Device()
        dev.open(bitrate=500000)

        dev.send(0x7DF, bytes([0x02, 0x01, 0x00, 0, 0, 0, 0, 0]))
        frame = dev.recv(timeout=1.0)
        if frame:
            print(f"0x{frame.arbitration_id:03X}: {frame.data.hex()}")

        dev.close()
    """

    def __init__(self, vid: int = 0x20A2, pid: int = 0x0001,
                 bus: Optional[int] = None, address: Optional[int] = None):
        self._transport = USBTransport(vid=vid, pid=pid, bus=bus, address=address)
        self._codec = ProtocolCodec()
        self._is_open = False
        self._bitrate = 0
        self._mode = CANMode.NORMAL
        self._device_info: Optional[DeviceInfo] = None

        # Receive queue and background reader
        self._rx_queue: deque = deque(maxlen=4096)
        self._rx_thread: Optional[threading.Thread] = None
        self._rx_running = False

    @property
    def is_open(self) -> bool:
        return self._is_open

    @property
    def device_info(self) -> Optional[DeviceInfo]:
        return self._device_info

    def open(self, bitrate: int = 500000, mode: int = CANMode.NORMAL,
             auto_detect: bool = True) -> None:
        """
        Open the SM2 Pro and start CAN communication.

        Args:
            bitrate: CAN bus bitrate (default 500000).
            mode: CAN mode (NORMAL, LISTEN_ONLY, LOOPBACK).
            auto_detect: Try to auto-detect protocol variant.

        Raises:
            SM2DeviceError: If the device can't be opened or configured.
        """
        try:
            self._transport.open()
        except USBTransportError as e:
            raise SM2DeviceError(f"Cannot open SM2 Pro: {e}") from e

        # FIX #1: Firmware boot failure must raise, not silently continue.
        # Without 12V on OBD pin 16, the MCU enumerates on USB but the
        # application firmware never starts — bulk endpoints are dead.
        if not self._transport.check_firmware_booted():
            self._transport.close()
            raise SM2DeviceError(
                "SM2 Pro firmware not booted — bulk endpoints not responding. "
                "The device needs 12V on OBD-II pin 16 to start its application "
                "firmware. USB 5V alone only powers the bootloader."
            )

        # FIX #2: Auto-detect failure must raise.
        # If no protocol variant gets a response, we cannot encode or decode
        # anything — continuing would send garbage and recv() returns None forever.
        if auto_detect:
            detector = ProtocolDetector(self._transport)
            detected = detector.detect()
            if detected:
                self._codec = detected
                logger.info("Protocol auto-detected successfully")
            else:
                self._transport.close()
                raise SM2DeviceError(
                    "No protocol variant produced a response. "
                    "The device may need a USB capture to determine the correct "
                    "protocol format. See: sm2can-capture --help"
                )

        # Request device info
        self._request_device_info()

        # FIX #3: CAN open with no response must raise.
        # If the device doesn't respond to CAN_OPEN, the channel isn't open.
        # Setting _is_open=True here would make send() silently drop frames
        # and recv() return None forever with no indication of failure.
        frame = self._codec.encode_can_open(bitrate, mode)
        resp = self._transport.write_read(frame, timeout_ms=1000)
        if resp:
            decoded = self._codec.decode_frame(resp)
            if decoded:
                cmd, payload = decoded
                if cmd == Command.NACK:
                    err_code = payload[0] if payload else 0xFF
                    self._transport.close()
                    raise SM2DeviceError(
                        f"CAN open rejected by device (error 0x{err_code:02X})"
                    )
                logger.info("CAN channel opened: %d bps, mode=%d", bitrate, mode)
        else:
            self._transport.close()
            raise SM2DeviceError(
                "No response to CAN open command. "
                "Device may not support this bitrate or the protocol "
                "codec needs updating from a USB capture."
            )

        self._bitrate = bitrate
        self._mode = mode
        self._is_open = True

        # Start background receive thread
        self._start_rx_thread()

    def close(self) -> None:
        """Close the CAN channel and release the USB device."""
        self._stop_rx_thread()

        if self._transport.is_open:
            try:
                frame = self._codec.encode_can_close()
                self._transport.write(frame)
                time.sleep(0.05)
            except Exception:
                pass
            self._transport.close()

        self._is_open = False
        logger.info("SM2 Pro closed")

    def send(self, arb_id: int, data: bytes,
             is_extended_id: bool = False,
             is_remote_frame: bool = False) -> None:
        """
        Send a CAN frame.

        Args:
            arb_id: CAN arbitration ID (11-bit or 29-bit).
            data: Frame data (0-8 bytes, truncated if longer).
            is_extended_id: True for 29-bit extended ID.
            is_remote_frame: True for RTR frame.

        Raises:
            SM2DeviceError: If not open or write fails.
        """
        if not self._is_open:
            raise SM2DeviceError("Device not open — call open() first")

        frame = CANFrame(
            arbitration_id=arb_id,
            data=data[:8],
            is_extended_id=is_extended_id,
            is_remote_frame=is_remote_frame,
        )

        try:
            encoded = self._codec.encode_can_send(frame)
            self._transport.write(encoded)
        except USBTransportError as e:
            raise SM2DeviceError(f"CAN send failed: {e}") from e

    def recv(self, timeout: float = 1.0) -> Optional[CANFrame]:
        """
        Receive a CAN frame from the background queue.

        Args:
            timeout: Timeout in seconds.

        Returns:
            CANFrame, or None on timeout.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._rx_queue:
                return self._rx_queue.popleft()
            time.sleep(0.001)
        return None

    def set_filter(self, arb_id: int, mask: int = 0x7FF) -> None:
        """Set a CAN acceptance filter."""
        data = struct.pack('>II', arb_id, mask)
        frame = self._codec.encode_command(Command.CAN_SET_FILTER, data)
        self._transport.write(frame)

    def clear_filters(self) -> None:
        """Clear all CAN filters (accept all)."""
        frame = self._codec.encode_command(Command.CAN_CLEAR_FILTER)
        self._transport.write(frame)

    def get_voltage(self) -> float:
        """
        Read the OBD connector voltage.

        Returns:
            Voltage in volts, or 0.0 if unavailable.
        """
        frame = self._codec.encode_command(Command.GET_VOLTAGE)
        resp = self._transport.write_read(frame, timeout_ms=500)
        if resp:
            decoded = self._codec.decode_frame(resp)
            if decoded:
                _, payload = decoded
                if len(payload) >= 2:
                    raw = struct.unpack('>H', payload[:2])[0]
                    return raw * 0.01  # Typically in 10mV units
        return 0.0

    # ── Private ──

    def _request_device_info(self) -> None:
        """Request and store device identification."""
        frame = self._codec.encode_identify()
        resp = self._transport.write_read(frame, timeout_ms=1000)
        if resp:
            decoded = self._codec.decode_frame(resp)
            if decoded:
                _, payload = decoded
                self._device_info = DeviceInfo()
                # Parse when we know the response format from captures
                logger.info("Device info received: %d bytes", len(payload))

    def _start_rx_thread(self) -> None:
        """Start background CAN frame receiver."""
        self._rx_running = True
        self._rx_thread = threading.Thread(
            target=self._rx_loop,
            daemon=True,
            name="sm2can-rx",
        )
        self._rx_thread.start()

    def _stop_rx_thread(self) -> None:
        """Stop background receiver."""
        self._rx_running = False
        if self._rx_thread:
            self._rx_thread.join(timeout=2.0)
            self._rx_thread = None

    # FIX #4: RX thread now counts consecutive errors and exits after 50.
    # Previously this was an infinite loop that silently ate all errors,
    # meaning a disconnected device would spin forever at 100% CPU in
    # the background with no indication of failure.
    def _rx_loop(self) -> None:
        """Background thread: read USB and decode CAN frames."""
        consecutive_errors = 0
        max_consecutive_errors = 50  # ~0.5s of continuous failure

        while self._rx_running and self._transport.is_open:
            try:
                data = self._transport.read(timeout_ms=50)
                if data:
                    consecutive_errors = 0
                    frames = self._codec.feed(data)
                    for cmd, payload in frames:
                        if cmd == Command.CAN_RECV:
                            can_frame = self._codec.decode_can_frame(payload)
                            if can_frame:
                                can_frame.timestamp = time.time()
                                self._rx_queue.append(can_frame)
                        elif cmd == Command.ASYNC_EVENT:
                            logger.debug("Async event: %s", payload.hex(' '))
            except USBTransportError:
                if self._rx_running:
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        logger.error(
                            "RX thread: %d consecutive USB errors, stopping",
                            consecutive_errors)
                        break
                    time.sleep(0.01)
            except Exception as e:
                if self._rx_running:
                    logger.debug("RX thread error: %s", e)
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        break
                    time.sleep(0.01)

        logger.debug("RX thread exited (running=%s, errors=%d)",
                     self._rx_running, consecutive_errors)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()
