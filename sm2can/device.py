"""
SM2Device — High-level API for the SM2 Pro CAN adapter.

Combines the USB transport with the protocol codec to provide
a simple, thread-safe interface for CAN bus operations.

Uses confirmed protocol from APK reverse engineering + hardware probing.

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import time
import logging
import threading
from typing import Optional
from collections import deque

from sm2can.usb_transport import USBTransport, USBTransportError
from sm2can.protocol import (
    SM2Codec, Cmd, CANFrame, CANMode, DeviceInfo, build_frame, parse_frame
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
        self._codec = SM2Codec()
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

    def open(self, bitrate: int = 500000, mode: int = CANMode.NORMAL) -> None:
        """
        Open the SM2 Pro and start CAN communication.

        Init sequence (confirmed via probing):
            1. Open USB transport
            2. Send INIT (0x88) — expect SUCCESS (0x00)
            3. Send ECHO (0x82) — verify firmware is alive
            4. Send DEVICE_INFO (0x83) — get fw/hw version
            5. Send CLEAR_FIFO (0x86) — flush device buffers
            6. Send CAN_OPEN (0x8A) — configure CAN channel

        Args:
            bitrate: CAN bus bitrate (default 500000).
            mode: CAN mode (NORMAL, LISTEN_ONLY, LOOPBACK).

        Raises:
            SM2DeviceError: If the device can't be opened or configured.
        """
        # Step 1: Open USB
        try:
            self._transport.open()
        except USBTransportError as e:
            raise SM2DeviceError(f"Cannot open SM2 Pro: {e}") from e

        # Step 2: Init
        resp = self._send_cmd(Cmd.INIT, label="INIT")
        if resp is None:
            raise SM2DeviceError(
                "SM2 Pro not responding to INIT command. "
                "Device may be in bootloader mode or hardware fault."
            )
        rx_cmd = resp[0] if resp else None
        if rx_cmd == Cmd.NACK:
            raise SM2DeviceError("SM2 Pro rejected INIT command")
        logger.info("INIT: OK (rx_cmd=0x%02X)", rx_cmd or 0)

        # Step 3: Echo test
        echo_data = b'SM2CAN'
        echo_frame = self._codec.encode_echo(echo_data)
        echo_resp = self._transport.write_read(echo_frame, timeout_ms=1000)
        if echo_resp:
            result = parse_frame(echo_resp)
            if result:
                _, _, valid, payload = result
                if valid and echo_data in payload:
                    logger.info("ECHO: verified — firmware alive")
                else:
                    logger.warning("ECHO: response but payload mismatch")
            else:
                logger.warning("ECHO: unparseable response")
        else:
            logger.warning("ECHO: no response (device may still work)")

        # Step 4: Device info
        self._request_device_info()

        # Step 5: Clear FIFO
        self._send_cmd(Cmd.CLEAR_FIFO, label="CLEAR_FIFO")

        # Step 6: Open CAN channel
        can_frame = self._codec.encode_can_open(bitrate, mode)
        can_resp = self._transport.write_read(can_frame, timeout_ms=1000)
        if can_resp:
            result = parse_frame(can_resp)
            if result:
                rx_cmd, _, valid, payload = result
                if rx_cmd == Cmd.NACK:
                    logger.warning("CAN_OPEN returned NACK — channel may need "
                                   "vehicle bus connected")
                elif rx_cmd == Cmd.CAN_OPEN:
                    logger.info("CAN_OPEN: accepted (cmd echoed)")
                elif rx_cmd == Cmd.SUCCESS:
                    logger.info("CAN_OPEN: success")
                else:
                    logger.info("CAN_OPEN: response cmd=0x%02X", rx_cmd)
        else:
            logger.warning("CAN_OPEN: no response")

        self._bitrate = bitrate
        self._mode = mode
        self._is_open = True

        # Start background receive thread
        self._start_rx_thread()

        logger.info("SM2 Pro opened: %d bps, mode=%s", bitrate,
                     CANMode(mode).name)

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
            data: Frame data (0-8 bytes).
            is_extended_id: True for 29-bit extended ID.
            is_remote_frame: True for RTR frame.
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
        if not self._is_open:
            raise SM2DeviceError("Device not open")
        frame = self._codec.encode_can_filter(arb_id, mask)
        self._transport.write(frame)

    def clear_filters(self) -> None:
        """Clear all CAN filters (accept all)."""
        if not self._is_open:
            raise SM2DeviceError("Device not open")
        frame = self._codec.encode_can_clear_filter()
        self._transport.write(frame)

    def echo(self, payload: bytes = b'SM2CAN') -> Optional[bytes]:
        """
        Send echo command and return echoed payload.

        Useful for health checks.
        """
        frame = self._codec.encode_echo(payload)
        resp = self._transport.write_read(frame, timeout_ms=1000)
        if resp:
            result = parse_frame(resp)
            if result:
                _, _, _, rx_payload = result
                return rx_payload
        return None

    def get_status(self) -> Optional[int]:
        """Query device status. Returns response cmd byte."""
        frame = self._codec.encode_status()
        resp = self._transport.write_read(frame, timeout_ms=500)
        if resp:
            result = parse_frame(resp)
            if result:
                return result[0]
        return None

    # ── Private ──

    def _send_cmd(self, cmd: int, payload: bytes = b'',
                  label: str = "", timeout_ms: int = 1000
                  ) -> Optional[bytes]:
        """Send a command and return raw response bytes."""
        frame = build_frame(cmd, payload)
        resp = self._transport.write_read(frame, timeout_ms=timeout_ms)
        if resp:
            logger.debug("%s: TX=%s RX=%s", label or f"CMD 0x{cmd:02X}",
                         frame.hex(' '), resp.hex(' '))
        else:
            logger.debug("%s: TX=%s RX=(timeout)", label or f"CMD 0x{cmd:02X}",
                         frame.hex(' '))
        return resp

    def _request_device_info(self) -> None:
        """Request and store device identification."""
        frame = self._codec.encode_device_info()
        resp = self._transport.write_read(frame, timeout_ms=1000)
        if resp:
            result = parse_frame(resp)
            if result:
                rx_cmd, length, valid, payload = result
                if rx_cmd == Cmd.SUCCESS and payload:
                    self._device_info = self._codec.decode_device_info(payload)
                    logger.info(
                        "Device info: HW_ID=%s FW=%s HW=%s",
                        self._device_info.hardware_id_hex,
                        self._device_info.firmware_str,
                        self._device_info.hardware_str,
                    )
                else:
                    logger.warning("DEVICE_INFO: cmd=0x%02X len=%d",
                                   rx_cmd, length)

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

    def _rx_loop(self) -> None:
        """Background thread: read USB and decode CAN frames."""
        consecutive_errors = 0
        max_consecutive_errors = 50

        while self._rx_running and self._transport.is_open:
            try:
                data = self._transport.read(timeout_ms=50)
                if data:
                    consecutive_errors = 0
                    frames = self._codec.feed(data)
                    for cmd, payload in frames:
                        if cmd == Cmd.CAN_RECV:
                            can_frame = self._codec.decode_can_frame(payload)
                            if can_frame:
                                can_frame.timestamp = time.time()
                                self._rx_queue.append(can_frame)
                        else:
                            logger.debug("RX async: cmd=0x%02X len=%d",
                                         cmd, len(payload))
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
