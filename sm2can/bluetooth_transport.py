"""
Bluetooth RFCOMM Transport for SM2 Pro.

Confirmed from APK reverse engineering (AndroidBth0.java):
  - UUID: 00001200-0000-1000-8000-00805F9B34FB (SDP L2CAP)
  - Pairing PIN: A5137F (bytes: 65, 53, 49, 51, 55, 70)
  - BT Module: BK3231S (firmware: "AT-AB -BK3231S Firmware Ver1.0-")
  - AT commands: AT-VERSION?, AT-FIRMWARE-UPDATE, AT-AB-OK
  - Read timeout: 7 seconds per chunk
  - Same wire protocol as USB (frames are transport-agnostic)

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# Confirmed from APK
BT_UUID = "00001200-0000-1000-8000-00805f9b34fb"
BT_PIN = "A5137F"
BT_PIN_BYTES = bytes([65, 53, 49, 51, 55, 70])
BT_MODULE = "BK3231S"
BT_READ_TIMEOUT = 7.0  # seconds


class BluetoothTransportError(Exception):
    """Base exception for Bluetooth transport failures."""


class BluetoothTransport:
    """
    Bluetooth RFCOMM transport for SM2 Pro.

    Uses the same wire protocol as USB — frames are transport-agnostic.
    Requires a paired BK3231S Bluetooth module.

    NOTE: This transport requires the 'bluetooth' or 'bleak' Python
    package, which is not installed by default. Install with:
        pip install pybluez    (classic RFCOMM, Linux)
        pip install bleak      (BLE, cross-platform — if SM2 Pro supports BLE)

    Example::

        transport = BluetoothTransport(address="AA:BB:CC:DD:EE:FF")
        transport.open()
        transport.write(frame_bytes)
        response = transport.read(timeout=7.0)
        transport.close()
    """

    def __init__(self, address: str, port: int = 1):
        self.address = address
        self.port = port
        self._sock = None
        self._is_open = False
        self._write_lock = threading.Lock()
        self._read_lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        return self._is_open

    def open(self) -> None:
        """
        Open Bluetooth RFCOMM connection to SM2 Pro.

        Raises:
            BluetoothTransportError: If connection fails.
        """
        try:
            import bluetooth
        except ImportError:
            raise BluetoothTransportError(
                "pybluez not installed. Install with: pip install pybluez"
            )

        try:
            self._sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            self._sock.connect((self.address, self.port))
            self._sock.settimeout(BT_READ_TIMEOUT)
            self._is_open = True
            logger.info("Bluetooth connected to %s port %d",
                        self.address, self.port)
        except Exception as e:
            raise BluetoothTransportError(
                f"Cannot connect to {self.address}: {e}"
            ) from e

    def close(self) -> None:
        """Close the Bluetooth connection."""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._is_open = False
        logger.info("Bluetooth connection closed")

    def write(self, data: bytes) -> int:
        """Write data to the RFCOMM socket."""
        if not self._is_open:
            raise BluetoothTransportError("Not connected")

        with self._write_lock:
            try:
                self._sock.send(data)
                logger.debug("BT TX %d bytes: %s", len(data), data.hex(' '))
                return len(data)
            except Exception as e:
                raise BluetoothTransportError(f"BT write error: {e}") from e

    def read(self, size: int = 4096,
             timeout: float = BT_READ_TIMEOUT) -> Optional[bytes]:
        """Read data from the RFCOMM socket."""
        if not self._is_open:
            raise BluetoothTransportError("Not connected")

        with self._read_lock:
            try:
                self._sock.settimeout(timeout)
                data = self._sock.recv(size)
                if data:
                    logger.debug("BT RX %d bytes: %s", len(data), data.hex(' '))
                    return data
                return None
            except Exception:
                return None

    def write_read(self, data: bytes,
                   timeout: float = BT_READ_TIMEOUT) -> Optional[bytes]:
        """Write and read response."""
        self.write(data)
        return self.read(timeout=timeout)

    def flush_input(self) -> int:
        """Drain pending data."""
        drained = 0
        while True:
            chunk = self.read(4096, timeout=0.1)
            if chunk is None:
                break
            drained += len(chunk)
        return drained

    @staticmethod
    def discover(timeout: float = 10.0):
        """
        Discover nearby SM2 Pro devices via Bluetooth.

        Returns list of (address, name) tuples.
        """
        try:
            import bluetooth
            devices = bluetooth.discover_devices(
                duration=int(timeout),
                lookup_names=True,
                lookup_class=True,
            )
            sm2_devices = []
            for addr, name, _ in devices:
                if name and 'scanmatik' in name.lower():
                    sm2_devices.append((addr, name))
            return sm2_devices
        except ImportError:
            logger.warning("pybluez not installed — cannot discover BT devices")
            return []

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()
