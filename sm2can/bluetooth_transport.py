"""
Bluetooth SPP Transport for SM2 Pro (planned).

STATUS: SCAFFOLDING — NOT YET FUNCTIONAL
==========================================
The original (non-clone) SM2 Pro supports Bluetooth Serial Port Profile
(SPP) with Class 2 radio (~10m range). This module will provide a
Bluetooth transport layer using the same interface as USBTransport.

KNOWN BLUETOOTH DETAILS:
  - Profile: SPP (Serial Port Profile)
  - Class: 2 (up to 10 meters)
  - Uses same proprietary binary protocol as USB
  - Manufacturer docs note "may decrease speed by order of magnitude"
  - Clone devices typically lack the Bluetooth radio

PLATFORM APPROACH:
  - macOS: IOBluetooth via pyobjc, or bleak for BLE bridge
  - Linux: BlueZ via socket (RFCOMM) or dbus
  - Cross-platform: bleak (if BLE-to-SPP bridge available)

LIMITATION:
  Bluetooth SPP latency (~10-50ms round-trip) makes it unsuitable for
  real-time CAN control (e.g., LKAS at 100Hz). It works fine for
  diagnostics, DTC reads, and parameter monitoring.

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)


class BluetoothTransportError(Exception):
    """Raised when Bluetooth communication fails."""


class BluetoothNotAvailableError(BluetoothTransportError):
    """Raised when Bluetooth is not available on this system."""


class BluetoothTransport:
    """
    Bluetooth SPP transport for SM2 Pro.

    Provides the same interface as USBTransport so the protocol
    layer and SM2Device can use either transport interchangeably.

    Usage (future)::

        transport = BluetoothTransport(address="AA:BB:CC:DD:EE:FF")
        transport.open()
        transport.write(b'\\x01\\x00')
        data = transport.read(timeout_ms=500)
        transport.close()
    """

    def __init__(self, address: Optional[str] = None, name: Optional[str] = None):
        """
        Args:
            address: Bluetooth MAC address (e.g., "AA:BB:CC:DD:EE:FF").
            name: Device name to search for (e.g., "Scanmatik").
        """
        self.address = address
        self.name = name
        self._is_open = False
        self._socket = None
        self._write_lock = threading.Lock()
        self._read_lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        return self._is_open

    def open(self) -> None:
        """
        Open Bluetooth SPP connection to the SM2 Pro.

        Raises:
            BluetoothNotAvailableError: If BT is not available.
            BluetoothTransportError: If connection fails.
        """
        raise NotImplementedError(
            "Bluetooth transport is not yet implemented. "
            "Contributions welcome! See: "
            "https://github.com/aldoguzman97/sm2can/issues"
        )

    def close(self) -> None:
        """Close the Bluetooth connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        self._is_open = False

    def write(self, data: bytes, timeout_ms: int = 100) -> int:
        """Write data over Bluetooth SPP."""
        raise NotImplementedError("Bluetooth transport not yet implemented")

    def read(self, size: int = 64, timeout_ms: int = 100) -> Optional[bytes]:
        """Read data from Bluetooth SPP."""
        raise NotImplementedError("Bluetooth transport not yet implemented")

    def read_all(self, timeout_ms: int = 100, max_packets: int = 16) -> bytes:
        """Read all available data."""
        raise NotImplementedError("Bluetooth transport not yet implemented")

    def write_read(self, data: bytes, timeout_ms: int = 300) -> Optional[bytes]:
        """Write and read response."""
        raise NotImplementedError("Bluetooth transport not yet implemented")

    def check_firmware_booted(self) -> bool:
        """Check if device responds over Bluetooth."""
        return False

    @staticmethod
    def scan(timeout: float = 10.0) -> list:
        """
        Scan for SM2 Pro devices via Bluetooth.

        Returns:
            List of dicts with address, name, rssi.
        """
        logger.info("Bluetooth scanning not yet implemented")
        return []

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()
