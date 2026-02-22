"""
USB Transport Layer for SM2 Pro hardware.

Handles raw USB communication via libusb (pyusb). No kernel driver required.
Works on macOS and Linux.

Hardware profile (from clean room reverse engineering of purchased device):
  - VID: 0x20A2  PID: 0x0001
  - Device Class: 0xFF (Vendor Specific)
  - Interface 0: 2 Bulk endpoints
    - EP 0x81 IN  (device -> host), 64-byte max packet
    - EP 0x02 OUT (host -> device), 64-byte max packet
  - Requires 12V on OBD pin 16 for firmware to boot fully.

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import time
import logging
import threading
from typing import Optional, List

import usb.core
import usb.util

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────
SM2_VID = 0x20A2
SM2_PID = 0x0001

EP_IN  = 0x81   # Bulk IN endpoint address
EP_OUT = 0x02   # Bulk OUT endpoint address

MAX_PACKET = 64  # USB full-speed bulk max packet size

# Timeouts (milliseconds)
DEFAULT_WRITE_TIMEOUT = 100
DEFAULT_READ_TIMEOUT  = 100


class USBTransportError(Exception):
    """Base exception for USB transport failures."""


class DeviceNotFoundError(USBTransportError):
    """Raised when the SM2 Pro is not found on the USB bus."""


class DeviceNotBootedError(USBTransportError):
    """Raised when the device is found but firmware hasn't booted (needs 12V)."""


class USBTransport:
    """
    Low-level USB transport for SM2 Pro.

    Provides raw bulk read/write and control transfer access.
    Thread-safe for concurrent read/write from different threads.

    Example::

        transport = USBTransport()
        transport.open()
        transport.write(b'\\x01\\x00\\x00')
        data = transport.read(timeout_ms=500)
        transport.close()
    """

    def __init__(self, vid: int = SM2_VID, pid: int = SM2_PID,
                 bus: Optional[int] = None, address: Optional[int] = None):
        self.vid = vid
        self.pid = pid
        self.bus = bus
        self.address = address

        self._dev: Optional[usb.core.Device] = None
        self._is_open = False
        self._write_lock = threading.Lock()
        self._read_lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        return self._is_open

    def open(self) -> None:
        """
        Find and open the SM2 Pro USB device.

        Raises:
            DeviceNotFoundError: If the device is not on the bus.
            USBTransportError: If the device can't be claimed.
        """
        if self._is_open:
            return

        self._dev = self._find_device()
        if self._dev is None:
            raise DeviceNotFoundError(
                f"SM2 Pro not found (VID=0x{self.vid:04X}, PID=0x{self.pid:04X}). "
                f"Is it plugged in? On macOS/Linux, you may need sudo."
            )

        logger.info(
            "Found SM2 Pro: VID=0x%04X PID=0x%04X Bus=%d Addr=%d",
            self._dev.idVendor, self._dev.idProduct,
            self._dev.bus, self._dev.address,
        )

        # Set configuration — required on macOS for vendor-specific devices
        self._set_configuration()

        # Detach kernel driver if attached (Linux only)
        self._detach_kernel_driver()

        # Claim the interface
        try:
            usb.util.claim_interface(self._dev, 0)
            logger.debug("Claimed interface 0")
        except usb.core.USBError as e:
            raise USBTransportError(
                f"Cannot claim USB interface: {e}. "
                f"Another process may be using the device, or try sudo."
            ) from e

        self._is_open = True
        logger.info("SM2 Pro USB transport opened")

    def close(self) -> None:
        """Release the USB interface and close the device."""
        if not self._is_open:
            return

        try:
            usb.util.release_interface(self._dev, 0)
        except Exception:
            pass

        try:
            usb.util.dispose_resources(self._dev)
        except Exception:
            pass

        self._dev = None
        self._is_open = False
        logger.info("SM2 Pro USB transport closed")

    def write(self, data: bytes, timeout_ms: int = DEFAULT_WRITE_TIMEOUT) -> int:
        """
        Write data to the OUT bulk endpoint.

        Args:
            data: Bytes to send (split into 64-byte USB packets automatically).
            timeout_ms: Write timeout in milliseconds.

        Returns:
            Number of bytes written.

        Raises:
            USBTransportError: On write failure.
        """
        self._check_open()

        with self._write_lock:
            try:
                written = self._dev.write(EP_OUT, data, timeout=timeout_ms)
                logger.debug("TX %d bytes: %s", len(data), data.hex(' '))
                return written
            except usb.core.USBTimeoutError as e:
                raise USBTransportError("USB write timeout") from e
            except usb.core.USBError as e:
                raise USBTransportError(f"USB write error: {e}") from e

    def read(self, size: int = MAX_PACKET,
             timeout_ms: int = DEFAULT_READ_TIMEOUT) -> Optional[bytes]:
        """
        Read data from the IN bulk endpoint.

        Args:
            size: Maximum bytes to read (default: 64).
            timeout_ms: Read timeout in milliseconds.

        Returns:
            Received bytes, or None on timeout.
        """
        self._check_open()

        with self._read_lock:
            try:
                data = self._dev.read(EP_IN, size, timeout=timeout_ms)
                if data is not None and len(data) > 0:
                    result = bytes(data)
                    logger.debug("RX %d bytes: %s", len(result), result.hex(' '))
                    return result
                return None
            except usb.core.USBTimeoutError:
                return None
            except usb.core.USBError as e:
                if 'timeout' in str(e).lower():
                    return None
                raise USBTransportError(f"USB read error: {e}") from e

    def read_all(self, timeout_ms: int = DEFAULT_READ_TIMEOUT,
                 max_packets: int = 16) -> bytes:
        """
        Read all available data (multiple packets until timeout).

        Returns:
            All received bytes concatenated.
        """
        result = bytearray()
        for _ in range(max_packets):
            chunk = self.read(timeout_ms=timeout_ms)
            if chunk is None:
                break
            result.extend(chunk)
        return bytes(result)

    def write_read(self, data: bytes, timeout_ms: int = 300) -> Optional[bytes]:
        """
        Write data and read the response (atomic operation).

        Returns:
            Response bytes, or None if no response.
        """
        self.write(data)
        time.sleep(0.01)  # Small gap for device processing
        return self.read_all(timeout_ms=timeout_ms)

    def control_transfer(self, bmRequestType: int, bRequest: int,
                         wValue: int = 0, wIndex: int = 0,
                         data_or_wLength=None,
                         timeout_ms: int = 200) -> Optional[bytes]:
        """
        Perform a USB control transfer (EP0).

        Returns:
            Response data for IN transfers, or None.
        """
        self._check_open()

        try:
            result = self._dev.ctrl_transfer(
                bmRequestType, bRequest, wValue, wIndex,
                data_or_wLength, timeout=timeout_ms
            )
            if result is not None and len(result) > 0:
                return bytes(result)
            return None
        except usb.core.USBError:
            return None

    def reset(self) -> None:
        """Perform a USB device reset."""
        if self._dev:
            try:
                self._dev.reset()
                time.sleep(1.0)
            except usb.core.USBError as e:
                logger.warning("USB reset failed: %s", e)

    def check_firmware_booted(self) -> bool:
        """
        Check if the SM2 Pro firmware has fully booted.

        The device needs 12V on the OBD connector. On USB power alone,
        the MCU enumerates but bulk endpoints don't respond.

        Returns:
            True if firmware appears to be running.
        """
        if not self._is_open:
            return False

        try:
            self.write(bytes([0x01]), timeout_ms=100)
            time.sleep(0.1)
            resp = self.read(timeout_ms=500)
            return resp is not None
        except USBTransportError:
            return False

    # ─────────────────────────────────────────────────────
    # Private methods
    # ─────────────────────────────────────────────────────

    def _check_open(self) -> None:
        """Raise if transport is not open."""
        if not self._is_open:
            raise USBTransportError("Transport not open — call open() first")

    def _set_configuration(self) -> None:
        """Set USB configuration, with reset-and-retry fallback."""
        try:
            self._dev.get_active_configuration()
            return  # Already configured
        except usb.core.USBError:
            pass

        try:
            self._dev.set_configuration(1)
            logger.debug("Set USB configuration 1")
        except usb.core.USBError:
            # Some devices need a reset before configuration
            try:
                self._dev.reset()
                time.sleep(1.0)
                self._dev = self._find_device()
                if self._dev is None:
                    raise USBTransportError("Device disappeared after USB reset")
                self._dev.set_configuration(1)
            except usb.core.USBError as e2:
                raise USBTransportError(
                    f"Cannot set USB configuration: {e2}. Try sudo."
                ) from e2

    def _detach_kernel_driver(self) -> None:
        """Detach kernel driver from interface 0 (Linux only)."""
        try:
            if self._dev.is_kernel_driver_active(0):
                self._dev.detach_kernel_driver(0)
                logger.debug("Detached kernel driver from interface 0")
        except (usb.core.USBError, NotImplementedError):
            pass

    def _find_device(self) -> Optional[usb.core.Device]:
        """Find the SM2 Pro on the USB bus."""
        backend = self._get_backend()
        kwargs = {"idVendor": self.vid, "idProduct": self.pid}
        if backend:
            kwargs["backend"] = backend

        if self.bus is not None and self.address is not None:
            for dev in usb.core.find(find_all=True, **kwargs):
                if dev.bus == self.bus and dev.address == self.address:
                    return dev
            return None
        else:
            return usb.core.find(**kwargs)

    @staticmethod
    def _get_backend():
        """Get the best available libusb backend."""
        import usb.backend.libusb1

        for path in [
            '/opt/homebrew/lib/libusb-1.0.dylib',       # Apple Silicon Homebrew
            '/usr/local/lib/libusb-1.0.dylib',           # Intel Homebrew
            '/usr/lib/libusb-1.0.so',                    # Linux
            '/usr/lib/x86_64-linux-gnu/libusb-1.0.so',  # Debian amd64
            '/usr/lib/aarch64-linux-gnu/libusb-1.0.so',  # Debian arm64
        ]:
            try:
                be = usb.backend.libusb1.get_backend(find_library=lambda x, p=path: p)
                if be is not None:
                    return be
            except Exception:
                continue

        try:
            return usb.backend.libusb1.get_backend()
        except Exception:
            return None

    @staticmethod
    def list_devices(vid: int = SM2_VID, pid: int = SM2_PID) -> List[dict]:
        """
        List all SM2 Pro devices on the USB bus.

        Returns:
            List of dicts with bus, address, serial info.
        """
        devices = []
        try:
            for dev in usb.core.find(find_all=True, idVendor=vid, idProduct=pid):
                info = {
                    'bus': dev.bus,
                    'address': dev.address,
                    'vid': dev.idVendor,
                    'pid': dev.idProduct,
                }
                try:
                    info['manufacturer'] = dev.manufacturer
                    info['product'] = dev.product
                    info['serial'] = dev.serial_number
                except Exception:
                    pass
                devices.append(info)
        except Exception:
            pass
        return devices

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
