"""
USB Transport Layer for SM2 Pro hardware.

Handles raw USB communication via libusb (pyusb). No kernel driver required.
Works on macOS and Linux.

Hardware profile (confirmed via probing 2026-02-22):
  - VID: 0x20A2  PID: 0x0001
  - Device Class: 0xFF (Vendor Specific)
  - Speed: Full Speed (12 Mb/s)
  - Interface 0: 2 Bulk endpoints
    - EP 0x81 IN  (device → host)
    - EP 0x02 OUT (host → device)
  - Powers up on USB 5V alone (no 12V required for firmware boot)
  - Manufacturer/Product/Serial strings: None (not populated in descriptor)

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import time
import logging
import threading
from typing import Optional, List

import usb.core
import usb.util

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────
# Constants — CONFIRMED from hardware probing
# ─────────────────────────────────────────────────────
SM2_VID = 0x20A2
SM2_PID = 0x0001

EP_IN  = 0x81   # Bulk IN endpoint address (confirmed)
EP_OUT = 0x02   # Bulk OUT endpoint address (confirmed)

MAX_PACKET = 64  # USB full-speed bulk max packet size

# Timeouts (milliseconds)
DEFAULT_WRITE_TIMEOUT = 1000
DEFAULT_READ_TIMEOUT  = 500


class USBTransportError(Exception):
    """Base exception for USB transport failures."""


class DeviceNotFoundError(USBTransportError):
    """Raised when the SM2 Pro is not found on the USB bus."""


class USBTransport:
    """
    Low-level USB transport for SM2 Pro.

    Provides raw bulk read/write access. Thread-safe for concurrent
    read/write from different threads.

    Example::

        transport = USBTransport()
        transport.open()
        transport.write(b'\\x88\\x00\\x00\\xDD')  # INIT command
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
        self._ep_out = None
        self._ep_in = None
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
            "Found SM2 Pro: VID=0x%04X PID=0x%04X Bus=%s Addr=%s",
            self._dev.idVendor, self._dev.idProduct,
            self._dev.bus, self._dev.address,
        )

        # Detach kernel driver if attached (Linux)
        self._detach_kernel_driver()

        # Set configuration
        self._set_configuration()

        # Find bulk endpoints
        self._find_endpoints()

        self._is_open = True
        logger.info("SM2 Pro USB transport opened (EP OUT=0x%02X, EP IN=0x%02X)",
                     self._ep_out.bEndpointAddress, self._ep_in.bEndpointAddress)

    def close(self) -> None:
        """Release the USB device."""
        if not self._is_open:
            return

        try:
            usb.util.dispose_resources(self._dev)
        except Exception:
            pass

        self._dev = None
        self._ep_out = None
        self._ep_in = None
        self._is_open = False
        logger.info("SM2 Pro USB transport closed")

    def write(self, data: bytes, timeout_ms: int = DEFAULT_WRITE_TIMEOUT) -> int:
        """
        Write data to the OUT bulk endpoint.

        Returns:
            Number of bytes written.

        Raises:
            USBTransportError: On write failure.
        """
        self._check_open()

        with self._write_lock:
            try:
                written = self._ep_out.write(data, timeout=timeout_ms)
                logger.debug("TX %d bytes: %s", len(data), data.hex(' '))
                return written
            except usb.core.USBTimeoutError as e:
                raise USBTransportError("USB write timeout") from e
            except usb.core.USBError as e:
                raise USBTransportError(f"USB write error: {e}") from e

    def read(self, size: int = 4096,
             timeout_ms: int = DEFAULT_READ_TIMEOUT) -> Optional[bytes]:
        """
        Read data from the IN bulk endpoint.

        Returns:
            Received bytes, or None on timeout.
        """
        self._check_open()

        with self._read_lock:
            try:
                data = self._ep_in.read(size, timeout=timeout_ms)
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
        """Read all available data (multiple packets until timeout)."""
        result = bytearray()
        for _ in range(max_packets):
            chunk = self.read(timeout_ms=timeout_ms)
            if chunk is None:
                break
            result.extend(chunk)
        return bytes(result)

    def write_read(self, data: bytes, timeout_ms: int = 500) -> Optional[bytes]:
        """Write data and read the response (atomic operation)."""
        self.flush_input()
        self.write(data)
        time.sleep(0.02)
        return self.read_all(timeout_ms=timeout_ms)

    def flush_input(self) -> int:
        """Drain any pending data from the IN endpoint."""
        drained = 0
        while True:
            chunk = self.read(4096, timeout_ms=50)
            if chunk is None:
                break
            drained += len(chunk)
        if drained:
            logger.debug("Flushed %d bytes from input", drained)
        return drained

    # ─────────────────────────────────────────────────────
    # Private methods
    # ─────────────────────────────────────────────────────

    def _check_open(self) -> None:
        if not self._is_open:
            raise USBTransportError("Transport not open — call open() first")

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

    def _set_configuration(self) -> None:
        """Set USB configuration."""
        try:
            self._dev.set_configuration()
        except usb.core.USBError:
            pass  # May already be configured

    def _detach_kernel_driver(self) -> None:
        """Detach kernel driver from all interfaces (Linux)."""
        for cfg in self._dev:
            for intf in cfg:
                try:
                    if self._dev.is_kernel_driver_active(intf.bInterfaceNumber):
                        self._dev.detach_kernel_driver(intf.bInterfaceNumber)
                        logger.debug("Detached kernel driver from interface %d",
                                     intf.bInterfaceNumber)
                except (usb.core.USBError, NotImplementedError):
                    pass

    def _find_endpoints(self) -> None:
        """Find bulk IN and OUT endpoints."""
        cfg = self._dev.get_active_configuration()

        for intf in cfg:
            for ep in intf:
                direction = usb.util.endpoint_direction(ep.bEndpointAddress)
                transfer_type = ep.bmAttributes & 0x03
                if transfer_type == 0x02:  # Bulk
                    if (direction == usb.util.ENDPOINT_OUT
                            and self._ep_out is None):
                        self._ep_out = ep
                    elif (direction == usb.util.ENDPOINT_IN
                          and self._ep_in is None):
                        self._ep_in = ep

        if not self._ep_out or not self._ep_in:
            raise USBTransportError(
                "Could not find bulk IN/OUT endpoints. "
                "Device may be in bootloader mode."
            )

    @staticmethod
    def _get_backend():
        """Get the best available libusb backend."""
        try:
            import usb.backend.libusb1
        except ImportError:
            return None

        for path in [
            '/opt/homebrew/lib/libusb-1.0.dylib',       # Apple Silicon Homebrew
            '/usr/local/lib/libusb-1.0.dylib',           # Intel Homebrew
            '/usr/lib/libusb-1.0.so',                    # Linux
            '/usr/lib/x86_64-linux-gnu/libusb-1.0.so',   # Debian amd64
            '/usr/lib/aarch64-linux-gnu/libusb-1.0.so',  # Debian arm64
        ]:
            try:
                be = usb.backend.libusb1.get_backend(
                    find_library=lambda x, p=path: p
                )
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
            List of dicts with bus, address info.
        """
        devices = []
        try:
            for dev in usb.core.find(find_all=True,
                                     idVendor=vid, idProduct=pid):
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
