"""
python-can Bus interface for SM2 Pro.

Registers as ``interface='sm2'`` via the entry point in pyproject.toml:

    import can
    bus = can.Bus(interface='sm2', channel=0, bitrate=500000)

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import logging
from typing import Optional

import can

from sm2can.usb_transport import USBTransport
from sm2can.protocol import CANMode
from sm2can.device import SM2Device

logger = logging.getLogger(__name__)


class SM2Bus(can.BusABC):
    """
    python-can Bus implementation for the SM2 Pro.

    Parameters for ``can.Bus(interface='sm2', ...)``:

        channel (int or str):
            Device index (0 for first device) or "bus:address" string.

        bitrate (int):
            CAN bitrate in bps. Default: 500000.

        listen_only (bool):
            If True, open in listen-only mode. Default: False.

        vid (int):
            USB Vendor ID override. Default: 0x20A2.

        pid (int):
            USB Product ID override. Default: 0x0001.

    Example::

        import can
        bus = can.Bus(interface='sm2', bitrate=500000)
        msg = bus.recv(timeout=1.0)
        bus.send(can.Message(arbitration_id=0x7DF,
                             data=[0x02, 0x01, 0x00, 0, 0, 0, 0, 0]))
        bus.shutdown()
    """

    CHANNEL_TYPE = "SM2 Pro CAN"

    def __init__(self, channel=0, bitrate=500000, listen_only=False,
                 vid=0x20A2, pid=0x0001, **kwargs):
        super().__init__(channel=channel, bitrate=bitrate, **kwargs)

        self._device = SM2Device(vid=vid, pid=pid)
        self._bitrate = bitrate

        mode = CANMode.LISTEN_ONLY if listen_only else CANMode.NORMAL

        try:
            self._device.open(bitrate=bitrate, mode=mode)
        except Exception as e:
            raise can.CanInitializationError(
                f"Failed to open SM2 Pro: {e}"
            ) from e

        logger.info("SM2 Pro CAN bus opened: bitrate=%d, listen_only=%s",
                     bitrate, listen_only)

    def send(self, msg: can.Message, timeout: Optional[float] = None) -> None:
        """Send a CAN message."""
        try:
            self._device.send(
                arb_id=msg.arbitration_id,
                data=msg.data,
                is_extended_id=msg.is_extended_id,
                is_remote_frame=msg.is_remote_frame,
            )
        except Exception as e:
            raise can.CanOperationError(f"SM2 Pro send failed: {e}") from e

    def _recv_internal(self, timeout: Optional[float]):
        """
        Internal receive — called by python-can's recv().

        Returns:
            Tuple of (Message, filter_match) or (None, None).
        """
        if timeout is None:
            timeout = 1.0

        frame = self._device.recv(timeout=timeout)
        if frame is None:
            return None, False

        msg = can.Message(
            timestamp=frame.timestamp,
            arbitration_id=frame.arbitration_id,
            data=frame.data,
            is_extended_id=frame.is_extended_id,
            is_remote_frame=frame.is_remote_frame,
            channel=self.channel,
        )
        return msg, False

    def shutdown(self) -> None:
        """Close the CAN bus and release the device."""
        try:
            self._device.close()
        except Exception:
            pass
        super().shutdown()

    def __del__(self) -> None:
        try:
            self.shutdown()
        except Exception:
            pass

    @staticmethod
    def _detect_available_configs():
        """Detect available SM2 Pro devices for python-can discovery."""
        configs = []
        devices = USBTransport.list_devices()
        for i, dev_info in enumerate(devices):
            configs.append({
                'interface': 'sm2',
                'channel': i,
                'bus': dev_info.get('bus'),
                'address': dev_info.get('address'),
            })
        return configs

    @property
    def channel_info(self) -> str:
        info = self._device.device_info
        if info and info.firmware_str != "unknown":
            return f"SM2 Pro FW:{info.firmware_str}"
        return f"SM2 Pro ch={self.channel}"

    def fileno(self) -> int:
        raise NotImplementedError("SM2 Pro uses USB, not file descriptors")
