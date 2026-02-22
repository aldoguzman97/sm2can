"""
SM2CAN — Open-source macOS/Linux driver for SM2 Pro J2534 CAN adapters.

Copyright (c) 2026 Aldo Guzman (aldoguzman97). MIT License.

This project uses clean room reverse engineering to achieve interoperability
with legitimately purchased hardware. No proprietary code was used.
See LEGAL.md for details.

Usage with python-can:
    import can
    bus = can.Bus(interface='sm2', channel=0, bitrate=500000)
    msg = bus.recv(timeout=1.0)

Direct usage:
    from sm2can import SM2Device
    dev = SM2Device()
    dev.open(bitrate=500000)
    frame = dev.recv(timeout=1.0)
    dev.close()
"""

__version__ = "0.1.0"
__author__ = "Aldo Guzman"
__license__ = "MIT"
__copyright__ = "Copyright (c) 2026 Aldo Guzman"

from sm2can.device import SM2Device
from sm2can.can_interface import SM2Bus

__all__ = ["SM2Device", "SM2Bus", "__version__"]
