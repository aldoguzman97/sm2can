# SM2CAN — Open-Source Driver for SM2 Pro CAN Adapters on macOS & Linux

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![PyPI](https://img.shields.io/pypi/v/sm2can)](https://pypi.org/project/sm2can/)
[![CI](https://github.com/aldoguzman97/sm2can/actions/workflows/ci.yml/badge.svg)](https://github.com/aldoguzman97/sm2can/actions)

**SM2CAN** is a userspace USB driver that enables SM2 Pro (and compatible)
J2534 CAN adapters to work on **macOS** and **Linux** — platforms the
manufacturer's driver does not support. It integrates with
[python-can](https://python-can.readthedocs.io/), making it a drop-in
replacement for any CAN interface.

> **Disclaimer:** This project is **not affiliated with, endorsed by, or
> sponsored by** the manufacturer of the SM2 Pro hardware. All trademarks
> are property of their respective owners. This driver was developed using
> [clean room reverse engineering](LEGAL.md) of a legitimately purchased
> device for the sole purpose of interoperability. See [LEGAL.md](LEGAL.md)
> for full details.

## Project Status

| Component | Status | Notes |
|-----------|--------|-------|
| USB transport (libusb) | ✅ Complete | Tested on macOS 13+ and Ubuntu 22.04+ |
| USB hardware detection | ✅ Complete | Auto-detects VID 0x20A2 PID 0x0001 |
| Protocol decoder | 🔧 Needs capture | Community USB captures welcome |
| Protocol auto-detection | ✅ Scaffolded | Tries multiple frame format variants |
| python-can `Bus` interface | ✅ Complete | `interface='sm2'` via entry point |
| CLI tools | ✅ Complete | `sm2can probe`, `monitor`, `send` |
| USB capture analysis | ✅ Complete | Parses pcap/pcapng from USBPcap |
| Homebrew formula | ✅ Ready | `brew tap aldoguzman97/sm2can` |
| Linux udev rules | ✅ Included | Non-root USB access |
| Bluetooth SPP transport | 📋 Planned | Architecture ready for future support |

### How You Can Help

**One USB capture from a Windows session completes this driver.**
If you can run Wireshark + USBPcap on Windows while connected to a vehicle:

```bash
pip install sm2can
sm2can-capture guide     # Step-by-step capture instructions
sm2can-capture decode mycapture.pcapng  # Auto-analyzes the protocol
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the 5-minute capture guide.

## Installation

### Homebrew (macOS)

```bash
brew tap aldoguzman97/sm2can
brew install sm2can
```

### pip (macOS & Linux)

```bash
pip install sm2can
```

### From source

```bash
git clone https://github.com/aldoguzman97/sm2can.git
cd sm2can
pip install -e ".[dev]"
```

### Prerequisites

| Platform | Command |
|----------|---------|
| **macOS** | `brew install libusb` |
| **Debian/Ubuntu** | `sudo apt install libusb-1.0-0-dev` |
| **Fedora/RHEL** | `sudo dnf install libusb1-devel` |
| **Arch** | `sudo pacman -S libusb` |

Python 3.8 or later required.

### Linux: USB Permissions

To use without `sudo`:

```bash
sudo cp scripts/99-sm2pro.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
# Log out and back in (user must be in 'plugdev' group)
```

## Quick Start

### Detect hardware

```bash
sm2can probe
```

### Monitor CAN bus

```bash
sm2can monitor --bitrate 500000
```

### Send a CAN frame

```bash
sm2can send 0x7DF 0201000000000000 --bitrate 500000
```

### Use with python-can

```python
import can

# SM2CAN registers as a python-can interface plugin automatically
bus = can.Bus(interface='sm2', channel=0, bitrate=500000)

# Receive
msg = bus.recv(timeout=1.0)
if msg:
    print(f"0x{msg.arbitration_id:03X}: {msg.data.hex()}")

# Send
bus.send(can.Message(
    arbitration_id=0x7DF,
    data=bytes([0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
))

bus.shutdown()
```

### Direct API

```python
from sm2can import SM2Device

with SM2Device() as dev:
    dev.open(bitrate=500000)
    dev.send(0x7DF, bytes([0x02, 0x01, 0x00, 0, 0, 0, 0, 0]))
    frame = dev.recv(timeout=1.0)
    if frame:
        print(f"0x{frame.arbitration_id:03X}: {frame.data.hex()}")
```

## Supported Hardware

| Device | USB ID | Interface | Status |
|--------|--------|-----------|--------|
| SM2 Pro (original) | `20A2:0001` | USB + BT | Primary target |
| SM2 Pro (clones) | `20A2:0001` | USB | Should work (same USB protocol) |

### Power Requirements

> **Important:** The SM2 Pro requires 12V on the OBD-II connector to boot
> its application firmware. On USB 5V power alone, the microcontroller
> enumerates on the bus but the CAN transceiver and command handler do not
> start. Connect to a vehicle with ignition ON, or supply 12V externally.

OBD-II bench power pinout:

| Pin | Function |
|-----|----------|
| 16 | +12V (battery) |
| 4 | Chassis ground |
| 5 | Signal ground |

A 12V / 1A wall adapter wired to these pins is sufficient.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Your Application / python-can / opendbc / UDS client    │
├──────────────────────────────────────────────────────────┤
│  SM2Bus (can_interface.py)                               │
│  python-can BusABC — registered via entry point          │
├──────────────────────────────────────────────────────────┤
│  SM2Device (device.py)                                   │
│  High-level: open / close / send / recv / background RX  │
├──────────────────────────────────────────────────────────┤
│  ProtocolCodec (protocol.py)                             │
│  Encode / decode binary protocol frames                  │
├────────────────────┬─────────────────────────────────────┤
│  USBTransport      │  BluetoothTransport (planned)       │
│  (usb_transport.py)│  (bluetooth_transport.py)           │
│  Bulk EP via libusb│  SPP via platform-native APIs       │
├────────────────────┴─────────────────────────────────────┤
│  Hardware: EP 0x02 OUT / EP 0x81 IN / 64-byte packets   │
└──────────────────────────────────────────────────────────┘
```

**Why userspace instead of a kernel driver?** A kernel extension (kext on
macOS, .ko on Linux) requires code signing, kernel version compatibility,
and administrator installation. A userspace driver via libusb installs with
pip, works everywhere, and cannot crash your kernel. The SM2 Pro's simple
2-endpoint bulk design is ideal for this approach.

## Roadmap

- [x] USB transport layer
- [x] Protocol codec with auto-detection framework
- [x] python-can `Bus` interface
- [x] CLI tools (`probe`, `monitor`, `send`)
- [x] USB capture decoder for protocol analysis
- [x] Homebrew formula
- [x] Linux udev rules
- [ ] Complete protocol specification (pending community captures)
- [ ] Bluetooth SPP transport
- [ ] CAN-FD support (if hardware supports it)
- [ ] ISO-TP (ISO 15765) pass-through
- [ ] SAE J2534 API shim layer

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most impactful contribution is
a USB capture from Windows — one file completes the protocol specification
for everyone.

## Legal

This project uses clean room reverse engineering to achieve interoperability
with legitimately purchased hardware. No proprietary code, firmware, or
documentation was used. See [LEGAL.md](LEGAL.md) for full details including
applicable case law.

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2026 Aldo Guzman ([@aldoguzman97](https://github.com/aldoguzman97))

## Acknowledgments

- [pyusb](https://github.com/pyusb/pyusb) — Cross-platform USB access
- [python-can](https://github.com/hardbyte/python-can) — CAN bus abstraction
- [libusb](https://libusb.info/) — Userspace USB I/O
- Everyone who contributes USB captures
