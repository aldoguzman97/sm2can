# SM2CAN

Open-source macOS/Linux driver for **SM2 Pro** J2534 CAN adapters (Scanmatik).

The SM2 Pro is a professional automotive diagnostic adapter that officially supports only Windows. SM2CAN provides native macOS and Linux support via clean room reverse engineering of the USB wire protocol.

## Install

```bash
pip install sm2can
```

macOS also needs libusb:

```bash
brew install libusb
```

## Quick Start

### python-can interface

```python
import can

bus = can.Bus(interface='sm2', bitrate=500000)

# Receive
msg = bus.recv(timeout=1.0)
if msg:
    print(f"0x{msg.arbitration_id:03X}: {msg.data.hex()}")

# Send
bus.send(can.Message(arbitration_id=0x7DF,
                     data=[0x02, 0x01, 0x00, 0, 0, 0, 0, 0]))

bus.shutdown()
```

### Direct API

```python
from sm2can import SM2Device

dev = SM2Device()
dev.open(bitrate=500000)

dev.send(0x7DF, bytes([0x02, 0x01, 0x00, 0, 0, 0, 0, 0]))
frame = dev.recv(timeout=1.0)

dev.close()
```

### CLI

```bash
sm2can probe              # Detect device, test echo, show firmware info
sm2can info               # Show device info
sm2can monitor            # Live CAN bus monitor
sm2can monitor -l         # Listen-only mode
sm2can send 7DF 0201000000000000   # Send a frame
sm2can echo               # Health check
```

## Protocol

The wire protocol was reverse engineered from the official Scanmatik Android APK and confirmed via live hardware probing.

**Frame format:**

```
[CMD, LEN_LO, LEN_HI, CHECKSUM, ...PAYLOAD]

Checksum = (CMD + 0x55 + LEN_HI + LEN_LO) & 0xFF
```

**USB identifiers:** VID `0x20A2` PID `0x0001`, bulk endpoints `0x02` (OUT) and `0x81` (IN).

See [SM2_PRO_PROTOCOL_SPEC.md](SM2_PRO_PROTOCOL_SPEC.md) for the complete protocol specification.

## Hardware Requirements

- SM2 Pro adapter (Scanmatik)
- USB cable
- Vehicle connection for CAN bus operations (12V on OBD-II pin 16 powers the vehicle side, but the SM2 Pro itself boots on USB 5V)

## Project Status

| Component | Status |
|-----------|--------|
| USB transport (pyusb) | ✅ Confirmed |
| Wire protocol (frame format, checksum) | ✅ Confirmed |
| System commands (INIT, ECHO, DEVICE_INFO, CLEAR_FIFO) | ✅ Confirmed |
| CAN channel commands (0x8A-0x8F) | ⏳ Accept payloads, need vehicle bus to verify |
| python-can integration | ✅ Complete |
| Bluetooth transport | 🔧 Framework (needs pybluez) |
| CLI tools | ✅ Complete |

## Legal

This project uses clean room reverse engineering to achieve interoperability with legitimately purchased hardware. No proprietary code, firmware, or documentation was used. See [LEGAL.md](LEGAL.md) for details.

## License

MIT — Copyright (c) 2026 Aldo Guzman
