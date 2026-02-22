# Contributing to SM2CAN

The most impactful contribution is a **USB capture** from Windows.
One capture = working driver for everyone on macOS and Linux.

## USB Capture (5 minutes)

1. **Install Wireshark** on Windows — check "Install USBPcap". Reboot.
2. **Plug in SM2 Pro** via USB + connect OBD to vehicle (ignition ON).
3. **Start capture** — Wireshark → USBPcap interface → Start.
4. **Generate traffic**:
   - Open Scanmatik software (captures init handshake)
   - Connect to an ECU (captures CAN open)
   - Read some DIDs (captures CAN frames)
   - Disconnect (captures close)
5. **Save** — File → Save As → `sm2_capture.pcapng`
6. **Analyze**: `sm2can-capture decode sm2_capture.pcapng`
7. **Submit** — open an issue at https://github.com/aldoguzman97/sm2can/issues

The capture contains only USB protocol bytes — no personal data.

## Code Contributions

```bash
git clone https://github.com/aldoguzman97/sm2can.git
cd sm2can
pip install -e ".[dev]"
pytest
ruff check sm2can/
```

### Project structure

```
sm2can/
├── sm2can/
│   ├── __init__.py              # Public API
│   ├── usb_transport.py         # USB via libusb
│   ├── bluetooth_transport.py   # Bluetooth SPP (planned)
│   ├── protocol.py              # Binary protocol codec
│   ├── device.py                # High-level SM2Device
│   ├── can_interface.py         # python-can Bus plugin
│   ├── cli.py                   # CLI entry point
│   └── tools/
│       ├── probe.py             # Hardware probe
│       └── capture_decoder.py   # USB capture analyzer
├── tests/
├── scripts/99-sm2pro.rules      # Linux udev
├── Formula/sm2can.rb            # Homebrew
├── LEGAL.md                     # Clean room RE notice
└── pyproject.toml
```

### Key areas

- **Protocol decoding** — help decode commands from captures
- **Bluetooth** — implement SPP transport for original SM2 Pro
- **Testing** — test with different clones and firmware versions
- **Documentation** — platform-specific setup guides
