"""
SM2CAN command-line interface.

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import sys
import time
import argparse
import logging

from sm2can import __version__


def cmd_probe(args):
    """Probe for SM2 Pro devices and test communication."""
    from sm2can.usb_transport import USBTransport

    print(f"SM2CAN v{__version__} — Device Probe")
    print("-" * 50)

    devices = USBTransport.list_devices()
    if not devices:
        print("x No SM2 Pro devices found on USB bus.")
        print("  - Is the device plugged in?")
        print("  - Try: sudo sm2can probe")
        print("  - macOS: brew install libusb")
        return 1

    for i, dev in enumerate(devices):
        print(f"\n+ Device {i}:")
        print(f"  Bus:     {dev.get('bus')}")
        print(f"  Address: {dev.get('address')}")
        print(f"  VID:PID: 0x{dev['vid']:04X}:0x{dev['pid']:04X}")
        if dev.get('serial'):
            print(f"  Serial:  {dev['serial']}")

    print("\nTesting communication...")
    try:
        transport = USBTransport()
        transport.open()

        booted = transport.check_firmware_booted()
        if booted:
            print("+ Firmware is running (bulk endpoints responding)")

            from sm2can.protocol import ProtocolDetector
            detector = ProtocolDetector(transport)
            codec = detector.detect()
            if codec:
                print("+ Protocol detected successfully!")
            else:
                print("! Could not auto-detect protocol variant")
        else:
            print("! Firmware not responding (device needs 12V on OBD)")
            print("  Connect to vehicle or provide 12V, then retry.")

        transport.close()
    except Exception as e:
        print(f"x Communication test failed: {e}")
        return 1

    return 0


def cmd_info(args):
    """Show device information."""
    from sm2can import SM2Device

    try:
        dev = SM2Device()
        dev.open(bitrate=args.bitrate)
        info = dev.device_info
        if info:
            print(f"Firmware: {info.firmware_version or '(pending protocol decode)'}")
            print(f"Hardware: {info.hardware_version or '(pending protocol decode)'}")
            print(f"Serial:   {info.serial_number or '(pending protocol decode)'}")
            voltage = dev.get_voltage()
            if voltage > 0:
                print(f"Voltage:  {voltage:.1f} V")
        else:
            print("Could not read device info (protocol not yet decoded)")
        dev.close()
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0


def cmd_monitor(args):
    """Monitor CAN bus traffic."""
    import can

    print(f"SM2CAN v{__version__} — CAN Bus Monitor")
    print(f"Bitrate: {args.bitrate} bps")
    print("-" * 60)
    print(f"{'Time':>10s}  {'ID':>6s}  {'DLC':>3s}  {'Data':24s}")
    print("-" * 60)

    try:
        bus = can.Bus(interface='sm2', bitrate=args.bitrate,
                     listen_only=args.listen_only)
    except Exception as e:
        print(f"Error opening CAN bus: {e}")
        return 1

    count = 0
    t0 = time.monotonic()

    try:
        while True:
            msg = bus.recv(timeout=1.0)
            if msg:
                t = msg.timestamp - t0 if t0 else msg.timestamp
                data_hex = msg.data.hex(' ') if msg.data else ''
                ext = 'X' if msg.is_extended_id else ' '
                print(f"{t:10.3f}  0x{msg.arbitration_id:03X}{ext}  "
                      f"{len(msg.data):3d}  {data_hex:24s}")
                count += 1
                if args.count and count >= args.count:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        elapsed = time.monotonic() - t0
        if elapsed > 0:
            print(f"\n{count} messages in {elapsed:.1f}s "
                  f"({count / elapsed:.1f} msg/s)")
        bus.shutdown()

    return 0


def cmd_send(args):
    """Send a CAN frame."""
    import can

    arb_id = int(args.id, 16)
    data = bytes.fromhex(args.data)

    try:
        bus = can.Bus(interface='sm2', bitrate=args.bitrate)
        msg = can.Message(
            arbitration_id=arb_id,
            data=data,
            is_extended_id=args.extended,
        )
        bus.send(msg)
        print(f"Sent: 0x{arb_id:03X} [{len(data)}] {data.hex(' ')}")
        bus.shutdown()
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog='sm2can',
        description=f'SM2CAN v{__version__} — SM2 Pro CAN adapter driver',
    )
    parser.add_argument('-v', '--verbose', action='count', default=0,
                       help='Increase verbosity (-v, -vv, -vvv)')
    parser.add_argument('--version', action='version',
                       version=f'sm2can {__version__}')

    sub = parser.add_subparsers(dest='command')

    sub.add_parser('probe', help='Detect and probe SM2 Pro hardware')

    p = sub.add_parser('info', help='Show device information')
    p.add_argument('-b', '--bitrate', type=int, default=500000)

    p = sub.add_parser('monitor', help='Monitor CAN bus traffic')
    p.add_argument('-b', '--bitrate', type=int, default=500000)
    p.add_argument('-n', '--count', type=int, default=None,
                  help='Stop after N messages')
    p.add_argument('-l', '--listen-only', action='store_true',
                  help='Listen-only mode (no TX)')

    p = sub.add_parser('send', help='Send a CAN frame')
    p.add_argument('id', help='Arbitration ID (hex, e.g., 0x7DF)')
    p.add_argument('data', help='Data bytes (hex, e.g., 0201000000000000)')
    p.add_argument('-b', '--bitrate', type=int, default=500000)
    p.add_argument('-x', '--extended', action='store_true',
                  help='Extended ID (29-bit)')

    args = parser.parse_args()

    log_level = [logging.WARNING, logging.INFO, logging.DEBUG][min(args.verbose, 2)]
    logging.basicConfig(level=log_level, format='%(name)s %(levelname)s: %(message)s')

    commands = {
        'probe': cmd_probe,
        'info': cmd_info,
        'monitor': cmd_monitor,
        'send': cmd_send,
    }

    if args.command in commands:
        sys.exit(commands[args.command](args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == '__main__':
    main()
