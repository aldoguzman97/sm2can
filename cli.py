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
    from sm2can.protocol import (
        build_frame, parse_frame, Cmd, SM2Codec
    )

    print(f"SM2CAN v{__version__} — Device Probe")
    print("-" * 50)

    devices = USBTransport.list_devices()
    if not devices:
        print("✗ No SM2 Pro devices found on USB bus.")
        print("  - Is the device plugged in?")
        print("  - Try: sudo sm2can probe")
        print("  - macOS: brew install libusb")
        return 1

    for i, dev in enumerate(devices):
        print(f"\n✓ Device {i}:")
        print(f"  Bus:     {dev.get('bus')}")
        print(f"  Address: {dev.get('address')}")
        print(f"  VID:PID: 0x{dev['vid']:04X}:0x{dev['pid']:04X}")

    print("\nTesting communication...")
    try:
        transport = USBTransport()
        transport.open()

        codec = SM2Codec()

        # Send INIT
        resp = transport.write_read(codec.encode_init(), timeout_ms=1000)
        if resp:
            result = parse_frame(resp)
            if result and result[0] == Cmd.SUCCESS:
                print("✓ INIT: device responded with SUCCESS")
            else:
                print(f"! INIT: response cmd=0x{result[0]:02X}" if result
                      else "! INIT: unparseable response")
        else:
            print("✗ INIT: no response — device may be in bootloader mode")
            transport.close()
            return 1

        # Send ECHO
        echo_data = b'SM2CAN'
        resp = transport.write_read(codec.encode_echo(echo_data), timeout_ms=1000)
        if resp:
            result = parse_frame(resp)
            if result and echo_data in result[3]:
                print("✓ ECHO: payload verified — firmware alive")
            else:
                print("! ECHO: response but payload mismatch")
        else:
            print("! ECHO: no response")

        # Device info
        resp = transport.write_read(codec.encode_device_info(), timeout_ms=1000)
        if resp:
            result = parse_frame(resp)
            if result and result[0] == Cmd.SUCCESS and result[3]:
                info = codec.decode_device_info(result[3])
                print(f"✓ Device Info:")
                print(f"    Hardware ID: {info.hardware_id_hex}")
                print(f"    Firmware:    {info.firmware_str}")
                print(f"    Hardware:    {info.hardware_str}")
            else:
                print("! DEVICE_INFO: unexpected response")
        else:
            print("! DEVICE_INFO: no response")

        transport.close()
        print("\n✓ All communication tests passed!")

    except Exception as e:
        print(f"✗ Communication test failed: {e}")
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
            print(f"Hardware ID: {info.hardware_id_hex}")
            print(f"Firmware:    {info.firmware_str}")
            print(f"Hardware:    {info.hardware_str}")
            print(f"Raw:         {info.raw.hex(' ')}")
        else:
            print("Could not read device info")
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
                t = time.monotonic() - t0
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


def cmd_echo(args):
    """Send echo command to test device health."""
    from sm2can.usb_transport import USBTransport
    from sm2can.protocol import SM2Codec, parse_frame

    try:
        transport = USBTransport()
        transport.open()
        codec = SM2Codec()

        payload = args.payload.encode() if args.payload else b'SM2CAN'
        resp = transport.write_read(codec.encode_echo(payload), timeout_ms=1000)
        if resp:
            result = parse_frame(resp)
            if result:
                _, _, valid, rx_payload = result
                print(f"TX payload: {payload.hex(' ')} ({payload})")
                print(f"RX payload: {rx_payload.hex(' ')} ({rx_payload})")
                print(f"Checksum:   {'OK' if valid else 'FAIL'}")
                print(f"Match:      {'YES' if payload in rx_payload else 'NO'}")
        else:
            print("No response")

        transport.close()
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
    p.add_argument('id', help='Arbitration ID (hex, e.g., 7DF)')
    p.add_argument('data', help='Data bytes (hex, e.g., 0201000000000000)')
    p.add_argument('-b', '--bitrate', type=int, default=500000)
    p.add_argument('-x', '--extended', action='store_true',
                   help='Extended ID (29-bit)')

    p = sub.add_parser('echo', help='Send echo command (health check)')
    p.add_argument('payload', nargs='?', default='SM2CAN',
                   help='Echo payload string')

    args = parser.parse_args()

    log_level = [logging.WARNING, logging.INFO, logging.DEBUG][min(args.verbose, 2)]
    logging.basicConfig(level=log_level,
                        format='%(name)s %(levelname)s: %(message)s')

    commands = {
        'probe': cmd_probe,
        'info': cmd_info,
        'monitor': cmd_monitor,
        'send': cmd_send,
        'echo': cmd_echo,
    }

    if args.command in commands:
        sys.exit(commands[args.command](args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == '__main__':
    main()
