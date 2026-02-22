"""
SM2 Pro Command Discovery Probe.

Sends frames with command bytes 0x00-0xFF to the SM2 Pro and records
which ones generate valid responses. Discovers actual command code map.

Usage:
    python -m sm2can.tools.probe               # Full scan 0x00-0xFF
    python -m sm2can.tools.probe --range 0 32  # Scan 0x00-0x1F
    python -m sm2can.tools.probe --echo        # Find echo command
    python -m sm2can.tools.probe --cmd 0x83    # Send single command

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import sys
import time
import argparse

from sm2can.protocol import build_frame, parse_frame, HEADER_SIZE
from sm2can.usb_transport import USBTransport, USBTransportError


def hex_dump(data, max_bytes=64):
    if not data:
        return "(empty)"
    shown = data[:max_bytes]
    h = ' '.join('{:02X}'.format(b) for b in shown)
    a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in shown)
    t = " ...+{}".format(len(data) - max_bytes) if len(data) > max_bytes else ""
    return "{}  |{}|{}".format(h, a, t)


def probe_command(transport, cmd, payload=b'', timeout_ms=500):
    """Send one command and capture response."""
    frame = build_frame(cmd, payload)
    transport.flush_input()

    try:
        transport.write(frame)
    except USBTransportError:
        return {'cmd': cmd, 'error': 'write_failed'}

    time.sleep(0.02)
    rx = transport.read(4096, timeout_ms=timeout_ms)

    result = {
        'cmd': cmd,
        'tx': frame,
        'rx': rx or b'',
        'responded': rx is not None and len(rx) > 0,
    }

    if rx and len(rx) >= HEADER_SIZE:
        parsed = parse_frame(rx)
        if parsed:
            result['rx_cmd'] = parsed[0]
            result['rx_len'] = parsed[1]
            result['checksum_ok'] = parsed[2]
            result['payload'] = parsed[3]

    return result


def scan_all(transport, start=0, end=256):
    """Scan a range of command bytes."""
    print("=== SCANNING 0x{:02X}-0x{:02X} ===".format(start, end - 1))
    print("Frame: [CMD, LEN_LO, LEN_HI, CKSUM, ...PAYLOAD]")
    print("Checksum: (cmd + 0x55 + len_hi + len_lo) & 0xFF")
    print()

    valid = []
    raw_resp = []

    for cmd in range(start, end):
        r = probe_command(transport, cmd)

        if r.get('error'):
            ch = 'E'
        elif r['responded']:
            if r.get('checksum_ok'):
                ch = 'V'
                valid.append(r)
            else:
                ch = '?'
                raw_resp.append(r)
        else:
            ch = '-'

        if cmd % 16 == 0:
            sys.stdout.write("\n  0x{:02X}: ".format(cmd))
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(0.02)

    print("\n")
    print("=== RESULTS ===")
    print("Scanned: {}".format(end - start))
    print("Valid (checksum OK): {}".format(len(valid)))
    print("Raw (checksum BAD):  {}".format(len(raw_resp)))
    print()

    for r in valid:
        print("  CMD 0x{:02X} -> rx_cmd=0x{:02X} len={}".format(
            r['cmd'], r.get('rx_cmd', 0), r.get('rx_len', 0)))
        print("    TX: {}".format(hex_dump(r['tx'])))
        print("    RX: {}".format(hex_dump(r['rx'])))
        if r.get('payload'):
            print("    Payload: {}".format(hex_dump(r['payload'])))
        print()


def echo_brute(transport):
    """Brute-force find the echo command."""
    print("=== ECHO BRUTE FORCE ===")
    echo_payload = b'ECHO'

    for cmd in range(256):
        r = probe_command(transport, cmd, echo_payload, timeout_ms=2000)

        if r['responded'] and r.get('checksum_ok'):
            if r.get('payload') and echo_payload in r['payload']:
                print("  *** ECHO FOUND: 0x{:02X} ***".format(cmd))
                print("    TX: {}".format(hex_dump(r['tx'])))
                print("    RX: {}".format(hex_dump(r['rx'])))
                return cmd

            print("  Valid resp 0x{:02X}: rx_cmd=0x{:02X} len={}".format(
                cmd, r.get('rx_cmd', 0), r.get('rx_len', 0)))

        if cmd % 32 == 31:
            print("  ...through 0x{:02X}".format(cmd))
        time.sleep(0.02)

    print("  Not found")
    return None


def single_cmd(transport, cmd, payload_hex=""):
    """Send a single command."""
    payload = bytes.fromhex(payload_hex) if payload_hex else b''
    frame = build_frame(cmd, payload)

    print("=== CMD 0x{:02X} ===".format(cmd))
    print("  Frame: {}".format(hex_dump(frame)))

    transport.flush_input()
    try:
        transport.write(frame)
    except USBTransportError:
        print("  Write failed")
        return

    all_rx = bytearray()
    for i in range(5):
        rx = transport.read(4096, timeout_ms=1000)
        if rx:
            all_rx.extend(rx)
            print("  RX {}: {}".format(i, hex_dump(rx)))
        elif all_rx:
            break

    if not all_rx:
        print("  No response (timeout)")
        return

    print("  Total: {} bytes".format(len(all_rx)))
    print("  Raw: {}".format(hex_dump(bytes(all_rx))))

    if len(all_rx) >= HEADER_SIZE:
        parsed = parse_frame(bytes(all_rx))
        if parsed:
            cmd_r, ln, valid, pl = parsed
            print("  Parsed: cmd=0x{:02X} len={} cksum={}".format(
                cmd_r, ln, 'OK' if valid else 'BAD'))
            if pl:
                print("  Payload: {}".format(hex_dump(pl)))


def main():
    parser = argparse.ArgumentParser(description="SM2 Pro Command Probe")
    parser.add_argument('--range', nargs=2, type=lambda x: int(x, 0),
                        metavar=('START', 'END'))
    parser.add_argument('--echo', action='store_true')
    parser.add_argument('--cmd', type=lambda x: int(x, 0))
    parser.add_argument('--payload', type=str, default='')

    args = parser.parse_args()

    transport = USBTransport()
    try:
        transport.open()
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    try:
        if args.cmd is not None:
            single_cmd(transport, args.cmd, args.payload)
        elif args.echo:
            echo_brute(transport)
        else:
            start, end = args.range if args.range else (0, 256)
            scan_all(transport, start, end)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        transport.close()
        print("Device closed.")


if __name__ == '__main__':
    main()
