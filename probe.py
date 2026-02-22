#!/usr/bin/env python3
"""
SM2CAN Hardware Probe — Detect and test SM2 Pro hardware.

Run with: sm2can probe  (or: python3 -m sm2can.tools.probe)

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import sys
import argparse
import logging

from sm2can.usb_transport import USBTransport

logger = logging.getLogger(__name__)


def probe_device(verbose: bool = False, brute: bool = False) -> dict:
    """
    Probe an SM2 Pro device and return findings.

    Returns dict with:
      - found: bool
      - firmware_booted: bool
      - descriptors: device info dict
      - responses: probe -> response mappings
      - protocol_hint: detected protocol type
    """
    results = {
        'found': False,
        'firmware_booted': False,
        'descriptors': {},
        'responses': {},
        'protocol_hint': 'unknown',
    }

    transport = USBTransport()
    try:
        transport.open()
    except Exception as e:
        if verbose:
            print(f"Could not open device: {e}")
        return results

    results['found'] = True

    dev = transport._dev
    results['descriptors'] = {
        'vid': f"0x{dev.idVendor:04X}",
        'pid': f"0x{dev.idProduct:04X}",
        'usb_version': f"{dev.bcdUSB >> 8}.{dev.bcdUSB & 0xFF}",
        'device_class': f"0x{dev.bDeviceClass:02X}",
        'manufacturer': dev.manufacturer,
        'product': dev.product,
        'serial': dev.serial_number,
        'bus': dev.bus,
        'address': dev.address,
    }

    # Probe SLCAN
    slcan_probes = [
        (b'\r\r\r', "Triple CR"),
        (b'V\r',    "Get version"),
        (b'N\r',    "Get serial"),
        (b'F\r',    "Get status"),
    ]
    for data, desc in slcan_probes:
        resp = transport.write_read(data, timeout_ms=200)
        if resp:
            results['responses'][f'slcan_{desc}'] = resp.hex()
            results['protocol_hint'] = 'slcan'

    # Probe binary
    binary_probes = [
        bytes([0x01]),
        bytes([0xAA, 0x01, 0x01]),
        bytes([0x55, 0x01, 0x01]),
        bytes([0x00, 0x01, 0x00]),
    ]
    for data in binary_probes:
        resp = transport.write_read(data, timeout_ms=200)
        if resp:
            results['responses'][f'binary_{data.hex()}'] = resp.hex()
            results['protocol_hint'] = 'scanmatik_binary'

    results['firmware_booted'] = bool(results['responses'])

    if brute and not results['responses']:
        for b in range(256):
            resp = transport.write_read(bytes([b]), timeout_ms=50)
            if resp:
                results['responses'][f'byte_0x{b:02x}'] = resp.hex()
                results['firmware_booted'] = True

    transport.close()
    return results


def main():
    parser = argparse.ArgumentParser(description='SM2CAN hardware probe')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--brute', action='store_true', help='Byte sweep')
    parser.add_argument('--json', action='store_true', help='JSON output')
    args = parser.parse_args()

    results = probe_device(verbose=args.verbose, brute=args.brute)

    if args.json:
        import json
        print(json.dumps(results, indent=2, default=str))
        return

    if not results['found']:
        print("x SM2 Pro not found on USB bus")
        print("  Is it plugged in? Try: sudo sm2can probe")
        sys.exit(1)

    print("+ SM2 Pro detected")
    d = results['descriptors']
    print(f"  VID:PID  {d['vid']}:{d['pid']}")
    print(f"  Bus/Addr {d['bus']}/{d['address']}")
    print(f"  USB      {d['usb_version']}")

    if results['firmware_booted']:
        print(f"\n+ Firmware responding ({len(results['responses'])} responses)")
        print(f"  Protocol: {results['protocol_hint']}")
        for name, resp in list(results['responses'].items())[:10]:
            print(f"  {name}: {resp}")
    else:
        print("\n! Firmware not responding (bulk endpoints silent)")
        print("  -> Device needs 12V on OBD connector to boot")
        print("  -> Connect to vehicle or provide 12V, then re-run")


if __name__ == '__main__':
    main()
