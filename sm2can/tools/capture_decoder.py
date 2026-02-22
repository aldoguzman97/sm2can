"""
SM2 Pro USB capture decoder.

Parses pcap/pcapng files containing USB bulk transfers to/from
the SM2 Pro and decodes them using the confirmed protocol.

Usage:
    python -m sm2can.tools.capture_decoder capture.pcapng
    python -m sm2can.tools.capture_decoder capture.pcap --raw

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import sys
import struct
import argparse
import logging
from typing import Optional, List, Tuple

from sm2can.protocol import (
    parse_frame, verify_checksum, HEADER_SIZE, Cmd
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────
# pcap / pcapng parsers
# ─────────────────────────────────────────────────────

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAPNG_MAGIC  = 0x0A0D0D0A

# USB linktype
LINKTYPE_USB_LINUX = 189
LINKTYPE_USB_LINUX_MMAPPED = 220
LINKTYPE_USBPCAP = 249


def read_pcap(filepath: str) -> List[dict]:
    """Read a pcap file and extract USB packets."""
    with open(filepath, 'rb') as f:
        data = f.read()

    if len(data) < 24:
        raise ValueError("File too small for pcap header")

    magic = struct.unpack('<I', data[0:4])[0]
    if magic == PCAP_MAGIC_LE:
        endian = '<'
    elif magic == PCAP_MAGIC_BE:
        endian = '>'
    elif magic == PCAPNG_MAGIC:
        return read_pcapng(filepath)
    else:
        raise ValueError(f"Unknown file format (magic=0x{magic:08X})")

    # Parse global header
    _, ver_major, ver_minor, _, _, snaplen, linktype = struct.unpack(
        f'{endian}IHHiIII', data[0:24]
    )
    logger.info("pcap v%d.%d linktype=%d snaplen=%d",
                ver_major, ver_minor, linktype, snaplen)

    packets = []
    offset = 24

    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            f'{endian}IIII', data[offset:offset + 16]
        )
        offset += 16

        if offset + incl_len > len(data):
            break

        pkt_data = data[offset:offset + incl_len]
        offset += incl_len

        timestamp = ts_sec + ts_usec / 1_000_000.0

        packet = _parse_usb_packet(pkt_data, linktype, timestamp)
        if packet:
            packets.append(packet)

    return packets


def read_pcapng(filepath: str) -> List[dict]:
    """Read a pcapng file. Simplified parser for USB captures."""
    with open(filepath, 'rb') as f:
        data = f.read()

    packets = []
    offset = 0
    linktype = 0

    while offset + 12 <= len(data):
        block_type = struct.unpack('<I', data[offset:offset + 4])[0]
        block_len = struct.unpack('<I', data[offset + 4:offset + 8])[0]

        if block_len < 12 or offset + block_len > len(data):
            break

        block_body = data[offset + 8:offset + block_len - 4]

        if block_type == 0x00000001:  # IDB
            if len(block_body) >= 8:
                linktype = struct.unpack('<HH', block_body[0:4])[0]
                logger.info("Interface linktype=%d", linktype)

        elif block_type == 0x00000006:  # EPB
            if len(block_body) >= 20:
                _, ts_hi, ts_lo, cap_len, _ = struct.unpack(
                    '<IIIII', block_body[0:20]
                )
                timestamp = ((ts_hi << 32) | ts_lo) / 1_000_000.0
                pkt_data = block_body[20:20 + cap_len]

                packet = _parse_usb_packet(pkt_data, linktype, timestamp)
                if packet:
                    packets.append(packet)

        offset += block_len

    return packets


def _parse_usb_packet(data: bytes, linktype: int,
                      timestamp: float) -> Optional[dict]:
    """Parse a USB packet based on linktype."""
    if linktype == LINKTYPE_USBPCAP:
        return _parse_usbpcap(data, timestamp)
    elif linktype in (LINKTYPE_USB_LINUX, LINKTYPE_USB_LINUX_MMAPPED):
        return _parse_usb_linux(data, timestamp)
    return None


def _parse_usbpcap(data: bytes, timestamp: float) -> Optional[dict]:
    """Parse USBPcap header format."""
    if len(data) < 27:
        return None

    header_len = struct.unpack('<H', data[0:2])[0]
    if header_len > len(data):
        return None

    # function: 0x08=URB_BULK, direction: bit 0 of endpoint
    function = data[22]
    endpoint = data[21]

    if function != 0x08:  # Only bulk transfers
        return None

    direction = 'IN' if (endpoint & 0x80) else 'OUT'
    payload = data[header_len:]

    if not payload:
        return None

    return {
        'timestamp': timestamp,
        'direction': direction,
        'endpoint': endpoint,
        'data': payload,
    }


def _parse_usb_linux(data: bytes, timestamp: float) -> Optional[dict]:
    """Parse Linux USB header format."""
    if len(data) < 64:
        return None

    # URB type at offset 8: 'S'=submit, 'C'=complete
    # Transfer type at offset 9: 3=bulk
    transfer_type = data[9]
    endpoint = data[10]

    if transfer_type != 3:  # bulk only
        return None

    direction = 'IN' if (endpoint & 0x80) else 'OUT'
    payload = data[64:]

    if not payload:
        return None

    return {
        'timestamp': timestamp,
        'direction': direction,
        'endpoint': endpoint,
        'data': payload,
    }


# ─────────────────────────────────────────────────────
# Protocol decoder
# ─────────────────────────────────────────────────────

def decode_packets(packets: List[dict], show_raw: bool = False) -> None:
    """Decode and display SM2 Pro protocol frames from USB packets."""
    cmd_names = {v: v.name for v in Cmd}

    for i, pkt in enumerate(packets):
        direction = pkt['direction']
        data = pkt['data']
        ts = pkt['timestamp']

        arrow = "→" if direction == 'OUT' else "←"
        label = "TX" if direction == 'OUT' else "RX"

        if show_raw:
            hex_str = data.hex(' ')
            print(f"{ts:12.6f}  {arrow} {label} [{len(data):3d}] {hex_str}")
            continue

        # Try to parse as SM2 frame
        result = parse_frame(data)
        if result:
            cmd, length, valid, payload = result
            cmd_name = cmd_names.get(cmd, f"0x{cmd:02X}")
            ck_str = "✓" if valid else "✗"

            print(f"{ts:12.6f}  {arrow} {label} CMD={cmd_name} "
                  f"len={length} {ck_str}")

            if payload:
                print(f"              payload: {payload.hex(' ')}")
        else:
            print(f"{ts:12.6f}  {arrow} {label} [{len(data):3d}] "
                  f"{data[:16].hex(' ')}{'...' if len(data) > 16 else ''}")


def main():
    parser = argparse.ArgumentParser(
        description="SM2 Pro USB Capture Decoder"
    )
    parser.add_argument('capture', help='pcap or pcapng file')
    parser.add_argument('--raw', action='store_true',
                        help='Show raw hex instead of decoded frames')
    parser.add_argument('-v', '--verbose', action='store_true')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    try:
        packets = read_pcap(args.capture)
    except Exception as e:
        print(f"Error reading capture: {e}")
        sys.exit(1)

    print(f"Loaded {len(packets)} USB bulk packets")
    print()

    if packets:
        decode_packets(packets, show_raw=args.raw)
    else:
        print("No USB bulk transfers found in capture.")


if __name__ == '__main__':
    main()
