#!/usr/bin/env python3
"""
SM2CAN Capture Decoder — Extract protocol from USB captures.

Takes a pcap/pcapng captured on Windows with USBPcap/Wireshark and
extracts the binary protocol: frame format, commands, checksums, timing.

No external dependencies required (parses pcap/pcapng natively).

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import sys
import struct
import argparse
import json
import os
from dataclasses import dataclass, field
from typing import Optional, List, Dict, BinaryIO
from collections import Counter


# ─────────────────────────────────────────────────────────
# PCap / PCapNG Parser
# ─────────────────────────────────────────────────────────

PCAP_MAGIC_LE    = 0xA1B2C3D4
PCAP_MAGIC_BE    = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
PCAPNG_MAGIC     = 0x0A0D0D0A
LINKTYPE_USBPCAP = 249

USBPCAP_HDR_SIZE = 27


@dataclass
class USBPacket:
    """A single USB transfer from the capture."""
    timestamp: float
    direction: str            # 'OUT' or 'IN'
    endpoint: int             # Endpoint number (without direction bit)
    transfer_type: str        # 'BULK', 'CONTROL', 'INTERRUPT', 'ISOCHRONOUS'
    data: bytes               # Transfer payload
    is_submission: bool = True  # True=submission (host request), False=completion
    setup: Optional[bytes] = None
    status: int = 0
    bus: int = 0
    device: int = 0

    @property
    def is_out(self) -> bool:
        return self.direction == 'OUT'

    @property
    def is_in(self) -> bool:
        return self.direction == 'IN'

    @property
    def is_bulk(self) -> bool:
        return self.transfer_type == 'BULK'

    @property
    def has_meaningful_data(self) -> bool:
        """True if this packet contains application-level data."""
        if not self.data:
            return False
        # OUT submissions carry data TO the device
        if self.is_out and self.is_submission:
            return True
        # IN completions carry data FROM the device
        if self.is_in and not self.is_submission:
            return True
        return False


def parse_pcap(filepath: str) -> List[USBPacket]:
    """
    Parse a pcap or pcapng file containing USBPcap data.

    Returns:
        List of USBPacket objects sorted by timestamp.
    """
    with open(filepath, 'rb') as f:
        magic = struct.unpack('<I', f.read(4))[0]
        f.seek(0)

        if magic == PCAPNG_MAGIC:
            return _parse_pcapng(f)
        elif magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            return _parse_pcap_le(f)
        elif magic == PCAP_MAGIC_BE:
            return _parse_pcap_be(f)
        else:
            raise ValueError(
                f"Unknown file format (magic: 0x{magic:08X}). "
                f"Expected pcap or pcapng from USBPcap."
            )


def _parse_pcap_le(f: BinaryIO) -> List[USBPacket]:
    """Parse classic pcap (little-endian)."""
    hdr = f.read(24)
    magic, ver_maj, ver_min, _, _, snaplen, linktype = struct.unpack(
        '<IHHiIII', hdr
    )
    _ = (ver_maj, ver_min, snaplen)  # suppress unused

    nanosecond = (magic == PCAP_MAGIC_NS_LE)

    if linktype != LINKTYPE_USBPCAP:
        raise ValueError(
            f"Not a USBPcap capture (link type {linktype}, expected {LINKTYPE_USBPCAP}). "
            f"Capture with USBPcap in Wireshark."
        )

    packets = []
    while True:
        pkt_hdr = f.read(16)
        if len(pkt_hdr) < 16:
            break

        ts_sec, ts_frac, incl_len, orig_len = struct.unpack('<IIII', pkt_hdr)
        _ = orig_len

        if nanosecond:
            timestamp = ts_sec + ts_frac * 1e-9
        else:
            timestamp = ts_sec + ts_frac * 1e-6

        pkt_data = f.read(incl_len)
        if len(pkt_data) < incl_len:
            break

        packet = _parse_usbpcap_packet(pkt_data, timestamp)
        if packet:
            packets.append(packet)

    return packets


def _parse_pcap_be(f: BinaryIO) -> List[USBPacket]:
    """Parse classic pcap (big-endian)."""
    hdr = f.read(24)
    magic, ver_maj, ver_min, _, _, snaplen, linktype = struct.unpack(
        '>IHHiIII', hdr
    )
    _ = (magic, ver_maj, ver_min, snaplen)

    if linktype != LINKTYPE_USBPCAP:
        raise ValueError(f"Not a USBPcap capture (link type {linktype})")

    packets = []
    while True:
        pkt_hdr = f.read(16)
        if len(pkt_hdr) < 16:
            break

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('>IIII', pkt_hdr)
        _ = orig_len
        timestamp = ts_sec + ts_usec * 1e-6

        pkt_data = f.read(incl_len)
        if len(pkt_data) < incl_len:
            break

        packet = _parse_usbpcap_packet(pkt_data, timestamp)
        if packet:
            packets.append(packet)

    return packets


def _parse_pcapng(f: BinaryIO) -> List[USBPacket]:
    """Parse pcapng format."""
    packets = []
    interfaces = {}
    ts_resol = 1e-6

    f.seek(0)

    while True:
        block_hdr = f.read(8)
        if len(block_hdr) < 8:
            break

        block_type, block_len = struct.unpack('<II', block_hdr)

        if block_len < 12:
            break

        block_body = f.read(block_len - 8)
        if len(block_body) < block_len - 8:
            break

        if block_type == 0x0A0D0D0A:
            pass  # Section Header Block

        elif block_type == 0x00000001:  # Interface Description Block
            if len(block_body) >= 12:
                lt, _, snaplen = struct.unpack('<HHI', block_body[:8])
                _ = snaplen
                iface_id = len(interfaces)
                interfaces[iface_id] = lt

        elif block_type == 0x00000006:  # Enhanced Packet Block
            if len(block_body) >= 24:
                iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(
                    '<IIIII', block_body[:20]
                )
                _ = orig_len

                timestamp_raw = (ts_hi << 32) | ts_lo
                timestamp = timestamp_raw * ts_resol

                pkt_data = block_body[20:20 + cap_len]

                lt = interfaces.get(iface_id, 0)
                if lt == LINKTYPE_USBPCAP:
                    packet = _parse_usbpcap_packet(pkt_data, timestamp)
                    if packet:
                        packets.append(packet)

    return packets


def _parse_usbpcap_packet(data: bytes, timestamp: float) -> Optional[USBPacket]:
    """
    Parse a single USBPcap packet.

    USBPcap header layout (27 bytes):
      Offset  Size  Field
      0       2     Header length (LE16)
      2       8     IRP ID
      10      4     USBD_STATUS (LE32)
      14      2     URB Function (LE16)
      16      1     IRP Info (bit 0: 0=submission, 1=completion)
      17      2     USB bus number (LE16)
      19      2     Device address (LE16)
      21      1     Endpoint (address with direction bit)
      22      1     Transfer type (0=ISO, 1=INT, 2=CTRL, 3=BULK)
      23      4     Data length (LE32)
    """
    if len(data) < USBPCAP_HDR_SIZE:
        return None

    hdr_len = struct.unpack('<H', data[0:2])[0]
    if hdr_len < USBPCAP_HDR_SIZE:
        return None

    status = struct.unpack('<I', data[10:14])[0]
    irp_info = data[16]
    bus = struct.unpack('<H', data[17:19])[0]
    device = struct.unpack('<H', data[19:21])[0]
    endpoint = data[21]
    transfer_type_raw = data[22]

    # Direction from endpoint address (bit 7)
    direction = 'IN' if (endpoint & 0x80) else 'OUT'
    endpoint_num = endpoint & 0x7F

    # Submission vs completion from IRP info
    is_submission = not bool(irp_info & 0x01)

    # Transfer type
    xfer_types = {0: 'ISOCHRONOUS', 1: 'INTERRUPT', 2: 'CONTROL', 3: 'BULK'}
    transfer_type = xfer_types.get(transfer_type_raw, f'UNKNOWN({transfer_type_raw})')

    # Extract payload
    payload = data[hdr_len:]

    # For control transfers, first 8 bytes of submission are the setup packet
    setup = None
    if transfer_type == 'CONTROL' and is_submission and len(payload) >= 8:
        setup = payload[:8]
        payload = payload[8:]

    # Filter: only return packets with meaningful data
    if not payload and not setup:
        return None

    return USBPacket(
        timestamp=timestamp,
        direction=direction,
        endpoint=endpoint_num,
        transfer_type=transfer_type,
        data=payload,
        is_submission=is_submission,
        setup=setup,
        status=status,
        bus=bus,
        device=device,
    )


# ─────────────────────────────────────────────────────────
# Protocol Analyzer
# ─────────────────────────────────────────────────────────

@dataclass
class TransferPair:
    """A matched OUT->IN request/response pair."""
    request: USBPacket
    response: Optional[USBPacket]
    delta_ms: float = 0.0


@dataclass
class ProtocolAnalysis:
    """Results of protocol analysis."""
    total_packets: int = 0
    bulk_out_packets: int = 0
    bulk_in_packets: int = 0
    control_packets: int = 0

    likely_header: Optional[int] = None
    likely_length_format: str = ""
    likely_checksum: str = ""
    min_frame_size: int = 0
    max_frame_size: int = 0

    init_sequence: List[bytes] = field(default_factory=list)
    command_codes: Dict[int, str] = field(default_factory=dict)

    avg_response_time_ms: float = 0.0
    init_total_time_ms: float = 0.0

    pairs: List[TransferPair] = field(default_factory=list)


class ProtocolAnalyzer:
    """
    Analyze captured USB traffic to reverse-engineer the protocol.

    Filters to meaningful data only:
    - OUT submissions (data going to device)
    - IN completions (data coming from device)
    """

    def __init__(self, packets: List[USBPacket]):
        self.packets = packets
        self.analysis = ProtocolAnalysis()

    def analyze(self) -> ProtocolAnalysis:
        """Run the full analysis pipeline."""
        a = self.analysis

        # Filter to meaningful bulk data only
        bulk_out = [p for p in self.packets
                    if p.is_bulk and p.is_out and p.has_meaningful_data]
        bulk_in = [p for p in self.packets
                   if p.is_bulk and p.is_in and p.has_meaningful_data]
        control = [p for p in self.packets if p.transfer_type == 'CONTROL']

        a.total_packets = len(self.packets)
        a.bulk_out_packets = len(bulk_out)
        a.bulk_in_packets = len(bulk_in)
        a.control_packets = len(control)

        if not bulk_out:
            return a

        # Match request/response pairs
        a.pairs = self._match_pairs(bulk_out, bulk_in)

        # Analyze frame format
        all_frames = [p.data for p in bulk_out + bulk_in if p.data]
        self._detect_frame_format(all_frames)

        # Init sequence
        a.init_sequence = [p.data for p in bulk_out[:20]]

        # Command detection
        self._detect_commands(a.pairs)

        # Timing
        if a.pairs:
            response_times = [p.delta_ms for p in a.pairs if p.response]
            if response_times:
                a.avg_response_time_ms = sum(response_times) / len(response_times)
            if len(a.pairs) >= 2:
                a.init_total_time_ms = (
                    (a.pairs[-1].request.timestamp - a.pairs[0].request.timestamp) * 1000
                )

        return a

    def _match_pairs(self, out_pkts: List[USBPacket],
                     in_pkts: List[USBPacket]) -> List[TransferPair]:
        """Match OUT requests with IN responses by timing."""
        pairs = []
        in_idx = 0

        for out_pkt in out_pkts:
            response = None
            while in_idx < len(in_pkts):
                in_pkt = in_pkts[in_idx]
                if in_pkt.timestamp >= out_pkt.timestamp:
                    delta = (in_pkt.timestamp - out_pkt.timestamp) * 1000
                    if delta < 1000:
                        response = in_pkt
                        in_idx += 1
                    break
                in_idx += 1

            delta_ms = ((response.timestamp - out_pkt.timestamp) * 1000
                       if response else 0)
            pairs.append(TransferPair(
                request=out_pkt, response=response, delta_ms=delta_ms,
            ))

        return pairs

    def _detect_frame_format(self, frames: List[bytes]) -> None:
        """Detect header byte, length encoding, and checksum."""
        a = self.analysis
        if not frames:
            return

        a.min_frame_size = min(len(f) for f in frames)
        a.max_frame_size = max(len(f) for f in frames)

        # Header detection: most common first byte
        first_bytes = Counter(f[0] for f in frames if f)
        total = len(frames)
        for byte_val, count in first_bytes.most_common(5):
            if count > total * 0.6:
                a.likely_header = byte_val
                break

        # Length format detection
        self._detect_length_format(frames)

        # Checksum detection
        self._detect_checksum(frames)

    def _detect_length_format(self, frames: List[bytes]) -> None:
        """Detect how length is encoded."""
        a = self.analysis
        offset = 1 if a.likely_header is not None else 0

        def extract_8bit(f: bytes) -> int:
            return f[offset] if len(f) > offset else -1

        def extract_be16(f: bytes) -> int:
            if len(f) > offset + 1:
                return struct.unpack('>H', f[offset:offset + 2])[0]
            return -1

        def extract_le16(f: bytes) -> int:
            if len(f) > offset + 1:
                return struct.unpack('<H', f[offset:offset + 2])[0]
            return -1

        extractors = [
            ("8bit", extract_8bit),
            ("BE16", extract_be16),
            ("LE16", extract_le16),
        ]

        scores: Dict[str, int] = {}
        for fmt_name, extract_fn in extractors:
            matches = 0
            for frame in frames:
                length_val = extract_fn(frame)
                if length_val < 0:
                    continue
                actual_len = len(frame)
                for adj in [0, -1, -2, -3, -4, -5]:
                    if length_val == actual_len + adj:
                        matches += 1
                        break
            scores[fmt_name] = matches

        if scores:
            best = max(scores, key=scores.get)
            if scores[best] > len(frames) * 0.5:
                a.likely_length_format = best

    def _detect_checksum(self, frames: List[bytes]) -> None:
        """Detect checksum algorithm."""
        a = self.analysis

        def xor_all(data: bytes) -> int:
            r = 0
            for b in data:
                r ^= b
            return r

        algorithms = {
            'XOR': lambda d: xor_all(d),
            'SUM': lambda d: sum(d) & 0xFF,
            'SUM_NEG': lambda d: (-sum(d)) & 0xFF,
            'XOR_FF': lambda d: xor_all(d) ^ 0xFF,
        }

        scores: Dict[str, int] = {name: 0 for name in algorithms}

        for frame in frames:
            if len(frame) < 2:
                continue
            last_byte = frame[-1]
            body = frame[:-1]
            for name, fn in algorithms.items():
                if fn(body) == last_byte:
                    scores[name] += 1

        if scores:
            best = max(scores, key=scores.get)
            if scores[best] > len(frames) * 0.5:
                a.likely_checksum = best
            elif scores[best] > len(frames) * 0.25:
                a.likely_checksum = f"{best}?"

    def _detect_commands(self, pairs: List[TransferPair]) -> None:
        """Identify command bytes by frequency."""
        a = self.analysis
        if not pairs:
            return

        cmd_offset = 1 if a.likely_header is not None else 0
        if 'BE16' in a.likely_length_format or 'LE16' in a.likely_length_format:
            cmd_offset += 2
        elif '8bit' in a.likely_length_format:
            cmd_offset += 1

        cmd_counts: Counter = Counter()
        for pair in pairs:
            if len(pair.request.data) > cmd_offset:
                cmd = pair.request.data[cmd_offset]
                cmd_counts[cmd] += 1

        for cmd, count in cmd_counts.most_common():
            if count <= 3:
                a.command_codes[cmd] = "INIT/CONFIG"
            else:
                a.command_codes[cmd] = f"DATA/CAN ({count}x)"


# ─────────────────────────────────────────────────────────
# Code Generator
# ─────────────────────────────────────────────────────────

def generate_protocol_code(analysis: ProtocolAnalysis) -> str:
    """Generate Python code for protocol constants."""
    lines = [
        '"""',
        'Auto-generated protocol constants from USB capture analysis.',
        f'Total packets analyzed: {analysis.total_packets}',
        f'Bulk OUT: {analysis.bulk_out_packets}, Bulk IN: {analysis.bulk_in_packets}',
        f'Average response time: {analysis.avg_response_time_ms:.1f} ms',
        '"""',
        '',
    ]

    if analysis.likely_header is not None:
        lines.append(f'HEADER_BYTE = 0x{analysis.likely_header:02X}')
    else:
        lines.append('HEADER_BYTE = None  # No consistent header detected')

    lines.append(f'LENGTH_FORMAT = "{analysis.likely_length_format}"')
    lines.append(f'CHECKSUM_ALGO = "{analysis.likely_checksum}"')
    lines.append(f'MIN_FRAME_SIZE = {analysis.min_frame_size}')
    lines.append(f'MAX_FRAME_SIZE = {analysis.max_frame_size}')
    lines.append('')

    if analysis.command_codes:
        lines.append('COMMANDS = {')
        for cmd, desc in sorted(analysis.command_codes.items()):
            lines.append(f'    0x{cmd:02X}: "{desc}",')
        lines.append('}')
        lines.append('')

    if analysis.init_sequence:
        lines.append('INIT_SEQUENCE = [')
        for i, frame in enumerate(analysis.init_sequence[:10]):
            hex_str = ', '.join(f'0x{b:02X}' for b in frame)
            lines.append(f'    bytes([{hex_str}]),  # Step {i}')
        lines.append(']')

    return '\n'.join(lines)


# ─────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────

def print_report(analysis: ProtocolAnalysis, verbose: bool = False) -> None:
    """Print human-readable analysis report."""
    a = analysis

    print("\n" + "=" * 70)
    print("  SM2CAN Protocol Analysis Report")
    print("=" * 70)

    print(f"\n  Packets:    {a.total_packets} total")
    print(f"  Bulk OUT:   {a.bulk_out_packets} (host -> device)")
    print(f"  Bulk IN:    {a.bulk_in_packets} (device -> host)")
    print(f"  Control:    {a.control_packets}")

    print(f"\n{'-' * 70}")
    print("  FRAME FORMAT")
    print(f"{'-' * 70}")

    if a.likely_header is not None:
        print(f"  Header byte:    0x{a.likely_header:02X}")
    else:
        print("  Header byte:    NOT DETECTED")

    print(f"  Length format:  {a.likely_length_format or 'NOT DETECTED'}")
    print(f"  Checksum:       {a.likely_checksum or 'NOT DETECTED'}")
    print(f"  Frame sizes:    {a.min_frame_size} - {a.max_frame_size} bytes")

    print(f"\n{'-' * 70}")
    print("  TIMING")
    print(f"{'-' * 70}")
    print(f"  Avg response:   {a.avg_response_time_ms:.1f} ms")
    print(f"  Init duration:  {a.init_total_time_ms:.0f} ms")

    if a.command_codes:
        print(f"\n{'-' * 70}")
        print("  DETECTED COMMANDS")
        print(f"{'-' * 70}")
        for cmd, desc in sorted(a.command_codes.items()):
            print(f"  0x{cmd:02X}  ->  {desc}")

    if a.pairs and verbose:
        print(f"\n{'-' * 70}")
        print("  TRANSACTION LOG")
        print(f"{'-' * 70}")
        t0 = a.pairs[0].request.timestamp if a.pairs else 0
        for i, pair in enumerate(a.pairs[:100]):
            t = (pair.request.timestamp - t0) * 1000
            req_hex = pair.request.data[:32].hex(' ')
            print(f"  {i:4d}  {t:7.1f}ms  OUT  {req_hex}")
            if pair.response:
                resp_hex = pair.response.data[:32].hex(' ')
                print(f"  {'':4s}  {'':7s}    IN   {pair.delta_ms:5.1f}ms  {resp_hex}")

    if a.init_sequence:
        print(f"\n{'-' * 70}")
        print("  INIT SEQUENCE (first 10 OUT transfers)")
        print(f"{'-' * 70}")
        for i, frame in enumerate(a.init_sequence[:10]):
            hex_str = frame.hex(' ')
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in frame)
            print(f"  [{i:2d}] {hex_str}")
            print(f"       ASCII: {ascii_str}")

    print(f"\n{'=' * 70}")


def print_capture_guide() -> None:
    """Print USB capture instructions."""
    print("""
=== HOW TO CAPTURE SM2 PRO USB TRAFFIC ON WINDOWS ===

This is the ONE thing needed to complete the macOS/Linux driver.
Takes about 5 minutes.

WHAT YOU NEED:
  - Windows PC (or VM with USB passthrough)
  - SM2 Pro plugged in via USB
  - SM2 Pro connected to vehicle (or 12V power on OBD)
  - Wireshark with USBPcap (free: https://www.wireshark.org)

STEPS:

  1. Install Wireshark — check "Install USBPcap" during setup. Reboot.

  2. Open Wireshark, select the USBPcap interface, start capture.

  3. Open Scanmatik software (captures init handshake).

  4. Connect to any ECU, read a few DIDs (captures CAN frames).

  5. Disconnect, close software (captures shutdown).

  6. Stop capture, save as .pcapng.

  7. Analyze:
       sm2can-capture decode mycapture.pcapng

  8. Submit to: https://github.com/aldoguzman97/sm2can/issues
     (contains only USB protocol bytes, no personal data)

FILTER (optional):
  In Wireshark: usb.idVendor == 0x20a2

ALTERNATIVE — USBPcap standalone:
  USBPcapCMD.exe -d "\\\\.\\USB#VID_20A2&PID_0001" -o capture.pcap

ALTERNATIVE — Linux usbmon:
  sudo modprobe usbmon
  sudo cat /sys/kernel/debug/usb/usbmon/2u > capture.txt &
  # Run Scanmatik under Wine, then Ctrl+C
""")


# ─────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='sm2can-capture',
        description='SM2CAN USB capture analysis and protocol decoder',
    )
    sub = parser.add_subparsers(dest='command')

    p = sub.add_parser('decode', help='Decode a USB capture file')
    p.add_argument('capture_file', help='Path to .pcap or .pcapng')
    p.add_argument('-v', '--verbose', action='store_true',
                  help='Show full transaction log')
    p.add_argument('-o', '--output', help='Write protocol code to file')
    p.add_argument('--json', help='Write analysis as JSON')

    sub.add_parser('guide', help='Show USB capture instructions')

    args = parser.parse_args()

    if args.command == 'guide':
        print_capture_guide()
        return 0

    elif args.command == 'decode':
        if not os.path.exists(args.capture_file):
            print(f"Error: File not found: {args.capture_file}")
            return 1

        print(f"Parsing {args.capture_file}...")
        try:
            packets = parse_pcap(args.capture_file)
        except Exception as e:
            print(f"Error parsing capture: {e}")
            return 1

        print(f"Loaded {len(packets)} USB packets")

        analyzer = ProtocolAnalyzer(packets)
        analysis = analyzer.analyze()

        print_report(analysis, verbose=args.verbose)

        code = generate_protocol_code(analysis)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(code)
            print(f"\nProtocol code written to: {args.output}")
        else:
            print(f"\n{'-' * 70}")
            print("  GENERATED CODE (paste into sm2can/protocol.py)")
            print(f"{'-' * 70}")
            print(code)

        if args.json:
            data = {
                'total_packets': analysis.total_packets,
                'bulk_out': analysis.bulk_out_packets,
                'bulk_in': analysis.bulk_in_packets,
                'likely_header': analysis.likely_header,
                'likely_length_format': analysis.likely_length_format,
                'likely_checksum': analysis.likely_checksum,
                'command_codes': {f'0x{k:02X}': v
                                 for k, v in analysis.command_codes.items()},
                'init_sequence': [f.hex() for f in analysis.init_sequence[:10]],
                'avg_response_time_ms': analysis.avg_response_time_ms,
            }
            with open(args.json, 'w') as outf:
                json.dump(data, outf, indent=2)
            print(f"JSON written to: {args.json}")

        return 0

    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
