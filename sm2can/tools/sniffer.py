#!/usr/bin/env python3
"""
sm2can-sniff — CAN bus sniffer for Hyundai vehicles via SM2 Pro.

Sniffs CAN traffic, decodes known Hyundai signals, logs to CSV,
and optionally injects passive LKAS11 probes.

Built on confirmed SM2 Pro protocol (APK RE + hardware probing).

Usage:
    sm2can-sniff                                  # Default: SM2 Pro, 500kbps
    sm2can-sniff --steering                       # Only steering IDs
    sm2can-sniff --inject                         # Sniff + inject LKAS11
    sm2can-sniff --log capture.csv                # Log all frames
    sm2can-sniff --interface socketcan --channel can0  # Other adapters
    sm2can-sniff --duration 30                    # Auto-stop after 30s
    sm2can-sniff --filter 251,2B0,340             # Only specific IDs

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import argparse
import csv
import signal
import sys
import time
import threading
from collections import defaultdict
from typing import Optional, Set

try:
    import can
except ImportError:
    print("ERROR: python-can required. pip install python-can")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
# Hyundai CAN Message Database (2013 Elantra MD, comma.ai opendbc)
# ═══════════════════════════════════════════════════════════════════════════

KNOWN_IDS = {
    # Powertrain
    0x200: "EMS12",
    0x260: "WHL_SPD11",
    0x2B0: "SAS11",
    0x316: "TCS13",
    0x329: "TCS11",
    0x345: "ESP12",
    0x394: "WHL_SPD12",
    0x500: "EMS11",
    0x507: "EMS_H12",
    0x52A: "EMS16",
    0x544: "WHL_SPD13",
    0x545: "WHL_SPD14",
    # Steering
    0x251: "MDPS12",
    0x340: "LKAS11",
    # Body / Cluster
    0x381: "SCC14",
    0x386: "CLU11",
    0x4F1: "SCC11",
    0x4F2: "SCC12",
    0x553: "CLU15",
    0x5B0: "CGW1",
    0x7D0: "DIAG_REQ",
    0x7D8: "DIAG_RESP",
}

STEERING_IDS = {0x251, 0x2B0, 0x340}


# ═══════════════════════════════════════════════════════════════════════════
# Signal Decoders
# ═══════════════════════════════════════════════════════════════════════════

def decode_sas11(data: bytes) -> str:
    """SAS11 (0x2B0) — Steering Angle Sensor."""
    if len(data) < 5:
        return "[short]"
    raw = (data[1] << 8) | data[0]
    if raw > 32767:
        raw -= 65536
    angle = raw * 0.1
    rate = data[2] * 4.0
    valid = (data[3] & 0x01) == 0
    return f"angle={angle:+7.1f}° rate={rate:+5.0f}°/s valid={valid}"


def decode_mdps12(data: bytes) -> str:
    """MDPS12 (0x251) — Motor Driven Power Steering status."""
    if len(data) < 7:
        return "[short]"
    raw_col = ((data[1] & 0x1F) << 8) | data[0]
    if raw_col > 4095:
        raw_col -= 8192
    col_tq = raw_col * 0.01

    raw_out = ((data[3] & 0x1F) << 8) | data[2]
    if raw_out > 4095:
        raw_out -= 8192
    out_tq = raw_out * 0.01

    raw_drv = data[4]
    if raw_drv > 127:
        raw_drv -= 256
    drv_tq = raw_drv * 0.01

    fault = bool(data[6] & 0x20)
    return (f"col={col_tq:+6.2f}Nm out={out_tq:+6.2f}Nm "
            f"drv={drv_tq:+5.2f}Nm fault={fault}")


def decode_lkas11(data: bytes) -> str:
    """LKAS11 (0x340) — LKAS steering command."""
    if len(data) < 8:
        return "[short]"
    raw_tq = data[2] | ((data[3] & 0x07) << 8)
    torque = raw_tq - 1024
    active = bool(data[3] & 0x08)
    sys_state = (data[0] >> 2) & 0x0F
    hba = (data[3] >> 5) & 0x07
    counter = data[7] & 0x0F
    chk = (data[7] >> 4) & 0x0F
    return (f"torque={torque:+5d} active={active} sys={sys_state} "
            f"hba={hba} cnt={counter} chk=0x{chk:X}")


def decode_clu11(data: bytes) -> str:
    """CLU11 (0x386) — Cluster / vehicle speed."""
    if len(data) < 4:
        return "[short]"
    raw_spd = (data[1] << 8) | data[0]
    speed_kph = raw_spd * 0.01
    return f"speed={speed_kph:.1f} km/h"


def decode_whl_spd11(data: bytes) -> str:
    """WHL_SPD11 (0x260) — Individual wheel speeds."""
    if len(data) < 8:
        return "[short]"
    fl = ((data[1] << 8) | data[0]) * 0.03125
    fr = ((data[3] << 8) | data[2]) * 0.03125
    rl = ((data[5] << 8) | data[4]) * 0.03125
    rr = ((data[7] << 8) | data[6]) * 0.03125
    return f"FL={fl:.1f} FR={fr:.1f} RL={rl:.1f} RR={rr:.1f} km/h"


def decode_tcs13(data: bytes) -> str:
    """TCS13 (0x316) — Traction control."""
    if len(data) < 8:
        return "[short]"
    accel = ((data[1] & 0x03) << 8) | data[0]
    brake = bool(data[2] & 0x01)
    return f"accel={accel} brake={brake}"


def decode_ems11(data: bytes) -> str:
    """EMS11 (0x500) — Engine management."""
    if len(data) < 8:
        return "[short]"
    rpm = ((data[1] << 8) | data[0]) * 0.25
    return f"RPM={rpm:.0f}"


DECODERS = {
    0x251: decode_mdps12,
    0x260: decode_whl_spd11,
    0x2B0: decode_sas11,
    0x316: decode_tcs13,
    0x340: decode_lkas11,
    0x386: decode_clu11,
    0x500: decode_ems11,
}


# ═══════════════════════════════════════════════════════════════════════════
# LKAS11 Builder (for injection mode)
# ═══════════════════════════════════════════════════════════════════════════

class LKAS11Injector:
    """Builds passive LKAS11 probe frames (torque=0, active=False)."""

    def __init__(self):
        self._cnt = 0

    def build(self, torque: int = 0, active: bool = False,
              sys_state: int = 1) -> bytes:
        torque = max(-1024, min(1023, torque))
        raw = torque + 1024
        d = bytearray(8)
        d[0] = (sys_state & 0x0F) << 2
        d[2] = raw & 0xFF
        d[3] = ((raw >> 8) & 0x07) | ((1 if active else 0) << 3)
        d[7] = self._cnt & 0x0F
        chk = 0
        for b in d:
            chk ^= b
        chk = ((chk >> 4) ^ (chk & 0x0F)) & 0x0F
        d[7] = (d[7] & 0x0F) | (chk << 4)
        self._cnt = (self._cnt + 1) & 0x0F
        return bytes(d)


# ═══════════════════════════════════════════════════════════════════════════
# CAN Sniffer
# ═══════════════════════════════════════════════════════════════════════════

class CANSniffer:
    """
    CAN bus sniffer with Hyundai signal decoding.

    Features:
        - Decode known Hyundai signals (steering, wheels, engine, cluster)
        - CSV logging with timestamps
        - Per-ID statistics (count, rate, last data)
        - Filter by specific CAN IDs
        - Optional LKAS11 injection at 100Hz
        - Steering system analysis summary
    """

    def __init__(self, bus, inject: bool = False,
                 log_path: Optional[str] = None,
                 filter_ids: Optional[Set[int]] = None,
                 steering_only: bool = False,
                 quiet: bool = False):
        self.bus = bus
        self.inject = inject
        self.steering_only = steering_only
        self.quiet = quiet
        self.running = True

        # ID filter
        self.filter_ids: Optional[Set[int]] = None
        if filter_ids:
            self.filter_ids = filter_ids
        elif steering_only:
            self.filter_ids = STEERING_IDS.copy()

        # Stats
        self.stats = defaultdict(lambda: {
            "count": 0, "last_data": None,
            "first_seen": 0.0, "last_seen": 0.0,
        })
        self.total_frames = 0
        self.start_time = time.monotonic()

        # CSV logger
        self.csv_writer = None
        self._log_file = None
        if log_path:
            self._log_file = open(log_path, "w", newline="")
            self.csv_writer = csv.writer(self._log_file)
            self.csv_writer.writerow([
                "timestamp", "elapsed", "id_hex", "id_dec",
                "name", "dlc", "data_hex", "decoded",
            ])

        # Injection
        self.lkas = LKAS11Injector() if inject else None
        self.inject_count = 0
        self.inject_errors = 0
        self.last_inject = 0.0

    def run(self) -> None:
        """Main sniff loop. Blocks until Ctrl+C or self.running=False."""
        self._print_header()

        try:
            while self.running:
                # Inject LKAS11 at 100Hz
                if self.inject:
                    self._inject_tick()

                # Receive
                try:
                    msg = self.bus.recv(timeout=0.005)
                except Exception as e:
                    if self.running:
                        print(f"  RX ERROR: {e}")
                        time.sleep(0.01)
                    continue

                if msg is not None:
                    self._process(msg)

        except KeyboardInterrupt:
            pass

        self._print_summary()

        if self._log_file:
            self._log_file.close()
            print(f"Log saved: {self._log_file.name}")

    def _inject_tick(self) -> None:
        """Send one LKAS11 frame if 10ms has elapsed."""
        now = time.monotonic()
        if now - self.last_inject < 0.01:
            return
        self.last_inject = now
        try:
            frame = self.lkas.build(torque=0, active=False, sys_state=1)
            msg = can.Message(
                arbitration_id=0x340,
                data=frame,
                is_extended_id=False,
            )
            self.bus.send(msg)
            self.inject_count += 1
        except Exception as e:
            self.inject_errors += 1
            if self.inject_errors <= 3:
                print(f"  TX ERROR: {e}")

    def _process(self, msg) -> None:
        """Process one received CAN frame."""
        now = time.monotonic()
        elapsed = now - self.start_time
        aid = msg.arbitration_id
        data = bytes(msg.data)

        # Update stats (always, even if filtered from display)
        s = self.stats[aid]
        s["count"] += 1
        s["last_data"] = data
        s["last_seen"] = elapsed
        if s["count"] == 1:
            s["first_seen"] = elapsed
        self.total_frames += 1

        # Decode
        name = KNOWN_IDS.get(aid, "")
        decoded = ""
        if aid in DECODERS:
            try:
                decoded = DECODERS[aid](data)
            except Exception:
                decoded = "[decode error]"

        # CSV log (all frames, unfiltered)
        if self.csv_writer:
            self.csv_writer.writerow([
                f"{time.time():.6f}", f"{elapsed:.6f}",
                f"0x{aid:03X}", aid, name, len(data),
                data.hex(" "), decoded,
            ])

        # Display filter
        if self.filter_ids and aid not in self.filter_ids:
            return

        if self.quiet:
            return

        # Print control: first occurrence always, steering every 50th,
        # others every 100th
        is_first = s["count"] == 1
        is_steering = aid in STEERING_IDS
        count = s["count"]

        if is_first:
            pass  # Always print
        elif is_steering:
            if count % 50 != 0:
                return
        else:
            if count % 100 != 0:
                return

        marker = "*" if is_first else " "
        data_hex = data.hex(" ")
        print(f"{marker}{elapsed:8.3f}  0x{aid:03X}  {name:>10s}  "
              f"{count:6d}  {data_hex:24s}  {decoded}")

    def _print_header(self) -> None:
        print()
        print("=" * 78)
        print("  SM2CAN — CAN Bus Sniffer")
        print("=" * 78)
        if self.inject:
            print("  Mode:   SNIFF + INJECT (LKAS11 at 100Hz, torque=0)")
        else:
            print("  Mode:   LISTEN ONLY")
        if self.filter_ids:
            ids = ", ".join(f"0x{x:03X}" for x in sorted(self.filter_ids))
            print(f"  Filter: {ids}")
        if self.csv_writer:
            print(f"  Log:    {self._log_file.name}")
        print("  Stop:   Ctrl+C")
        print("=" * 78)
        print()
        print(f" {'TIME':>8s}  {'ID':>5s}  {'NAME':>10s}  {'COUNT':>6s}  "
              f"{'DATA':24s}  DECODED")
        print("-" * 78)

    def _print_summary(self) -> None:
        elapsed = time.monotonic() - self.start_time
        print()
        print("=" * 78)
        print("  SUMMARY")
        print("=" * 78)
        print(f"  Duration:     {elapsed:.1f}s")
        print(f"  Total frames: {self.total_frames}")
        if elapsed > 0:
            print(f"  Bus load:     ~{self.total_frames / elapsed:.0f} msg/s")
        if self.inject:
            print(f"  TX injected:  {self.inject_count} "
                  f"(errors: {self.inject_errors})")
        print()

        if not self.stats:
            print("  *** NO CAN FRAMES RECEIVED ***")
            print()
            print("  Troubleshooting:")
            print("    1. Is SM2 Pro connected to vehicle OBD-II port?")
            print("    2. Is ignition ON (at least ACC)?")
            print("    3. Correct bitrate? Hyundai C-CAN = 500kbps")
            print("    4. OBD-II pins 6 (CAN-H) + 14 (CAN-L) connected?")
            print()
            return

        # Per-ID table
        print(f"  {'ID':>5s}  {'NAME':>12s}  {'COUNT':>8s}  {'RATE':>8s}  "
              f"{'LAST DATA'}")
        print("  " + "-" * 68)

        for aid in sorted(self.stats.keys()):
            s = self.stats[aid]
            name = KNOWN_IDS.get(aid, "???")
            span = s["last_seen"] - s["first_seen"]
            rate = f"{s['count'] / span:.1f}/s" if span > 0.1 else "---"
            data_hex = s["last_data"].hex(" ") if s["last_data"] else ""
            flag = " <<<" if aid in STEERING_IDS else ""
            print(f"  0x{aid:03X}  {name:>12s}  {s['count']:8d}  "
                  f"{rate:>8s}  {data_hex}{flag}")

        print()
        self._steering_analysis()

    def _steering_analysis(self) -> None:
        """Analyze steering-related messages."""
        has_mdps = 0x251 in self.stats
        has_sas = 0x2B0 in self.stats
        has_lkas = 0x340 in self.stats

        print("  STEERING ANALYSIS:")

        if has_sas:
            s = self.stats[0x2B0]
            data = s["last_data"]
            if data and len(data) >= 3:
                raw = (data[1] << 8) | data[0]
                if raw > 32767:
                    raw -= 65536
                print(f"    + SAS11  (0x2B0) angle={raw * 0.1:+.1f} deg "
                      f"({s['count']} frames)")
        else:
            print("    - SAS11  (0x2B0) not found")

        if has_mdps:
            s = self.stats[0x251]
            print(f"    + MDPS12 (0x251) present ({s['count']} frames)")
        else:
            print("    - MDPS12 (0x251) not found")

        if has_lkas:
            s = self.stats[0x340]
            print(f"    ! LKAS11 (0x340) seen ({s['count']} frames)")
            if self.inject:
                print("      (includes injected frames)")
        else:
            if not self.inject:
                print("    - LKAS11 (0x340) absent (expected for 2013)")

        # Diagnostic hints
        if has_mdps and not has_sas:
            print("\n    NOTE: MDPS present but no SAS — may be diagnostic bus, "
                  "not C-CAN.")
        if not has_mdps and not has_sas and self.total_frames > 0:
            print("\n    NOTE: Traffic present but no steering messages.")
            print("    Likely on diagnostic/body bus, not C-CAN.")
            print("    Check OBD-II wiring: C-CAN uses pins 6 + 14.")

        print()


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="sm2can-sniff",
        description="CAN bus sniffer for Hyundai vehicles via SM2 Pro",
    )
    parser.add_argument("-i", "--interface", default="sm2",
                        help="python-can interface (default: sm2)")
    parser.add_argument("-c", "--channel", default="0",
                        help="CAN channel (default: 0)")
    parser.add_argument("-b", "--bitrate", type=int, default=500_000,
                        help="CAN bitrate (default: 500000)")
    parser.add_argument("--inject", action="store_true",
                        help="Inject passive LKAS11 probes at 100Hz")
    parser.add_argument("--steering", action="store_true",
                        help="Only show steering IDs (0x251, 0x2B0, 0x340)")
    parser.add_argument("--filter", type=str, default=None,
                        help="Comma-separated hex IDs to show (e.g., 251,2B0,340)")
    parser.add_argument("--log", type=str, default=None,
                        help="Log all frames to CSV file")
    parser.add_argument("--duration", type=int, default=0,
                        help="Auto-stop after N seconds (0=Ctrl+C)")
    parser.add_argument("--quiet", action="store_true",
                        help="No live output, only summary at end")
    parser.add_argument("--listen-only", action="store_true",
                        help="Open CAN in listen-only mode")

    args = parser.parse_args()

    # Parse filter IDs
    filter_ids = None
    if args.filter:
        try:
            filter_ids = {int(x.strip(), 16) for x in args.filter.split(",")}
        except ValueError:
            print(f"ERROR: Invalid filter IDs: {args.filter}")
            print("  Use hex values: --filter 251,2B0,340")
            return 1

    # Parse channel
    try:
        channel = int(args.channel)
    except ValueError:
        channel = args.channel

    # Connect
    print(f"Connecting: interface={args.interface}, channel={channel}, "
          f"bitrate={args.bitrate}...")

    bus_kwargs = {
        "interface": args.interface,
        "channel": channel,
        "bitrate": args.bitrate,
    }
    if args.listen_only:
        bus_kwargs["listen_only"] = True

    try:
        bus = can.Bus(**bus_kwargs)
    except Exception as e:
        print(f"FAILED: {e}")
        print()
        print("Troubleshooting:")
        print("  1. Is SM2 Pro connected via USB?")
        print("  2. Is sm2can installed? pip install sm2can")
        print("  3. Try with sudo for USB permissions")
        return 1

    print("Connected.")

    # Create sniffer
    sniffer = CANSniffer(
        bus,
        inject=args.inject,
        log_path=args.log,
        filter_ids=filter_ids,
        steering_only=args.steering,
        quiet=args.quiet,
    )

    # Duration timer
    if args.duration > 0:
        def stop():
            time.sleep(args.duration)
            sniffer.running = False
        threading.Thread(target=stop, daemon=True).start()

    # Run
    try:
        sniffer.run()
    finally:
        try:
            bus.shutdown()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
