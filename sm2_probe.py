#!/usr/bin/env python3
"""SM2 Pro Command Discovery Probe"""

import argparse, sys, time

try:
    import usb.core, usb.util
except ImportError:
    print("ERROR: pip install pyusb"); sys.exit(1)

SM2_VID = 0x20A2
SM2_PID = 0x0001
CHECKSUM_SALT = 0x55
HEADER_SIZE = 4
READ_TIMEOUT_MS = 500
ECHO_TIMEOUT_MS = 2000

def build_frame(cmd, payload=b""):
    length = len(payload)
    len_lo = length & 0xFF
    len_hi = (length >> 8) & 0xFF
    checksum = (cmd + CHECKSUM_SALT + len_hi + len_lo) & 0xFF
    return bytes([cmd, len_lo, len_hi, checksum]) + payload

def parse_header(data):
    if len(data) < 4: return None, 0, False
    cmd = data[0]
    length = data[1] | (data[2] << 8)
    expected = (cmd + CHECKSUM_SALT + (length >> 8) + (length & 0xFF)) & 0xFF
    return cmd, length, (expected == data[3])

def hex_dump(data, mx=64):
    if not data: return "(empty)"
    s = data[:mx]
    h = " ".join("{:02X}".format(b) for b in s)
    a = "".join(chr(b) if 32 <= b < 127 else "." for b in s)
    t = " ...+{}".format(len(data)-mx) if len(data)>mx else ""
    return "{}  |{}|{}".format(h, a, t)

class SM2ProUSB:
    def __init__(self):
        self.dev = self.ep_out = self.ep_in = None
    def open(self):
        self.dev = usb.core.find(idVendor=SM2_VID, idProduct=SM2_PID)
        if self.dev is None:
            print("ERROR: SM2 Pro not found"); return False
        print("Found SM2 Pro: Bus {} Dev {}".format(self.dev.bus, self.dev.address))
        try: print("  Mfg: {}".format(self.dev.manufacturer))
        except: print("  Mfg: ?")
        try: print("  Product: {}".format(self.dev.product))
        except: print("  Product: ?")
        try: print("  Serial: {}".format(self.dev.serial_number))
        except: print("  Serial: ?")
        for cfg in self.dev:
            for intf in cfg:
                try:
                    if self.dev.is_kernel_driver_active(intf.bInterfaceNumber):
                        self.dev.detach_kernel_driver(intf.bInterfaceNumber)
                except: pass
        try: self.dev.set_configuration()
        except: pass
        cfg = self.dev.get_active_configuration()
        for intf in cfg:
            for ep in intf:
                d = usb.util.endpoint_direction(ep.bEndpointAddress)
                if ep.bmAttributes & 0x03 == 0x02:
                    if d == usb.util.ENDPOINT_OUT and not self.ep_out: self.ep_out = ep
                    elif d == usb.util.ENDPOINT_IN and not self.ep_in: self.ep_in = ep
        if not self.ep_out or not self.ep_in:
            print("ERROR: No bulk endpoints"); return False
        print("  EP OUT: 0x{:02X} EP IN: 0x{:02X}".format(self.ep_out.bEndpointAddress, self.ep_in.bEndpointAddress))
        return True
    def send(self, data):
        try: self.ep_out.write(data, timeout=1000); return True
        except usb.core.USBError as e: print("  Write err: {}".format(e)); return False
    def recv(self, size=4096, timeout_ms=READ_TIMEOUT_MS):
        try: return bytes(self.ep_in.read(size, timeout=timeout_ms))
        except: return b""
    def flush_input(self):
        while self.recv(4096, timeout_ms=50): pass
    def close(self):
        if self.dev: usb.util.dispose_resources(self.dev)

def probe_command(sm2, cmd, payload=b"", timeout_ms=READ_TIMEOUT_MS):
    frame = build_frame(cmd, payload)
    r = {"cmd":cmd, "tx":frame, "rx":b"", "rx_cmd":None, "rx_len":0,
         "rx_payload":b"", "cksum_ok":False, "responded":False, "error":None}
    sm2.flush_input()
    if not sm2.send(frame): r["error"]="write_failed"; return r
    rx = sm2.recv(4096, timeout_ms=timeout_ms)
    r["rx"] = rx
    if not rx: return r
    r["responded"] = True
    if len(rx) >= 4:
        rc, rl, v = parse_header(rx)
        r["rx_cmd"]=rc; r["rx_len"]=rl; r["cksum_ok"]=v
        if v and len(rx) >= 4+rl: r["rx_payload"] = rx[4:4+rl]
    return r

def scan_all(sm2, start=0, end=256):
    print("=== SCANNING 0x{:02X}-0x{:02X} ===".format(start, end-1))
    print("Frame: [CMD, LEN_LO, LEN_HI, CKSUM, ...PAYLOAD]")
    print("Checksum: (cmd + 0x55 + len_hi + len_lo) & 0xFF")
    print()
    valid = []; raw_resp = []
    for cmd in range(start, end):
        r = probe_command(sm2, cmd)
        if r["error"]: ch="E"
        elif r["responded"]:
            if r["cksum_ok"]: ch="V"; valid.append(r)
            else: ch="?"; raw_resp.append(r)
        else: ch="-"
        if cmd % 16 == 0: sys.stdout.write("\n  0x{:02X}: ".format(cmd))
        sys.stdout.write(ch); sys.stdout.flush()
        time.sleep(0.02)
    print("\n")
    print("=== RESULTS ===")
    print("Scanned: {}".format(end-start))
    print("Valid (checksum OK): {}".format(len(valid)))
    print("Raw (checksum BAD):  {}".format(len(raw_resp)))
    print()
    for r in valid:
        print("  CMD 0x{:02X} -> rx_cmd=0x{:02X} len={}".format(r["cmd"], r["rx_cmd"], r["rx_len"]))
        print("    TX: {}".format(hex_dump(r["tx"])))
        print("    RX: {}".format(hex_dump(r["rx"])))
        if r["rx_payload"]: print("    Payload: {}".format(hex_dump(r["rx_payload"])))
        print()
    for r in raw_resp:
        print("  CMD 0x{:02X} -> Raw: {}".format(r["cmd"], hex_dump(r["rx"])))

def echo_brute(sm2):
    print("=== ECHO BRUTE FORCE ===")
    for cmd in range(256):
        r = probe_command(sm2, cmd, b"ECHO", ECHO_TIMEOUT_MS)
        if r["responded"] and r["cksum_ok"]:
            if b"ECHO" in r["rx_payload"]:
                print("  *** ECHO FOUND: 0x{:02X} ***".format(cmd))
                print("    TX: {}".format(hex_dump(r["tx"])))
                print("    RX: {}".format(hex_dump(r["rx"])))
                return cmd
            print("  Valid resp 0x{:02X}: rx_cmd=0x{:02X} len={}".format(cmd, r["rx_cmd"], r["rx_len"]))
        if cmd % 32 == 31: print("  ...through 0x{:02X}".format(cmd))
        time.sleep(0.02)
    print("  Not found"); return None

def single_cmd(sm2, cmd, payload_hex=""):
    payload = bytes.fromhex(payload_hex) if payload_hex else b""
    frame = build_frame(cmd, payload)
    print("=== CMD 0x{:02X} ===".format(cmd))
    print("  Frame: {}".format(hex_dump(frame)))
    sm2.flush_input()
    if not sm2.send(frame): print("  Write failed"); return
    all_rx = bytearray()
    for i in range(5):
        rx = sm2.recv(4096, timeout_ms=1000)
        if rx: all_rx.extend(rx); print("  RX {}: {}".format(i, hex_dump(rx)))
        elif all_rx: break
    if not all_rx: print("  No response (timeout)"); return
    print("  Total: {} bytes".format(len(all_rx)))
    print("  Raw: {}".format(hex_dump(bytes(all_rx))))
    if len(all_rx) >= 4:
        rc, rl, v = parse_header(bytes(all_rx))
        print("  Parsed: cmd=0x{:02X} len={} cksum={}".format(rc, rl, "OK" if v else "BAD"))
        if v and len(all_rx)>=4+rl: print("  Payload: {}".format(hex_dump(bytes(all_rx[4:4+rl]))))

def main():
    p = argparse.ArgumentParser(description="SM2 Pro Probe")
    p.add_argument("--range", nargs=2, type=lambda x: int(x,0), metavar=("S","E"))
    p.add_argument("--echo", action="store_true")
    p.add_argument("--cmd", type=lambda x: int(x,0))
    p.add_argument("--payload", type=str, default="")
    a = p.parse_args()
    sm2 = SM2ProUSB()
    if not sm2.open(): sys.exit(1)
    try:
        if a.cmd is not None: single_cmd(sm2, a.cmd, a.payload)
        elif a.echo: echo_brute(sm2)
        else:
            s, e = a.range if a.range else (0, 256)
            scan_all(sm2, s, e)
    except KeyboardInterrupt: print(""); print("Interrupted.")
    finally: sm2.close(); print("Device closed.")

if __name__ == "__main__": main()
