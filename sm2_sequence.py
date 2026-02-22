#!/usr/bin/env python3
"""SM2 Pro sequence probe - sends multi-command sequences in one USB session."""

import sys, time
try:
    import usb.core, usb.util
except ImportError:
    print("pip install pyusb"); sys.exit(1)

SALT = 0x55

def frame(cmd, payload=b''):
    ln = len(payload)
    lo, hi = ln & 0xFF, (ln >> 8) & 0xFF
    ck = (cmd + SALT + hi + lo) & 0xFF
    return bytes([cmd, lo, hi, ck]) + payload

def parse(data):
    if len(data) < 4: return None, 0, False, b''
    c = data[0]; ln = data[1] | (data[2] << 8)
    ok = ((c + SALT + (ln >> 8) + (ln & 0xFF)) & 0xFF) == data[3]
    pl = data[4:4+ln] if ok and len(data) >= 4+ln else b''
    return c, ln, ok, pl

def hx(data):
    return ' '.join('{:02X}'.format(b) for b in data) if data else '(empty)'

class SM2:
    def __init__(self):
        self.dev = usb.core.find(idVendor=0x20A2, idProduct=0x0001)
        if not self.dev: print("SM2 Pro not found"); sys.exit(1)
        for c in self.dev:
            for i in c:
                try:
                    if self.dev.is_kernel_driver_active(i.bInterfaceNumber):
                        self.dev.detach_kernel_driver(i.bInterfaceNumber)
                except: pass
        try: self.dev.set_configuration()
        except: pass
        cfg = self.dev.get_active_configuration()
        self.epo = self.epi = None
        for i in cfg:
            for e in i:
                d = usb.util.endpoint_direction(e.bEndpointAddress)
                if e.bmAttributes & 3 == 2:
                    if d == usb.util.ENDPOINT_OUT and not self.epo: self.epo = e
                    elif d == usb.util.ENDPOINT_IN and not self.epi: self.epi = e
        print("SM2 Pro connected: EP OUT=0x{:02X} IN=0x{:02X}".format(
            self.epo.bEndpointAddress, self.epi.bEndpointAddress))

    def send(self, cmd, payload=b''):
        f = frame(cmd, payload)
        self.epo.write(f, timeout=1000)
        return f

    def recv(self, timeout=500):
        try: return bytes(self.epi.read(4096, timeout=timeout))
        except: return b''

    def flush(self):
        while self.recv(50): pass

    def cmd(self, cmd, payload=b'', label="", timeout=500):
        self.flush()
        f = self.send(cmd, payload)
        time.sleep(0.02)
        rx = self.recv(timeout)
        rc, rl, ok, pl = parse(rx) if rx else (None, 0, False, b'')
        tag = " [{}]".format(label) if label else ""
        print("  TX 0x{:02X}: {}{}".format(cmd, hx(f), tag))
        if rx:
            print("  RX:      {} (cmd=0x{:02X} len={} {})".format(
                hx(rx), rc, rl, "OK" if ok else "BAD"))
            if pl: print("  Payload: {}".format(hx(pl)))
        else:
            print("  RX:      (no response)")
        print()
        return rc, rl, ok, pl

    def close(self):
        usb.util.dispose_resources(self.dev)

def main():
    s = SM2()
    print()
    print("=== SEQUENCE 1: Init then probe channel commands ===")
    s.cmd(0x88, label="INIT")
    s.cmd(0x86, label="CLEAR FIFO")
    # Try 0x8A-0x8F with payloads after init
    for c in range(0x8A, 0x90):
        s.cmd(c, b'\x00', label="1-byte payload")
    print()

    print("=== SEQUENCE 2: Init + CAN baud payloads on 0x8A ===")
    s.cmd(0x88, label="INIT")
    # Try different payload sizes for 0x8A
    s.cmd(0x8A, b'\x05', label="J2534 CAN proto=5")
    s.cmd(0x8A, b'\x05\x00\x00\x00', label="proto=5 + pad")
    s.cmd(0x8A, b'\x05\x20\xA1\x07\x00', label="proto=5 baud=500k")
    s.cmd(0x8A, b'\x00\x20\xA1\x07\x00', label="ch=0 baud=500k")
    s.cmd(0x8A, b'\x00\x00\x20\xA1\x07\x00', label="ch=0 proto=0 baud=500k")
    print()

    print("=== SEQUENCE 3: Try 0x84/0x85/0x89 with init state ===")
    s.cmd(0x88, label="INIT")
    s.cmd(0x84, b'\x05\x20\xA1\x07\x00', label="0x84 proto+baud")
    s.cmd(0x85, b'\x05\x20\xA1\x07\x00', label="0x85 proto+baud")
    s.cmd(0x89, b'\x05\x20\xA1\x07\x00', label="0x89 proto+baud")
    # Try with channel byte prefix
    s.cmd(0x84, b'\x00\x05\x20\xA1\x07\x00', label="0x84 ch+proto+baud")
    s.cmd(0x89, b'\x00\x05\x20\xA1\x07\x00', label="0x89 ch+proto+baud")
    print()

    print("=== SEQUENCE 4: 0x80 status variations ===")
    s.cmd(0x80, label="STATUS no payload")
    s.cmd(0x80, b'\x00', label="STATUS arg=0")
    s.cmd(0x80, b'\x01', label="STATUS arg=1")
    s.cmd(0x80, b'\x02', label="STATUS arg=2")
    s.cmd(0x80, b'\xFF', label="STATUS arg=FF")
    print()

    print("=== SEQUENCE 5: Try large payloads on echo-back range ===")
    s.cmd(0x88, label="INIT")
    # CAN frame structure guess: arb_id(4) + dlc(1) + data(8)
    can_frame = b'\x00\x00\x07\xDF\x08\x02\x01\x00\x00\x00\x00\x00\x00'
    s.cmd(0x8A, can_frame, label="0x8A CAN frame?")
    s.cmd(0x8B, can_frame, label="0x8B CAN frame?")
    s.cmd(0x8C, can_frame, label="0x8C CAN frame?")
    s.cmd(0x90, can_frame, label="0x90 CAN frame?")
    s.cmd(0xA0, can_frame, label="0xA0 CAN frame?")
    print()

    print("=== SEQUENCE 6: Device info deep read ===")
    s.cmd(0x83, label="DEVICE INFO no payload")
    s.cmd(0x83, b'\x00', label="DEVICE INFO arg=0")
    s.cmd(0x83, b'\x01', label="DEVICE INFO arg=1")
    s.cmd(0x83, b'\x02', label="DEVICE INFO arg=2")
    print()

    s.close()
    print("Done.")

if __name__ == '__main__':
    main()
