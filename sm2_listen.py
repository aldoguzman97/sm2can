#!/usr/bin/env python3
"""SM2 Pro listen probe - init, configure, then listen for async data."""

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

dev = usb.core.find(idVendor=0x20A2, idProduct=0x0001)
if not dev: print("SM2 Pro not found"); sys.exit(1)
for c in dev:
    for i in c:
        try:
            if dev.is_kernel_driver_active(i.bInterfaceNumber):
                dev.detach_kernel_driver(i.bInterfaceNumber)
        except: pass
try: dev.set_configuration()
except: pass
cfg = dev.get_active_configuration()
epo = epi = None
for i in cfg:
    for e in i:
        d = usb.util.endpoint_direction(e.bEndpointAddress)
        if e.bmAttributes & 3 == 2:
            if d == usb.util.ENDPOINT_OUT and not epo: epo = e
            elif d == usb.util.ENDPOINT_IN and not epi: epi = e

def send(cmd, payload=b'', label=""):
    f = frame(cmd, payload)
    epo.write(f, timeout=1000)
    time.sleep(0.02)
    try: rx = bytes(epi.read(4096, timeout=500))
    except: rx = b''
    rc, rl, ok, pl = parse(rx) if rx else (None, 0, False, b'')
    tag = " [{}]".format(label) if label else ""
    print("  TX 0x{:02X}: {}{}".format(cmd, hx(f), tag))
    if rx:
        print("  RX:      {} (cmd=0x{:02X} len={})".format(hx(rx), rc, rl))
        if pl: print("  Payload: {}".format(hx(pl)))
    else:
        print("  RX:      (timeout)")
    print()
    return rc, ok, pl

def listen(seconds, label=""):
    print("--- Listening for {} seconds{} ---".format(
        seconds, " [{}]".format(label) if label else ""))
    count = 0
    end = time.time() + seconds
    while time.time() < end:
        try:
            rx = bytes(epi.read(4096, timeout=200))
            if rx:
                count += 1
                rc, rl, ok, pl = parse(rx)
                print("  ASYNC #{}: {} (cmd=0x{:02X} len={} {})".format(
                    count, hx(rx), rc, rl, "OK" if ok else "BAD"))
                if pl: print("    Payload: {}".format(hx(pl)))
        except: pass
    if count == 0:
        print("  (nothing received)")
    print()

print("SM2 Pro connected")
print()

# Drain
while True:
    try: dev.read(epi.bEndpointAddress, 4096, timeout=50)
    except: break

print("=== TEST 1: Init + listen (baseline) ===")
send(0x88, label="INIT")
listen(2, "after init only")

print("=== TEST 2: Init + 0x8A config + listen ===")
send(0x88, label="INIT")
send(0x86, label="CLEAR FIFO")
# Try: channel=0, CAN 500k, 11-bit
send(0x8A, b'\x00\x05\x00\x20\xA1\x07\x00', label="ch0 CAN 500k attempt 1")
listen(2, "after 0x8A config")

print("=== TEST 3: Init + sequential 0x8A-0x8D + listen ===")
send(0x88, label="INIT")
send(0x8A, b'\x05', label="0x8A: protocol=CAN?")
send(0x8B, b'\x20\xA1\x07\x00', label="0x8B: baud=500k?")
send(0x8C, b'\x00', label="0x8C: channel=0?")
send(0x8D, b'\x01', label="0x8D: start?")
listen(2, "after sequential setup")

print("=== TEST 4: Try J2534-style PassThruConnect params ===")
# J2534 PassThruConnect: DeviceID(4) ProtocolID(4) Flags(4) Baudrate(4)
send(0x88, label="INIT")
import struct
# ProtocolID: 6=ISO15765, 5=CAN  Flags: 0  Baud: 500000
payload = struct.pack('<IIII', 0, 5, 0, 500000)
send(0x8A, payload, label="J2534 connect CAN 500k")
listen(2, "after J2534 connect")

# Same with ISO15765
payload = struct.pack('<IIII', 0, 6, 0, 500000)
send(0x8A, payload, label="J2534 connect ISO15765 500k")
listen(2, "after J2534 ISO15765")

print("=== TEST 5: Send OBD2 request then listen ===")
send(0x88, label="INIT")
# Config CAN
send(0x8A, struct.pack('<IIII', 0, 5, 0, 500000), label="open CAN 500k")
# Send CAN frame: ID=0x7DF, DLC=8, data=02 01 00 (OBD2 PIDs supported)
can_data = struct.pack('<I', 0x7DF) + b'\x08\x02\x01\x00\x00\x00\x00\x00\x00'
send(0x8B, can_data, label="OBD2 PID request to 0x7DF")
listen(3, "waiting for OBD2 response")

print("=== TEST 6: Bulk raw read test ===")
print("Reading raw for 5 seconds to catch any async traffic...")
listen(5, "extended raw listen")

usb.util.dispose_resources(dev)
print("Done.")
