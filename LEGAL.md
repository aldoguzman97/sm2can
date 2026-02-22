# Legal Notice

## Clean Room Reverse Engineering

SM2CAN was developed through clean room reverse engineering of a legitimately
purchased SM2 Pro device. The purpose is to achieve interoperability — enabling
the hardware to function on macOS and Linux, platforms not officially supported
by the manufacturer.

## What was done

1. **USB device enumeration** — Standard USB descriptor queries (`lsusb`,
   `system_profiler`) to identify VID, PID, endpoints, and device class.

2. **Android APK analysis** — The official Scanmatik Android app
   (`Scanmatik_Android_2.21.35.apk`) was decompiled using `jadx` to understand
   the wire protocol frame format and checksum algorithm from the Java/JNI
   transport layer.

3. **Live hardware probing** — Sending protocol frames to the device over USB
   and observing responses to map the command space.

## What was NOT done

- No proprietary Windows DLL was disassembled or decompiled.
- No proprietary firmware was extracted or modified.
- No proprietary documentation was used.
- No encryption or DRM was circumvented.
- No copyrighted code was copied.

## Legal basis

Reverse engineering for interoperability is protected under:

- **DMCA § 1201(f)** — Reverse engineering for interoperability of computer programs
- **EU Directive 2009/24/EC, Article 6** — Decompilation for interoperability
- **Australian Copyright Act 1968, § 47D** — Interoperability analysis

## Trademarks

"Scanmatik" and "SM2 Pro" are trademarks of their respective owners. SM2CAN is
an independent project and is not affiliated with, endorsed by, or sponsored by
Scanmatik or any related entity.
