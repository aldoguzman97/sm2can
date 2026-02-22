# Scanmatik 2 Pro Wire Protocol Specification

**Reverse-engineered from:** `Scanmatik_Android_2.21.35.apk`
**Source method:** `com.scanmatik.sm2lib.AndroidBth0.nativeCb_request(byte[])`
**Date:** 2026-02-22

## Frame Format

The protocol uses a simple 4-byte header followed by a variable-length payload.
The same frame format is used for both TX (host→device) and RX (device→host).
The same frame format is used across all transports (USB bulk, Bluetooth SPP, WiFi).

```
Offset  Size  Field
------  ----  -----
0       1     Command/Response byte
1       1     Payload length - LOW byte  (little-endian)
2       1     Payload length - HIGH byte (little-endian)
3       1     Checksum
4..N    var   Payload (N = length from bytes 1-2)
```

**Total frame size** = 4 + payload_length

## Checksum Algorithm

```
checksum = (command_byte + 0x55 + length_high_byte + length_low_byte) & 0xFF
```

The constant **0x55** is a protocol salt baked into every checksum.

### Java source (verbatim from APK decompilation):

```java
// TX: computing checksum before send
byte b = bArr[0];                                    // command byte
int i = (bArr[1] & 255) | ((bArr[2] & 255) << 8);  // payload length LE16
bArr[3] = (byte) (b + 85 + (i >> 8) + (i & 255));  // checksum

// RX: verifying checksum on response
byte b2 = bArr[0];
int i2 = (bArr[1] & 255) | ((bArr[2] & 255) << 8);
if (((byte) (b2 + 85 + (i2 >> 8) + (i2 & 255))) == bArr[3]) {
    // valid frame
}
```

Note: `85` decimal = `0x55` hex.

### Python implementation:

```python
def sm2_checksum(cmd: int, length: int) -> int:
    len_lo = length & 0xFF
    len_hi = (length >> 8) & 0xFF
    return (cmd + 0x55 + len_hi + len_lo) & 0xFF

def sm2_build_frame(cmd: int, payload: bytes = b'') -> bytes:
    length = len(payload)
    len_lo = length & 0xFF
    len_hi = (length >> 8) & 0xFF
    checksum = sm2_checksum(cmd, length)
    return bytes([cmd, len_lo, len_hi, checksum]) + payload

def sm2_parse_header(header: bytes) -> tuple:
    """Returns (cmd, payload_length, checksum_valid)"""
    cmd = header[0]
    length = header[1] | (header[2] << 8)
    expected = sm2_checksum(cmd, length)
    return cmd, length, (expected == header[3])
```

## Key Protocol Properties

| Property | Value |
|----------|-------|
| Header magic byte | **None** — first byte is command directly |
| Length encoding | Little-endian 16-bit (max payload: 65535 bytes) |
| Length counts | Payload bytes only (excludes 4-byte header) |
| Checksum scope | Command byte + 0x55 + both length bytes |
| Frame direction | Same format TX and RX |
| Transport agnostic | Yes — identical over USB/BT/WiFi |

## Transport Layer Details

### USB Transport
- The Java layer opens the USB device and passes the **file descriptor** to native code
- Native code performs bulk transfers via Linux usbfs ioctls on the fd
- `nativeCb_getFd()` returns `UsbDeviceConnection.getFileDescriptor()`
- No additional USB-specific framing — bulk endpoints carry raw protocol frames
- The protocol frames are sent/received directly on bulk OUT/IN endpoints

### Bluetooth Transport
- RFCOMM SPP stream (UUID: `00001200-0000-1000-8000-00805F9B34FB`)
- Pairing PIN: `A5137F` (bytes: `{65, 53, 49, 51, 55, 70}`)
- BK3231S Bluetooth module (firmware string: `AT-AB -BK3231S Firmware Ver1.0-`)
- AT command set: `AT-VERSION?`, `AT-FIRMWARE-UPDATE`, `AT-AB-OK`
- 7-second read timeout per chunk
- Same protocol framing as USB

### WiFi Transport
- WiFi Direct P2P connection
- SSID pattern: `DIRECT-SCANMATIK-#XXXXX` (hex device ID)
- TCP socket after P2P group formation
- Same protocol framing as USB/BT

## Status Codes (SMSTATUS)

From `libcom.scanmatik.sm2lib.so` string table:

| Status | Name |
|--------|------|
| 0x0000 | SMSTATUS_SUCCESS |
| ? | SMSTATUS_INVALID_PARAMETER |
| ? | SMSTATUS_TXTIMEOUT |
| ? | SMSTATUS_INVALID_RESPONSE |
| ? | SMSTATUS_INVALID_INTERFACE |
| ? | SMSTATUS_RADIOLINK_DENIED |
| ? | SMSTATUS_UNSUCCESSFUL |
| ? | SMSTATUS_APPINITFAILED |
| ? | SMSTATUS_DEVICE_NOT_FOUND |
| ? | SMSTATUS_ABORTED |
| ? | SMSTATUS_NO_RESPONSE |
| ? | SMSTATUS_LOW_RESOURCES |
| ? | SMSTATUS_REQUEST_REJECTED |
| ? | SMSTATUS_OPERATION_WAS_NEVER_PERFORMED |
| ? | SMSTATUS_INVALID_LENGTH |
| ? | SMSTATUS_NO_RADIO_DONGLE_FOUND |
| ? | SMSTATUS_FILE_IO_ERROR |
| ? | SMSTATUS_NO_USB_HOST_HARDWARE_FOUND |
| ? | SMSTATUS_UNSUPPORTED |
| ? | SMSTATUS_DEVICE_IN_USE_BY_ANOTHER_PROCCESS |
| ? | SMSTATUS_WIRELESS_CREDENTIALS_WRONG |

(Exact numeric values are in the .so binary; ordering in string table suggests sequential assignment)

## Known Named Functions

From `libcom.scanmatik.sm2lib.so` exports:

| Function | Purpose |
|----------|---------|
| `Sm2Lib_EchoV2` | Echo/ping — likely first command to verify communication |
| `Sm2Lib_Clear_FifoV2` | Clear device FIFO buffers |
| `Sm2Lib_writeOTPData` | Write one-time programmable data |
| `Sm2Lib_ISO13400_3_detect_eth_option` | DoIP (Diagnostics over IP) detection |
| `Sm2Lib_Can_Shuttle_J2534_maxNumTxFramesToken_getMaxFrames` | J2534 CAN max TX frames query |
| `Sm2Lib_Can_Shuttle_J2534_maxNumTxFramesToken_pushFrame` | J2534 CAN frame push |
| `Sm2Lib_getNDISAdapterInformation` | Network adapter info |

Plus ~180 obfuscated `sm2lib_XX` functions (numbered 01-187).

## Command Code Discovery Strategy

The actual command byte values are embedded in the native ARM64 `.so` binary.
They are NOT visible in Java or string tables. To discover them:

1. **Echo probe**: Send frames with incrementing command bytes (0x00-0xFF)
   with empty payload, observe which ones get valid responses
2. **Ghidra analysis**: Disassemble `Sm2Lib_EchoV2` in the .so to find
   the command byte it uses
3. **USB capture**: Run official Scanmatik software while capturing with
   USBPcap/Wireshark, decode frames using this spec

## What We Know vs What We Don't

### Confirmed ✅
- Frame format: [CMD, LEN_LO, LEN_HI, CHECKSUM, ...PAYLOAD]
- Checksum: `(cmd + 0x55 + len_hi + len_lo) & 0xFF`
- No header/magic byte
- Transport-agnostic framing
- Bluetooth PIN: A5137F
- BT module: BK3231S

### Unknown ❌
- Actual command byte values (echo, CAN open, CAN send, CAN read, etc.)
- Payload format for each command
- Whether USB requires any initialization sequence before protocol frames
- Whether firmware boot handshake exists (the AT commands may only be BT)

## Architecture Summary

```
┌─────────────────────────────────────────┐
│           Scanmatik Application         │
│  (Java: menus, DTC display, live data)  │
└──────────────┬──────────────────────────┘
               │ JNI
┌──────────────▼──────────────────────────┐
│         libcom.scanmatik.smandroid.so   │
│  (plugin loader, UI callbacks, vehicle  │
│   module orchestration)                 │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│         libcom.scanmatik.sm2lib.so      │
│  (SM2 Pro hardware protocol, frame      │
│   encode/decode, CAN/K-Line/DoIP,       │
│   J2534 shuttle, transport abstraction)  │
├─────────┬──────────┬────────────────────┤
│ USB fd  │ BT SPP   │ WiFi TCP           │
│ (ioctl) │ (stream) │ (socket)           │
└─────────┴──────────┴────────────────────┘
               │
        ┌──────▼──────┐
        │  SM2 Pro HW │
        │  (STM32 +   │
        │   BK3231S)  │
        └─────────────┘
```
