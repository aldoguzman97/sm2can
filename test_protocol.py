"""
Tests for SM2 Pro protocol — using confirmed values from hardware probing.

Every checksum in this file was verified against the device on 2026-02-22.

Copyright (c) 2026 Aldo Guzman. MIT License.
"""

import pytest
from sm2can.protocol import (
    sm2_checksum, verify_checksum, build_frame, parse_frame,
    SM2Codec, Cmd, CANFrame, DeviceInfo, HEADER_SIZE, CHECKSUM_SALT
)


# ══════════════════════════════════════════════════════════════
#  Checksum tests — verified against Java source and hardware
# ══════════════════════════════════════════════════════════════

class TestChecksum:
    """Checksum = (cmd + 0x55 + len_hi + len_lo) & 0xFF"""

    def test_salt_is_0x55(self):
        assert CHECKSUM_SALT == 0x55

    def test_cmd_0x00_empty(self):
        # Confirmed: 00 00 00 55
        assert sm2_checksum(0x00, 0) == 0x55

    def test_cmd_0x01_empty(self):
        # Confirmed: 01 00 00 56
        assert sm2_checksum(0x01, 0) == 0x56

    def test_cmd_0x82_empty(self):
        # ECHO empty: 82 00 00 D7
        assert sm2_checksum(0x82, 0) == 0xD7

    def test_cmd_0x82_payload_4(self):
        # ECHO with 4-byte payload: 82 04 00 DB
        assert sm2_checksum(0x82, 4) == 0xDB

    def test_cmd_0x83_empty(self):
        # DEVICE_INFO: 83 00 00 D8
        assert sm2_checksum(0x83, 0) == 0xD8

    def test_cmd_0x86_empty(self):
        # CLEAR_FIFO: 86 00 00 DB
        assert sm2_checksum(0x86, 0) == 0xDB

    def test_cmd_0x88_empty(self):
        # INIT: 88 00 00 DD
        assert sm2_checksum(0x88, 0) == 0xDD

    def test_response_success(self):
        # SUCCESS response: 00 00 00 55
        assert sm2_checksum(0x00, 0) == 0x55

    def test_response_nack(self):
        # NACK response: 01 00 00 56
        assert sm2_checksum(0x01, 0) == 0x56

    def test_response_device_info(self):
        # Device info response: 00 12 00 67 (cmd=0, len=18)
        assert sm2_checksum(0x00, 18) == 0x67

    def test_response_status_idle(self):
        # Status idle: 5E 00 00 B3
        assert sm2_checksum(0x5E, 0) == 0xB3

    def test_echo_response(self):
        # Echo response with 4-byte payload: 00 04 00 59
        assert sm2_checksum(0x00, 4) == 0x59

    def test_large_payload(self):
        # Length 256 = 0x0100: len_lo=0, len_hi=1
        # checksum = (cmd + 0x55 + 1 + 0) & 0xFF
        assert sm2_checksum(0x00, 256) == 0x56

    def test_max_payload(self):
        # Length 65535 = 0xFFFF: len_lo=0xFF, len_hi=0xFF
        assert sm2_checksum(0x00, 65535) == (0x55 + 0xFF + 0xFF) & 0xFF


# ══════════════════════════════════════════════════════════════
#  Frame building tests
# ══════════════════════════════════════════════════════════════

class TestBuildFrame:

    def test_init_frame(self):
        frame = build_frame(0x88)
        assert frame == bytes([0x88, 0x00, 0x00, 0xDD])

    def test_echo_with_payload(self):
        frame = build_frame(0x82, b'ECHO')
        assert frame == bytes([0x82, 0x04, 0x00, 0xDB]) + b'ECHO'

    def test_device_info_frame(self):
        frame = build_frame(0x83)
        assert frame == bytes([0x83, 0x00, 0x00, 0xD8])

    def test_clear_fifo_frame(self):
        frame = build_frame(0x86)
        assert frame == bytes([0x86, 0x00, 0x00, 0xDB])

    def test_status_frame(self):
        frame = build_frame(0x80)
        assert frame == bytes([0x80, 0x00, 0x00, 0xD5])

    def test_empty_payload_is_4_bytes(self):
        frame = build_frame(0x00)
        assert len(frame) == 4
        assert frame == bytes([0x00, 0x00, 0x00, 0x55])


# ══════════════════════════════════════════════════════════════
#  Frame parsing tests — using actual hardware responses
# ══════════════════════════════════════════════════════════════

class TestParseFrame:

    def test_success_response(self):
        # Actual response to INIT
        data = bytes([0x00, 0x00, 0x00, 0x55])
        cmd, length, valid, payload = parse_frame(data)
        assert cmd == 0x00
        assert length == 0
        assert valid is True
        assert payload == b''

    def test_nack_response(self):
        # Actual NACK response
        data = bytes([0x01, 0x00, 0x00, 0x56])
        cmd, length, valid, payload = parse_frame(data)
        assert cmd == 0x01
        assert length == 0
        assert valid is True

    def test_status_idle_response(self):
        # Actual response to STATUS (0x80)
        data = bytes([0x5E, 0x00, 0x00, 0xB3])
        cmd, length, valid, payload = parse_frame(data)
        assert cmd == 0x5E
        assert valid is True

    def test_device_info_response(self):
        # Actual device info response (22 bytes total: 4 header + 18 payload)
        data = bytes([
            0x00, 0x12, 0x00, 0x67,  # header: cmd=0, len=18, cksum
            0x30, 0x87, 0xA7, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x76, 0x09, 0x00, 0x00,
            0x02, 0x03
        ])
        cmd, length, valid, payload = parse_frame(data)
        assert cmd == 0x00  # SUCCESS
        assert length == 18
        assert valid is True
        assert len(payload) == 18
        assert payload[0] == 0x30
        assert payload[12] == 0x76
        assert payload[13] == 0x09

    def test_echo_response(self):
        # Actual echo response: cmd=0x00, 4-byte payload "ECHO"
        data = bytes([0x00, 0x04, 0x00, 0x59, 0x45, 0x43, 0x48, 0x4F])
        cmd, length, valid, payload = parse_frame(data)
        assert cmd == 0x00
        assert length == 4
        assert valid is True
        assert payload == b'ECHO'

    def test_channel_ack(self):
        # Actual 0x8A ACK (echo of cmd byte, empty payload)
        data = bytes([0x8A, 0x00, 0x00, 0xDF])
        cmd, length, valid, payload = parse_frame(data)
        assert cmd == 0x8A
        assert valid is True

    def test_too_short(self):
        assert parse_frame(b'\x00\x00') is None
        assert parse_frame(b'') is None

    def test_bad_checksum(self):
        data = bytes([0x00, 0x00, 0x00, 0xFF])  # Wrong checksum
        cmd, length, valid, payload = parse_frame(data)
        assert valid is False


# ══════════════════════════════════════════════════════════════
#  Verify checksum on raw bytes
# ══════════════════════════════════════════════════════════════

class TestVerifyChecksum:

    def test_all_confirmed_frames(self):
        """Verify every frame we saw on the wire."""
        confirmed = [
            bytes([0x00, 0x00, 0x00, 0x55]),  # SUCCESS
            bytes([0x01, 0x00, 0x00, 0x56]),  # NACK
            bytes([0x5E, 0x00, 0x00, 0xB3]),  # STATUS_IDLE
            bytes([0x88, 0x00, 0x00, 0xDD]),  # INIT TX
            bytes([0x82, 0x00, 0x00, 0xD7]),  # ECHO empty TX
            bytes([0x82, 0x04, 0x00, 0xDB]),  # ECHO 4-byte TX
            bytes([0x83, 0x00, 0x00, 0xD8]),  # DEVICE_INFO TX
            bytes([0x86, 0x00, 0x00, 0xDB]),  # CLEAR_FIFO TX
            bytes([0x80, 0x00, 0x00, 0xD5]),  # STATUS TX
            bytes([0x8A, 0x00, 0x00, 0xDF]),  # CAN_OPEN ACK
            bytes([0x8B, 0x00, 0x00, 0xE0]),  # CAN_SEND ACK
            bytes([0x8C, 0x00, 0x00, 0xE1]),  # CAN_RECV ACK
            bytes([0x00, 0x12, 0x00, 0x67]),  # Device info response header
            bytes([0x00, 0x04, 0x00, 0x59]),  # Echo response header
        ]
        for frame in confirmed:
            assert verify_checksum(frame), \
                f"Checksum failed for {frame.hex(' ')}"


# ══════════════════════════════════════════════════════════════
#  SM2Codec tests
# ══════════════════════════════════════════════════════════════

class TestSM2Codec:

    def setup_method(self):
        self.codec = SM2Codec()

    def test_encode_init(self):
        frame = self.codec.encode_init()
        assert frame == bytes([0x88, 0x00, 0x00, 0xDD])

    def test_encode_echo(self):
        frame = self.codec.encode_echo(b'TEST')
        assert frame[:4] == bytes([0x82, 0x04, 0x00, 0xDB])
        assert frame[4:] == b'TEST'

    def test_encode_device_info(self):
        frame = self.codec.encode_device_info()
        assert frame == bytes([0x83, 0x00, 0x00, 0xD8])

    def test_decode_device_info(self):
        payload = bytes([
            0x30, 0x87, 0xA7, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x76, 0x09, 0x00, 0x00,
            0x02, 0x03
        ])
        info = self.codec.decode_device_info(payload)
        assert info.firmware_version == 0x0976
        assert info.firmware_str == "9.118"
        assert info.hardware_rev == 0x0302
        assert info.hardware_id_hex == "30 87 a7"

    def test_streaming_decoder(self):
        # Feed two complete frames in one chunk
        frame1 = build_frame(0x00, b'')  # SUCCESS
        frame2 = build_frame(0x8A, b'')  # CAN_OPEN ACK
        results = self.codec.feed(frame1 + frame2)
        assert len(results) == 2
        assert results[0] == (0x00, b'')
        assert results[1] == (0x8A, b'')

    def test_streaming_partial(self):
        # Feed a frame in two chunks
        frame = build_frame(0x00, b'\x01\x02\x03\x04')
        part1 = frame[:3]  # Partial header
        part2 = frame[3:]  # Rest

        results1 = self.codec.feed(part1)
        assert len(results1) == 0  # Not enough data

        results2 = self.codec.feed(part2)
        assert len(results2) == 1
        assert results2[0] == (0x00, b'\x01\x02\x03\x04')

    def test_encode_can_send(self):
        frame = CANFrame(
            arbitration_id=0x7DF,
            data=bytes([0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        )
        encoded = self.codec.encode_can_send(frame)
        # Header: 0x8B, len=14 (4+1+1+8), cksum
        assert encoded[0] == 0x8B
        assert encoded[1] == 14  # len_lo
        assert encoded[2] == 0   # len_hi
        # Payload starts at offset 4:
        # arb_id LE32: DF 07 00 00
        assert encoded[4:8] == b'\xDF\x07\x00\x00'
        # flags=0, dlc=8
        assert encoded[8] == 0x00
        assert encoded[9] == 0x08


# ══════════════════════════════════════════════════════════════
#  Command enum tests
# ══════════════════════════════════════════════════════════════

class TestCmd:

    def test_system_commands_in_0x80_range(self):
        assert Cmd.STATUS == 0x80
        assert Cmd.ECHO == 0x82
        assert Cmd.DEVICE_INFO == 0x83
        assert Cmd.CLEAR_FIFO == 0x86
        assert Cmd.POWER_DOWN == 0x87
        assert Cmd.INIT == 0x88

    def test_channel_commands(self):
        assert Cmd.CAN_OPEN == 0x8A
        assert Cmd.CAN_SEND == 0x8B
        assert Cmd.CAN_RECV == 0x8C
        assert Cmd.CAN_CLOSE == 0x8D

    def test_response_codes(self):
        assert Cmd.SUCCESS == 0x00
        assert Cmd.NACK == 0x01
        assert Cmd.STATUS_IDLE == 0x5E
