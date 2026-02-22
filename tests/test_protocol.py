"""Tests for sm2can package.

Copyright (c) 2026 Aldo Guzman. MIT License.
"""
import struct
import pytest

from sm2can.protocol import (
    ProtocolCodec, Command, CANFrame, CANMode,
    _checksum_xor, _checksum_sum, _checksum_none,
    CHECKSUM_FUNCTIONS,
)


class TestProtocolCodec:
    """Test the protocol frame encoder/decoder."""

    def setup_method(self):
        self.codec = ProtocolCodec()

    def test_encode_command_basic(self):
        frame = self.codec.encode_command(Command.IDENTIFY)
        assert len(frame) >= self.codec.MIN_FRAME_SIZE
        assert frame[0] == self.codec.HEADER_BYTE

    def test_encode_command_with_data(self):
        data = bytes([0x01, 0x02, 0x03])
        frame = self.codec.encode_command(Command.CAN_OPEN, data)
        assert len(frame) == self.codec.MIN_FRAME_SIZE + len(data)

    def test_decode_roundtrip(self):
        original_data = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        cmd = Command.CAN_SEND
        frame = self.codec.encode_command(cmd, original_data)
        result = self.codec.decode_frame(frame)
        assert result is not None
        decoded_cmd, decoded_data = result
        assert decoded_cmd == cmd
        assert decoded_data == original_data

    def test_decode_short_frame_returns_none(self):
        assert self.codec.decode_frame(b'') is None
        assert self.codec.decode_frame(b'\xAA') is None
        assert self.codec.decode_frame(b'\xAA\x00') is None

    def test_decode_wrong_header(self):
        frame = bytes([0x99, 0x00, 0x01, 0x42, 0x00])
        assert self.codec.decode_frame(frame) is None

    def test_feed_single_frame(self):
        frame = self.codec.encode_command(Command.GET_VERSION)
        results = self.codec.feed(frame)
        assert len(results) == 1
        cmd, _ = results[0]
        assert cmd == Command.GET_VERSION

    def test_feed_multiple_frames(self):
        f1 = self.codec.encode_command(Command.IDENTIFY)
        f2 = self.codec.encode_command(Command.GET_VERSION)
        results = self.codec.feed(f1 + f2)
        assert len(results) == 2

    def test_feed_partial_frame(self):
        frame = self.codec.encode_command(Command.IDENTIFY)
        mid = len(frame) // 2
        r1 = self.codec.feed(frame[:mid])
        assert len(r1) == 0
        r2 = self.codec.feed(frame[mid:])
        assert len(r2) == 1

    def test_feed_garbage_prefix(self):
        frame = self.codec.encode_command(Command.IDENTIFY)
        results = self.codec.feed(bytes([0x99, 0x88, 0x77]) + frame)
        assert len(results) == 1

    def test_encode_can_open(self):
        frame = self.codec.encode_can_open(500000, CANMode.NORMAL)
        assert len(frame) > 0
        assert self.codec.decode_frame(frame) is not None

    def test_encode_can_send(self):
        can_frame = CANFrame(
            arbitration_id=0x7DF,
            data=bytes([0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        )
        frame = self.codec.encode_can_send(can_frame)
        assert self.codec.decode_frame(frame) is not None

    def test_decode_can_frame(self):
        arb_id = 0x340
        data = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        payload = struct.pack('>IBB', arb_id, 0x00, len(data)) + data
        frame = self.codec.decode_can_frame(payload)
        assert frame is not None
        assert frame.arbitration_id == arb_id
        assert frame.data == data
        assert frame.is_extended_id is False

    def test_decode_can_frame_extended(self):
        arb_id = 0x18DAF110
        data = bytes([0x30, 0x00, 0x00])
        payload = struct.pack('>IBB', arb_id, 0x01, len(data)) + data
        frame = self.codec.decode_can_frame(payload)
        assert frame is not None
        assert frame.arbitration_id == arb_id
        assert frame.is_extended_id is True

    def test_decode_can_frame_invalid_dlc_clamped(self):
        """DLC > 8 should be clamped, not crash."""
        payload = struct.pack('>IBB', 0x123, 0x00, 255)  # dlc=255
        payload += bytes(8)
        frame = self.codec.decode_can_frame(payload)
        assert frame is not None
        assert len(frame.data) <= 8

    def test_reset_buffer(self):
        frame = self.codec.encode_command(Command.IDENTIFY)
        self.codec.feed(frame[:2])
        self.codec.reset_buffer()
        results = self.codec.feed(frame[2:])
        assert len(results) == 0


class TestChecksumFunctions:
    """Test checksum implementations."""

    def test_xor(self):
        data = bytes([0xAA, 0x00, 0x01, 0x42])
        assert _checksum_xor(data) == (0xAA ^ 0x00 ^ 0x01 ^ 0x42)

    def test_sum(self):
        data = bytes([0x01, 0x02, 0x03])
        assert _checksum_sum(data) == 6

    def test_sum_overflow(self):
        data = bytes([0xFF, 0x02])
        assert _checksum_sum(data) == (0xFF + 0x02) & 0xFF

    def test_none(self):
        assert _checksum_none(b'\xFF\xFF') == 0

    def test_codec_with_sum_checksum(self):
        """Codec should work with different checksum functions."""
        codec = ProtocolCodec(checksum_fn=_checksum_sum)
        frame = codec.encode_command(Command.IDENTIFY)
        result = codec.decode_frame(frame)
        assert result is not None
        cmd, _ = result
        assert cmd == Command.IDENTIFY

    def test_codec_with_none_checksum(self):
        codec = ProtocolCodec(checksum_fn=_checksum_none)
        frame = codec.encode_command(Command.GET_VERSION)
        result = codec.decode_frame(frame)
        assert result is not None

    def test_checksum_functions_dict(self):
        """CHECKSUM_FUNCTIONS should contain all named algorithms."""
        assert 'xor' in CHECKSUM_FUNCTIONS
        assert 'sum' in CHECKSUM_FUNCTIONS
        assert 'none' in CHECKSUM_FUNCTIONS
        assert callable(CHECKSUM_FUNCTIONS['xor'])


class TestCANFrame:
    def test_repr(self):
        frame = CANFrame(arbitration_id=0x7DF, data=b'\x02\x01\x00')
        s = repr(frame)
        assert '0x7DF' in s
        assert '02 01 00' in s

    def test_extended_id(self):
        frame = CANFrame(arbitration_id=0x18DAF110, data=b'\x10',
                        is_extended_id=True)
        assert frame.is_extended_id


class TestCaptureDecoder:
    def test_parse_empty_file(self, tmp_path):
        f = tmp_path / "bad.pcap"
        f.write_bytes(b'not a pcap file at all')
        from sm2can.tools.capture_decoder import parse_pcap
        with pytest.raises(ValueError):
            parse_pcap(str(f))

    def test_parse_valid_pcap_header(self, tmp_path):
        from sm2can.tools.capture_decoder import parse_pcap, LINKTYPE_USBPCAP
        f = tmp_path / "empty.pcap"
        header = struct.pack('<IHHiIII',
                            0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_USBPCAP)
        f.write_bytes(header)
        packets = parse_pcap(str(f))
        assert packets == []

    def test_protocol_analysis_empty(self):
        from sm2can.tools.capture_decoder import ProtocolAnalyzer
        analyzer = ProtocolAnalyzer([])
        analysis = analyzer.analyze()
        assert analysis.total_packets == 0

    def test_generate_code(self):
        from sm2can.tools.capture_decoder import generate_protocol_code, ProtocolAnalysis
        analysis = ProtocolAnalysis(
            likely_header=0xAA,
            likely_length_format='BE16',
            likely_checksum='XOR',
            min_frame_size=5,
            max_frame_size=64,
        )
        code = generate_protocol_code(analysis)
        assert 'HEADER_BYTE = 0xAA' in code
        assert 'XOR' in code
        compile(code, '<test>', 'exec')  # Must be valid Python

    def test_usb_packet_has_meaningful_data(self):
        from sm2can.tools.capture_decoder import USBPacket
        # OUT submission with data = meaningful
        p = USBPacket(0.0, 'OUT', 2, 'BULK', b'\x01', is_submission=True)
        assert p.has_meaningful_data
        # OUT completion = not meaningful
        p = USBPacket(0.0, 'OUT', 2, 'BULK', b'\x01', is_submission=False)
        assert not p.has_meaningful_data
        # IN completion with data = meaningful
        p = USBPacket(0.0, 'IN', 1, 'BULK', b'\x02', is_submission=False)
        assert p.has_meaningful_data
        # IN submission = not meaningful
        p = USBPacket(0.0, 'IN', 1, 'BULK', b'\x02', is_submission=True)
        assert not p.has_meaningful_data
        # No data = not meaningful
        p = USBPacket(0.0, 'OUT', 2, 'BULK', b'', is_submission=True)
        assert not p.has_meaningful_data


class TestBluetoothTransport:
    """Test Bluetooth transport scaffolding."""

    def test_import(self):
        from sm2can.bluetooth_transport import BluetoothTransport
        bt = BluetoothTransport(address="AA:BB:CC:DD:EE:FF")
        assert not bt.is_open

    def test_open_raises_not_implemented(self):
        from sm2can.bluetooth_transport import BluetoothTransport
        bt = BluetoothTransport()
        with pytest.raises(NotImplementedError):
            bt.open()

    def test_scan_returns_empty(self):
        from sm2can.bluetooth_transport import BluetoothTransport
        devices = BluetoothTransport.scan(timeout=0.1)
        assert devices == []
