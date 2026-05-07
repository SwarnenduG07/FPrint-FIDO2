"""CTAP2 protocol handler for FIDO2 HID transport."""

import struct
from typing import Optional

# CTAP HID commands
CTAPHID_PING = 0x01
CTAPHID_MSG = 0x03
CTAPHID_INIT = 0x06
CTAPHID_ERROR = 0x3F

# CTAP2 commands (inside CTAPHID_MSG)
CTAP2_GET_INFO = 0x04
CTAP2_MAKE_CREDENTIAL = 0x01
CTAP2_GET_ASSERTION = 0x02

# CTAP status codes
CTAP2_OK = 0x00
CTAP2_ERR_INVALID_COMMAND = 0x01
CTAP2_ERR_OPERATION_DENIED = 0x27

# Broadcast channel ID
BROADCAST_CID = 0xFFFFFFFF

HID_PACKET_SIZE = 64


class CTAP2Handler:
    """Handles CTAP2 protocol over HID transport."""

    def __init__(self):
        self._channels = {}  # cid -> nonce mapping
        self._next_cid = 1

    def handle_packet(self, packet: bytes) -> Optional[bytes]:
        """
        Process incoming HID packet and return response packet.
        
        Args:
            packet: 64-byte HID packet from browser
            
        Returns:
            64-byte response packet, or None if no response needed
        """
        if len(packet) != HID_PACKET_SIZE:
            return None

        # Parse HID initialization packet: CID(4BE) + CMD(1) + BCNT_H(1) + BCNT_L(1) + DATA
        cid = struct.unpack_from(">I", packet, 0)[0]
        cmd = packet[4] & 0x7F
        is_init_packet = bool(packet[4] & 0x80)
        payload_len = (packet[5] << 8) | packet[6]
        payload = packet[7 : 7 + min(payload_len, 57)]

        print(f"[CTAP2] CID={cid:08x} CMD={cmd:02x} INIT={is_init_packet} LEN={payload_len}", flush=True)

        if not is_init_packet:
            return None  # continuation packet, ignore for now

        # Handle commands
        if cmd == CTAPHID_INIT:
            return self._handle_init(cid, payload)
        elif cmd == CTAPHID_PING:
            return self._handle_ping(cid, payload)
        elif cmd == CTAPHID_MSG:
            return self._handle_msg(cid, payload)
        else:
            return self._error(cid, CTAP2_ERR_INVALID_COMMAND)

    def _handle_init(self, cid: int, nonce: bytes) -> bytes:
        """Handle CTAPHID_INIT - allocate a channel."""
        if len(nonce) != 8:
            return self._error(cid, CTAP2_ERR_INVALID_COMMAND)

        # Allocate new channel ID
        new_cid = self._next_cid
        self._next_cid += 1
        self._channels[new_cid] = nonce

        # Response: nonce(8) + new_cid(4BE) + protocol(1) + major(1) + minor(1) + build(1) + capabilities(1)
        response = nonce + struct.pack(">IBBBBB", new_cid, 2, 1, 0, 0, 0x04)

        packet = self._build_packet(BROADCAST_CID, CTAPHID_INIT, response)
        print(f"[CTAP2] INIT: nonce={nonce.hex()} new_cid={new_cid:08x} response={response.hex()}", flush=True)
        print(f"[CTAP2] INIT: full packet={packet.hex()}", flush=True)
        return packet

    def _handle_ping(self, cid: int, data: bytes) -> bytes:
        """Handle CTAPHID_PING - echo back the data."""
        return self._build_packet(cid, CTAPHID_PING, data)

    def _handle_msg(self, cid: int, payload: bytes) -> bytes:
        """Handle CTAPHID_MSG - CTAP2 command."""
        if len(payload) == 0:
            return self._error(cid, CTAP2_ERR_INVALID_COMMAND)

        ctap_cmd = payload[0]
        ctap_data = payload[1:]

        print(f"[CTAP2] CTAP command: {ctap_cmd:02x}")

        if ctap_cmd == CTAP2_GET_INFO:
            return self._handle_get_info(cid)
        elif ctap_cmd == CTAP2_MAKE_CREDENTIAL:
            print("[CTAP2] MakeCredential - not implemented yet")
            return self._error(cid, CTAP2_ERR_OPERATION_DENIED)
        elif ctap_cmd == CTAP2_GET_ASSERTION:
            print("[CTAP2] GetAssertion - not implemented yet")
            return self._error(cid, CTAP2_ERR_OPERATION_DENIED)
        else:
            return self._error(cid, CTAP2_ERR_INVALID_COMMAND)

    def _handle_get_info(self, cid: int) -> bytes:
        """Handle authenticatorGetInfo - return device capabilities."""
        # CBOR-encoded response (simplified)
        # Map with: versions, extensions, aaguid, options, maxMsgSize, pinProtocols
        info = bytes([
            0xA6,  # map(6)
            0x01,  # key: versions
            0x82,  # array(2)
            0x66, 0x55, 0x32, 0x46, 0x5F, 0x56, 0x32,  # "U2F_V2"
            0x68, 0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30,  # "FIDO_2_0"
            
            0x02,  # key: extensions
            0x80,  # array(0) - no extensions
            
            0x03,  # key: aaguid
            0x50,  # bytes(16)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            
            0x04,  # key: options
            0xA2,  # map(2)
            0x62, 0x75, 0x76,  # "uv" (user verification)
            0xF5,  # true
            0x62, 0x72, 0x6B,  # "rk" (resident key)
            0xF5,  # true
            
            0x05,  # key: maxMsgSize
            0x19, 0x04, 0x00,  # 1024
            
            0x06,  # key: pinProtocols
            0x80,  # array(0) - no PIN
        ])

        response = bytes([CTAP2_OK]) + info
        return self._build_packet(cid, CTAPHID_MSG, response)

    def _error(self, cid: int, error_code: int) -> bytes:
        """Build error response."""
        return self._build_packet(cid, CTAPHID_ERROR, bytes([error_code]))

    def _build_packet(self, cid: int, cmd: int, data: bytes) -> bytes:
        """Build a 64-byte HID packet."""
        data_len = len(data)
        packet = struct.pack(">IBBB", cid, cmd | 0x80, (data_len >> 8) & 0xFF, data_len & 0xFF)
        packet += data[:57]  # max 57 bytes in init packet
        packet = packet.ljust(HID_PACKET_SIZE, b"\x00")
        return packet
