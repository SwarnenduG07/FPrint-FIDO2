"""CTAP2 protocol handler for FIDO2 HID transport."""

import struct
from typing import Optional

# CTAP HID commands
CTAPHID_PING  = 0x01
CTAPHID_MSG   = 0x03  # U2F legacy
CTAPHID_INIT  = 0x06
CTAPHID_CBOR  = 0x10  # CTAP2 native
CTAPHID_ERROR = 0x3F

# CTAP2 commands (inside CTAPHID_CBOR)
CTAP2_MAKE_CREDENTIAL = 0x01
CTAP2_GET_ASSERTION   = 0x02
CTAP2_GET_INFO        = 0x04

# CTAP status codes
CTAP2_OK                   = 0x00
CTAP2_ERR_INVALID_COMMAND  = 0x01
CTAP2_ERR_OPERATION_DENIED = 0x27

BROADCAST_CID    = 0xFFFFFFFF
HID_PACKET_SIZE  = 64
MAX_INIT_PAYLOAD = 57  # 64 - 7 header bytes
MAX_CONT_PAYLOAD = 59  # 64 - 5 header bytes


class CTAP2Handler:
    """Handles CTAP2 protocol over HID transport."""

    def __init__(self):
        self._channels: dict = {}  # cid -> nonce
        self._next_cid: int = 1
        self._pending: dict = {}   # cid -> reassembly state

    def handle_packet(self, packet: bytes) -> Optional[bytes]:
        """Process a 64-byte HID packet and return a response, or None."""
        if len(packet) != HID_PACKET_SIZE:
            return None

        cid = struct.unpack_from(">I", packet, 0)[0]
        first_byte = packet[4]
        is_init = bool(first_byte & 0x80)

        if is_init:
            cmd = first_byte & 0x7F
            payload_len = (packet[5] << 8) | packet[6]
            data = packet[7 : 7 + min(payload_len, MAX_INIT_PAYLOAD)]

            print(f"[CTAP2] CID={cid:08x} CMD={cmd:02x} LEN={payload_len}", flush=True)

            if payload_len > MAX_INIT_PAYLOAD:
                # Start multi-packet reassembly
                self._pending[cid] = {
                    "cmd": cmd,
                    "data": bytearray(data),
                    "remaining": payload_len - len(data),
                }
                return None

            return self._dispatch(cid, cmd, bytes(data))

        else:
            # Continuation packet: CID(4) + SEQ(1) + DATA(59)
            seq = first_byte & 0x7F
            chunk = packet[5:]

            if cid not in self._pending:
                return self._error(cid, CTAP2_ERR_INVALID_COMMAND)

            state = self._pending[cid]
            take = min(len(chunk), state["remaining"])
            state["data"].extend(chunk[:take])
            state["remaining"] -= take

            print(f"[CTAP2] CID={cid:08x} CONT seq={seq} remaining={state['remaining']}", flush=True)

            if state["remaining"] <= 0:
                cmd = state["cmd"]
                full_data = bytes(state["data"])
                del self._pending[cid]
                return self._dispatch(cid, cmd, full_data)

            return None

    def _dispatch(self, cid: int, cmd: int, data: bytes) -> Optional[bytes]:
        """Dispatch a fully reassembled command."""
        if cmd == CTAPHID_INIT:
            return self._handle_init(cid, data)
        elif cmd == CTAPHID_PING:
            return self._build_packet(cid, CTAPHID_PING, data)
        elif cmd == CTAPHID_CBOR:
            return self._handle_cbor(cid, data)
        else:
            return self._error(cid, CTAP2_ERR_INVALID_COMMAND)

    def _handle_init(self, cid: int, nonce: bytes) -> bytes:
        """Handle CTAPHID_INIT — allocate a channel."""
        if len(nonce) != 8:
            return self._error(cid, CTAP2_ERR_INVALID_COMMAND)

        new_cid = self._next_cid
        self._next_cid += 1
        self._channels[new_cid] = nonce

        # nonce(8) + new_cid(4BE) + protocol(1) + major(1) + minor(1) + build(1) + capabilities(1)
        response = nonce + struct.pack(">IBBBBB", new_cid, 2, 1, 0, 0, 0x04)
        print(f"[CTAP2] INIT new_cid={new_cid:08x}", flush=True)
        return self._build_packet(BROADCAST_CID, CTAPHID_INIT, response)

    def _handle_cbor(self, cid: int, data: bytes) -> bytes:
        """Handle CTAPHID_CBOR — CTAP2 native command."""
        if not data:
            return self._error(cid, CTAP2_ERR_INVALID_COMMAND)

        ctap_cmd = data[0]
        print(f"[CTAP2] CBOR cmd={ctap_cmd:02x}", flush=True)

        if ctap_cmd == CTAP2_GET_INFO:
            return self._handle_get_info(cid)
        elif ctap_cmd == CTAP2_MAKE_CREDENTIAL:
            return self._handle_make_credential(cid, data[1:])
        elif ctap_cmd == CTAP2_GET_ASSERTION:
            print("[CTAP2] GetAssertion — not implemented yet")
            return self._error(cid, CTAP2_ERR_OPERATION_DENIED)
        else:
            return self._error(cid, CTAP2_ERR_INVALID_COMMAND)

    def _handle_make_credential(self, cid: int, cbor_data: bytes) -> bytes:
        """Handle authenticatorMakeCredential — register a new credential."""
        import cbor2
        import hashlib
        import crypto
        import store
        import fprint

        try:
            params = cbor2.loads(cbor_data)
        except Exception as e:
            print(f"[CTAP2] MakeCredential CBOR parse error: {e}", flush=True)
            return self._error(cid, CTAP2_ERR_INVALID_COMMAND)

        client_data_hash = bytes(params[1])
        rp               = params[2]
        user             = params[3]
        rp_id            = rp["id"]
        user_id          = bytes(user["id"])
        user_name        = user.get("name", "")

        print(f"[CTAP2] MakeCredential rp={rp_id} user={user_name}", flush=True)

        # Fingerprint verification
        if not fprint.verify_fingerprint():
            print("[CTAP2] Fingerprint verification failed", flush=True)
            return self._error(cid, CTAP2_ERR_OPERATION_DENIED)

        # Generate keypair and credential ID
        cred_id           = crypto.new_credential_id()
        priv_key, pub_key = crypto.generate_keypair()
        cose_key          = crypto.public_key_to_cose(pub_key)

        store.save(cred_id, rp_id, user_id, user_name, pub_key, priv_key)

        # Build authenticatorData (spec section 6.1)
        rp_id_hash = hashlib.sha256(rp_id.encode()).digest()  # 32 bytes
        flags      = 0x45  # UP(0x01) | UV(0x04) | AT(0x40)
        aaguid     = b"linux-hello\x00\x00\x00\x00\x00"      # exactly 16 bytes

        auth_data = (
            rp_id_hash +                                # 32 bytes
            bytes([flags]) +                            # 1 byte
            struct.pack(">I", 0) +                      # signCount 4 bytes
            aaguid +                                    # 16 bytes
            struct.pack(">H", len(cred_id)) +           # credIdLen 2 bytes
            cred_id +                                   # credId
            cose_key                                    # credentialPublicKey
        )

        att_obj = cbor2.dumps({
            "fmt":     "none",
            "attStmt": {},
            "authData": auth_data,
        })

        response = bytes([CTAP2_OK]) + att_obj
        print(f"[CTAP2] MakeCredential OK cred_id={cred_id.hex()}", flush=True)
        return self._build_response(cid, response)

    def _handle_get_info(self, cid: int) -> bytes:
        """Handle authenticatorGetInfo — return device capabilities."""
        # CBOR map: {1: ["FIDO_2_0"], 3: aaguid(16), 4: {rk: true, uv: true}, 5: 1024}
        info = bytes([
            0xA4,  # map(4)

            0x01,  # key 1: versions
            0x81,  # array(1)
            0x68, 0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30,  # "FIDO_2_0"

            0x03,  # key 3: aaguid
            0x50,  # bytes(16)
            0x6c, 0x69, 0x6e, 0x75, 0x78, 0x2d, 0x68, 0x65,
            0x6c, 0x6c, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00,

            0x04,  # key 4: options
            0xA2,  # map(2)
            0x62, 0x72, 0x6B, 0xF5,  # "rk": true
            0x62, 0x75, 0x76, 0xF5,  # "uv": true

            0x05,  # key 5: maxMsgSize
            0x19, 0x04, 0x00,  # 1024
        ])

        response = bytes([CTAP2_OK]) + info
        print(f"[CTAP2] GetInfo OK", flush=True)
        return self._build_packet(cid, CTAPHID_CBOR, response)

    def _error(self, cid: int, code: int) -> bytes:
        """Build a CTAPHID_ERROR response."""
        return self._build_packet(cid, CTAPHID_ERROR, bytes([code]))

    def _build_response(self, cid: int, data: bytes) -> list[bytes]:
        """Build one or more 64-byte HID packets for a response."""
        packets = []

        # First packet: CID(4) + CMD(1) + LEN_H(1) + LEN_L(1) + DATA[:57]
        data_len = len(data)
        header = struct.pack(">IBBB", cid, CTAPHID_CBOR | 0x80,
                             (data_len >> 8) & 0xFF, data_len & 0xFF)
        packets.append((header + data[:MAX_INIT_PAYLOAD]).ljust(HID_PACKET_SIZE, b"\x00"))

        # Continuation packets: CID(4) + SEQ(1) + DATA[:59]
        offset = MAX_INIT_PAYLOAD
        seq = 0
        while offset < data_len:
            chunk = data[offset:offset + MAX_CONT_PAYLOAD]
            header = struct.pack(">IB", cid, seq & 0x7F)
            packets.append((header + chunk).ljust(HID_PACKET_SIZE, b"\x00"))
            offset += MAX_CONT_PAYLOAD
            seq += 1

        return packets

    def _build_packet(self, cid: int, cmd: int, data: bytes) -> bytes:
        """Build a 64-byte HID initialization packet."""
        data_len = len(data)
        header = struct.pack(">IBBB", cid, cmd | 0x80, (data_len >> 8) & 0xFF, data_len & 0xFF)
        payload = data[:MAX_INIT_PAYLOAD]
        return (header + payload).ljust(HID_PACKET_SIZE, b"\x00")
