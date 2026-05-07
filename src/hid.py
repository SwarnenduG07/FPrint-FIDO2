"""Virtual FIDO2 HID device via /dev/uhid."""

import os
import struct
import threading
from typing import Callable

# FIDO2 HID report descriptor (CTAP specification)
FIDO_HID_DESCRIPTOR = bytes([
    0x06, 0xD0, 0xF1,  # Usage Page (FIDO Alliance)
    0x09, 0x01,        # Usage (U2F HID Authenticator Device)
    0xA1, 0x01,        # Collection (Application)
    0x09, 0x20,        #   Usage (Input Report Data)
    0x15, 0x00,        #   Logical Minimum (0)
    0x26, 0xFF, 0x00,  #   Logical Maximum (255)
    0x75, 0x08,        #   Report Size (8 bits)
    0x95, 0x40,        #   Report Count (64 bytes)
    0x81, 0x02,        #   Input (Data, Variable, Absolute)
    0x09, 0x21,        #   Usage (Output Report Data)
    0x15, 0x00,        #   Logical Minimum (0)
    0x26, 0xFF, 0x00,  #   Logical Maximum (255)
    0x75, 0x08,        #   Report Size (8 bits)
    0x95, 0x40,        #   Report Count (64 bytes)
    0x91, 0x02,        #   Output (Data, Variable, Absolute)
    0xC0,              # End Collection
])

# uhid event types (from linux/uhid.h)
UHID_CREATE2 = 11
UHID_DESTROY = 1
UHID_INPUT2 = 12
UHID_OUTPUT = 6

HID_PACKET_SIZE = 64


class FIDOHIDDevice:
    """Virtual FIDO2 HID device using /dev/uhid."""

    def __init__(self, on_packet: Callable[[bytes], None]):
        """
        Initialize the virtual HID device.
        
        Args:
            on_packet: Callback invoked when a packet is received from the host
        """
        self._on_packet = on_packet
        self._fd = None
        self._running = False
        self._thread = None

    def create(self) -> None:
        """Create and register the virtual HID device."""
        self._fd = open("/dev/uhid", "r+b", buffering=0)
        self._fileno = self._fd.fileno()

        # Build UHID_CREATE2 event
        name = b"linux-hello FIDO2".ljust(128, b"\x00")
        phys = b"".ljust(64, b"\x00")
        uniq = b"".ljust(64, b"\x00")
        rd_size = len(FIDO_HID_DESCRIPTOR)
        bus = 0x03  # BUS_USB
        vendor = 0x1209  # pid.codes open-source VID
        product = 0x0001
        version = 0x0100
        country = 0
        rd_data = FIDO_HID_DESCRIPTOR.ljust(4096, b"\x00")

        event = struct.pack("<I", UHID_CREATE2)
        event += name + phys + uniq
        event += struct.pack("<HHIIII", rd_size, bus, vendor, product, version, country)
        event += rd_data

        os.write(self._fileno, event)

    def send(self, data: bytes) -> None:
        """
        Send a 64-byte HID report to the host.

        Args:
            data: Exactly 64 bytes to send
        """
        if len(data) != HID_PACKET_SIZE:
            raise ValueError(f"HID packet must be {HID_PACKET_SIZE} bytes")

        # uhid_input2_req: size(2) + data[4096]
        # Prepend HID report ID (0x00)
        report = b"\x00" + data
        event = struct.pack("<IH", UHID_INPUT2, len(report)) + report.ljust(4096, b"\x00")
        print(f"[HID] SEND {data.hex()[:32]}...", flush=True)
        os.write(self._fileno, event)

    def start(self) -> None:
        """Start listening for packets from the host."""
        self._running = True
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the device and clean up."""
        self._running = False
        if self._fd:
            destroy_event = struct.pack("<I", UHID_DESTROY)
            self._fd.write(destroy_event)
            self._fd.close()
            self._fd = None

    def _read_loop(self) -> None:
        """Background thread that reads events from /dev/uhid."""
        # Max event size: type(4) + uhid_output_req: data(4096) + size(2) + rtype(1) = 4103
        EVENT_SIZE = 4103
        while self._running:
            try:
                raw = os.read(self._fileno, EVENT_SIZE)
                if not raw:
                    continue

                event_type = struct.unpack_from("<I", raw)[0]
                print(f"[HID] event_type={event_type} len={len(raw)}", flush=True)

                if event_type == UHID_OUTPUT:
                    # uhid_output_req: data[4096] + size(2) + rtype(1)
                    data_blob = raw[4 : 4 + 4096]
                    size = struct.unpack_from("<H", raw, 4 + 4096)[0]
                    payload = data_blob[:size]
                    # Strip leading HID report ID byte (0x00)
                    if payload and payload[0] == 0x00:
                        payload = payload[1:]
                    print(f"[HID] OUTPUT size={size} payload={payload.hex()}", flush=True)
                    if len(payload) >= HID_PACKET_SIZE:
                        self._on_packet(payload[:HID_PACKET_SIZE])

            except OSError:
                break
