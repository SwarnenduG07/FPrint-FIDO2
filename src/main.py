"""FIDO2 fingerprint authenticator daemon."""

import signal
import sys
import threading
from hid import FIDOHIDDevice
from ctap2 import CTAP2Handler

CTAPHID_KEEPALIVE = 0x3B
STATUS_UPNEEDED   = 0x02  # waiting for user presence


def send_keepalives(device: FIDOHIDDevice, cid: int, stop: threading.Event) -> None:
    """Send keepalive packets every 100ms until stop is set."""
    import struct
    while not stop.wait(0.1):
        pkt = struct.pack(">IBBB", cid, CTAPHID_KEEPALIVE | 0x80, 0, 1) + bytes([STATUS_UPNEEDED])
        pkt = pkt.ljust(64, b"\x00")
        try:
            device.send(pkt)
        except Exception:
            break


def handle_packet(device: FIDOHIDDevice, ctap: CTAP2Handler, data: bytes) -> None:
    """Handle incoming HID packet from browser — runs in HID read thread."""
    from ctap2 import CTAPHID_CBOR, CTAP2_MAKE_CREDENTIAL, CTAP2_GET_ASSERTION
    import struct

    cid     = struct.unpack_from(">I", data, 0)[0]
    is_init = bool(data[4] & 0x80)
    cmd     = data[4] & 0x7F

    # For long operations, dispatch to a worker thread so HID read loop stays free
    needs_thread = (
        is_init and
        cmd == (CTAPHID_CBOR & 0x7F) and
        len(data) > 7 and
        data[7] in (CTAP2_MAKE_CREDENTIAL, CTAP2_GET_ASSERTION)
    )

    if needs_thread:
        threading.Thread(
            target=_process_packet, args=(device, ctap, data, cid),
            daemon=True
        ).start()
    else:
        _process_packet(device, ctap, data, cid)


def _process_packet(device: FIDOHIDDevice, ctap: CTAP2Handler,
                    data: bytes, cid: int) -> None:
    """Process a packet, sending keepalives while waiting for fingerprint."""
    stop_kav = threading.Event()

    # Start keepalive thread
    kav = threading.Thread(
        target=send_keepalives, args=(device, cid, stop_kav), daemon=True
    )
    kav.start()

    try:
        response = ctap.handle_packet(data)
    finally:
        stop_kav.set()

    if response is None:
        return
    packets = response if isinstance(response, list) else [response]
    for pkt in packets:
        device.send(pkt)


def main() -> None:
    """Entry point."""
    print("Starting linux-hello FIDO2 authenticator...")

    ctap   = CTAP2Handler()
    device = FIDOHIDDevice(on_packet=lambda data: handle_packet(device, ctap, data))

    try:
        device.create()
        print("Virtual HID device created at /dev/uhid")
        device.start()
        print("Listening for packets. Press Ctrl+C to stop.")
        signal.pause()

    except KeyboardInterrupt:
        print("\nStopping...")
    except PermissionError:
        print("Error: Cannot access /dev/uhid. Run with sudo or add udev rule.")
        sys.exit(1)
    finally:
        device.stop()
        print("Stopped.")


if __name__ == "__main__":
    main()
