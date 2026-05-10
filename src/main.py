"""FIDO2 fingerprint authenticator daemon."""

import signal
import sys
import struct
import threading
from hid import FIDOHIDDevice
from ctap2 import CTAP2Handler

CTAPHID_KEEPALIVE = 0x3B
STATUS_UPNEEDED   = 0x02


def send_keepalives(device: FIDOHIDDevice, cid: int, stop: threading.Event) -> None:
    """Send keepalive packets every 100ms until stop is set."""
    while not stop.wait(0.1):
        pkt = struct.pack(">IBBB", cid, CTAPHID_KEEPALIVE | 0x80, 0, 1) + bytes([STATUS_UPNEEDED])
        pkt = pkt.ljust(64, b"\x00")
        try:
            device.send(pkt)
        except Exception:
            break


def handle_packet(device: FIDOHIDDevice, ctap: CTAP2Handler, data: bytes) -> None:
    """Handle incoming HID packet — runs in HID read thread."""
    response = ctap.handle_packet(data)
    if response is None:
        return

    # If this is a long-op response, send keepalives were already running.
    # Just send the response packets.
    packets = response if isinstance(response, list) else [response]
    for pkt in packets:
        device.send(pkt)


def main() -> None:
    """Entry point."""
    print("Starting linux-hello FIDO2 authenticator...")

    ctap   = CTAP2Handler()

    # Pass device reference to ctap so it can send keepalives during fingerprint
    def on_packet(data: bytes) -> None:
        handle_packet(device, ctap, data)

    device = FIDOHIDDevice(on_packet=on_packet)
    ctap.set_device(device)

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
