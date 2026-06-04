"""FIDO2 fingerprint authenticator daemon."""

import signal
import sys
import struct
import threading
import queue
from hid import FIDOHIDDevice
from ctap2 import CTAP2Handler

CTAPHID_KEEPALIVE = 0x3B
STATUS_UPNEEDED   = 0x02


def send_keepalives(device: FIDOHIDDevice, cid: int, stop: threading.Event) -> None:
    """Send keepalive packets every 500ms until stop is set."""
    while not stop.wait(0.5):
        pkt = struct.pack(">IBBB", cid, CTAPHID_KEEPALIVE | 0x80, 0, 1) + bytes([STATUS_UPNEEDED])
        pkt = pkt.ljust(64, b"\x00")
        try:
            device.send(pkt)
        except Exception:
            break


class PacketWorker:
    """
    Single worker thread that processes packets sequentially.
    The HID read loop feeds packets here via a queue so it never blocks.
    """

    def __init__(self, device: FIDOHIDDevice, ctap: CTAP2Handler):
        self._device = device
        self._ctap   = ctap
        self._queue  = queue.Queue()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def submit(self, data: bytes) -> None:
        self._queue.put(data)

    def _run(self) -> None:
        while True:
            data = self._queue.get()
            cid  = struct.unpack_from(">I", data, 0)[0]

            stop_kav = threading.Event()
            kav = threading.Thread(
                target=send_keepalives, args=(self._device, cid, stop_kav), daemon=True
            )
            kav.start()

            try:
                response = self._ctap.handle_packet(data)
            finally:
                stop_kav.set()
                kav.join(timeout=1.0)

            if response is None:
                continue

            for pkt in (response if isinstance(response, list) else [response]):
                self._device.send(pkt)


def main() -> None:
    """Entry point."""
    print("Starting linux-hello FIDO2 authenticator...")

    ctap   = CTAP2Handler()
    device = FIDOHIDDevice(on_packet=lambda data: None)  # placeholder
    worker = PacketWorker(device, ctap)

    # Wire on_packet to worker after both are created
    device._on_packet = worker.submit

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
