"""FIDO2 fingerprint authenticator daemon."""

import signal
import sys
from hid import FIDOHIDDevice
from ctap2 import CTAP2Handler


def handle_packet(device: FIDOHIDDevice, ctap: CTAP2Handler, data: bytes) -> None:
    """Handle incoming HID packet from browser."""
    response = ctap.handle_packet(data)
    if response:
        device.send(response)


def main() -> None:
    """Entry point."""
    print("Starting linux-hello FIDO2 authenticator...")
    
    ctap = CTAP2Handler()
    device = FIDOHIDDevice(on_packet=lambda data: handle_packet(device, ctap, data))
    
    try:
        device.create()
        print("Virtual HID device created at /dev/uhid")
        device.start()
        print("Listening for packets. Press Ctrl+C to stop.")
        
        # Keep running
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
