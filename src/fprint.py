"""fprintd D-Bus bridge for fingerprint verification."""

import os
import threading
import dbus
import dbus.mainloop.glib
from gi.repository import GLib

# Must be set before any DBus connection is created
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

_REAL_USER = os.environ.get("SUDO_USER") or os.environ.get("USER") or "sunny"


def verify_fingerprint(timeout: int = 30) -> bool:
    """
    Verify fingerprint via fprintd D-Bus API.
    Returns True if fingerprint matched, False otherwise.
    """
    matched = [False]
    done    = threading.Event()
    dev     = [None]

    def on_verify_status(status, is_done):
        print(f"[FPRINT] status={status} done={is_done}", flush=True)
        if status == "verify-match":
            matched[0] = True
        if is_done or status in ("verify-match", "verify-no-match",
                                 "verify-unknown-error", "verify-disconnected"):
            done.set()

    try:
        bus = dbus.SystemBus()
        mgr = dbus.Interface(
            bus.get_object("net.reactivated.Fprint", "/net/reactivated/Fprint/Manager"),
            "net.reactivated.Fprint.Manager"
        )
        dev[0] = dbus.Interface(
            bus.get_object("net.reactivated.Fprint", mgr.GetDefaultDevice()),
            "net.reactivated.Fprint.Device"
        )
        dev[0].connect_to_signal("VerifyStatus", on_verify_status)
        dev[0].Claim(_REAL_USER)
        dev[0].VerifyStart("any")
        print(f"[FPRINT] Touch fingerprint sensor (user={_REAL_USER})...", flush=True)

        # Wait for result
        done.wait(timeout=timeout)

    except dbus.DBusException as e:
        print(f"[FPRINT] D-Bus error: {e}", flush=True)
    finally:
        if dev[0]:
            try:
                dev[0].VerifyStop()
            except dbus.DBusException:
                pass
            try:
                dev[0].Release()
            except dbus.DBusException:
                pass

    return matched[0]


def _start_glib_loop() -> None:
    """Run GLib main loop in background thread to process D-Bus signals."""
    loop = GLib.MainLoop()
    loop.run()


# Start GLib loop once at module load
threading.Thread(target=_start_glib_loop, daemon=True).start()
