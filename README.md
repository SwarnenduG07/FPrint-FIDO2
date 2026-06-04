# linux-hello

A software FIDO2 authenticator for Linux that uses your laptop's fingerprint sensor for WebAuthn — the Linux equivalent of Windows Hello.

## What it does

- Appears as a USB security key to browsers (via `/dev/uhid`)
- Uses your fingerprint sensor (via `fprintd`) for user verification
- Stores credentials locally in SQLite (`~/.local/share/linux-hello/credentials.db`)
- Works in Firefox and Chrome with any WebAuthn-enabled website

## Requirements

- Linux with `/dev/uhid` (most modern kernels)
- `fprintd` with enrolled fingerprints
- Python 3.14+
- `uv` package manager

## Setup

**1. Install dependencies**

```bash
uv sync
```

**2. Enroll your fingerprint** (if not already done)

```bash
fprintd-enroll
```

**3. Install udev rule** (allows browser access to the virtual device)

```bash
sudo cp 70-uhid.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo modprobe -r uhid && sudo modprobe uhid
```

**4. Add yourself to the `input` group** (log out and back in after)

```bash
sudo usermod -aG input $USER
```

## Running

```bash
sudo uv run src/main.py
```

The daemon must run as root to write to `/dev/uhid`. Then register on any WebAuthn site (e.g. [webauthn.io](https://webauthn.io)):

1. Go to the site and click Register
2. Choose **USB security key** when prompted
3. Touch your fingerprint sensor
4. Done — credential is saved locally

## Architecture

```
Browser (WebAuthn)
      │
      ▼
/dev/uhid  ←── linux-hello daemon
      │
      ├── src/hid.py      Virtual HID device
      ├── src/ctap2.py    CTAP2 protocol (INIT, GetInfo, MakeCredential, GetAssertion)
      ├── src/fprint.py   Fingerprint verification via fprintd D-Bus
      ├── src/crypto.py   P-256 key generation and signing
      └── src/store.py    SQLite credential storage
```

## Project Structure

```
linux-hello/
├── src/
│   ├── main.py       Entry point and packet dispatch
│   ├── hid.py        Virtual FIDO2 HID device via /dev/uhid
│   ├── ctap2.py      CTAP2 protocol handler
│   ├── fprint.py     fprintd D-Bus bridge
│   ├── crypto.py     Cryptographic operations (ES256/P-256)
│   └── store.py      Credential storage (SQLite)
├── 70-uhid.rules     udev rule for device permissions
├── fido2-fprint.service  systemd user service (WIP)
├── plan.md           Build plan
└── pyproject.toml
```

## Status

| Feature | Status |
|---------|--------|
| Virtual HID device | ✅ Working |
| CTAP2 INIT / GetInfo | ✅ Working |
| MakeCredential (register) | ✅ Working |
| Fingerprint verification | ✅ Working |
| GetAssertion (login) | ⏳ In progress |
| systemd auto-start | ⏳ Todo |

## Dependencies

| Package | Purpose |
|---------|---------|
| `fido2` | CTAP2/CBOR protocol handling |
| `cryptography` | P-256 key generation and signing |
| `dbus-python` | fprintd D-Bus interface |
| `cbor2` | CBOR encoding/decoding |
| `python-gobject` | GLib main loop for D-Bus signals |
