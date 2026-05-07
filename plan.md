# FPrint-FIDO2 Bridge — Build Plan

## What We're Building
A software FIDO2 authenticator that uses your laptop's fingerprint sensor for user verification, appearing as a real security key to browsers.

## Why
- Browsers support WebAuthn/FIDO2 natively — no extensions needed
- Your fingerprint sensor (ELAN Match-on-Chip 2) works but can't talk FIDO2 directly
- We bridge the gap entirely in software using `/dev/uhid` (already available on your system)

---

## Architecture

```
Firefox/Chrome
     │  WebAuthn API
     ▼
/dev/uhid  ◄── our daemon (virtual FIDO2 HID device)
     │
     ├── CTAP2 protocol handler (parse browser requests)
     ├── Credential store (encrypted local file)
     └── fprintd D-Bus (fingerprint verify instead of PIN)
```

---

## Components

### 1. Virtual HID Device
- Open `/dev/uhid`, register as a FIDO2 HID device
- Browser discovers it like a USB security key
- Library: `uhid-python`

### 2. CTAP2 Protocol Handler
- `authenticatorGetInfo` — tell browser our capabilities
- `authenticatorMakeCredential` — register on a website
- `authenticatorGetAssertion` — login to a website
- Library: `python-fido2` (reuse its CBOR/CTAP2 parsing)

### 3. Fingerprint Verification
- When browser asks for user verification (UV flag)
- Call `fprintd` via D-Bus → user touches sensor → verified
- Fallback: reject after N failed attempts

### 4. Credential Storage
- Store private keys + metadata per site
- Location: `~/.local/share/fido2-fprint/credentials.db`
- Encrypted with a master key derived from login keyring
- Backend: sqlite3 (stdlib)

---

## Tech Stack

| Library | Purpose |
|---------|---------|
| `python-fido2` | CTAP2/CBOR protocol handling |
| `uhid-python` | Virtual HID device via `/dev/uhid` |
| `cryptography` | P-256 key generation (ES256) |
| `dbus-python` | Talk to fprintd |
| `sqlite3` | Credential storage (stdlib) |

---

## Build Order

| Step | What | Done |
|------|------|------|
| 1 | Virtual HID device that browser detects | ☐ |
| 2 | `authenticatorGetInfo` response | ☐ |
| 3 | `authenticatorMakeCredential` (register) | ☐ |
| 4 | Fingerprint verification via fprintd | ☐ |
| 5 | `authenticatorGetAssertion` (login) | ☐ |
| 6 | Credential storage (sqlite3 + encryption) | ☐ |
| 7 | udev rules + systemd user service | ☐ |

---

## Out of Scope
- PIN fallback (fingerprint only)
- NFC/BLE transport (USB HID only)
- Enterprise/batch attestation
- Multi-device credential sync

---

## System Info
- OS: CachyOS (Arch-based), kernel 7.0.3-1-cachyos
- Fingerprint sensor: ELAN Match-on-Chip 2 (already enrolled, fprintd working)
- `/dev/uhid`: available and ready
- sudo fingerprint: working
- Lock screen fingerprint: working

---

## End Result
- Register fingerprint on GitHub, Google, etc. as a security key
- Touch sensor to log in — no password needed
- Works in Firefox and Chrome
- Fully local, no cloud, no hardware dongle
