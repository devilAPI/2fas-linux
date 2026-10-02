# 2FAS Linux Applet

A system tray applet for Linux that integrates with the [2FAS](https://2fas.com) phone app to deliver 2FA codes to your desktop.

## How it works

- **Left-click** the tray icon → pushes a notification to your phone, waits for you to select an account, then copies the code to your clipboard.
- **Right-click** → context menu with: Pair Device, Settings, Exit.
- **Settings** → manage paired phones (see device names, remove devices).

Codes are decrypted locally using an RSA keypair stored in `~/.config/2fas-applet/config.json`. Nothing is sent to any third party beyond the official 2FAS API.

## Requirements

- Linux with a StatusNotifierItem-compatible tray (Waybar, KDE Plasma, etc.)
- Python 3.11+
- GTK 4 + GLib (usually pre-installed)
- `dbus-python`

```
pip install cryptography requests websockets Pillow dbus-python
```

For clipboard support, install one of: `wl-copy` (Wayland), `xclip`, or `xsel`.

## Setup

```bash
python3 2fas-applet.py
```

On first run it registers with the 2FAS API and shows a pairing dialog. Open the 2FAS app on your phone, tap **+** and scan the QR code. After pairing, left-clicking the icon will request codes.

To start it automatically, add it to your compositor's autostart (e.g. `exec-once = python3 /path/to/2fas-applet.py` in Hyprland).

## Notes

- Config is stored at `~/.config/2fas-applet/config.json`
- Multiple phones can be paired; manage them via right-click → Settings
- The applet uses the same API and crypto as the official browser extension
