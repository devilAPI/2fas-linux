#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""
2FAS Linux Taskbar Applet
- Left click  → request 2FA code immediately
- Right click → context menu (Pair Device, Auto-type toggle, Exit)

Requirements:
    pip install cryptography requests websockets Pillow
    # for auto-type:
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import struct
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, unquote

import gi
gi.require_version("Gtk", "4.0")

import dbus
import dbus.service
import dbus.mainloop.glib
import requests
import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_private_key
from gi.repository import GLib, Gtk
from PIL import Image, ImageDraw

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_URL = "https://api2.2fas.com"
WS_URL  = "wss://ws.2fas.com"
CONFIG_DIR  = Path.home() / ".config" / "2fas-applet"
CONFIG_FILE = CONFIG_DIR / "config.json"
SIGNATURE_VERSION = "1"
NONCE_BYTES = 24
WS_TIMEOUT_SECONDS = 175
EXT_NAME = "Linux Desktop"

_SNI_IFACE   = "org.kde.StatusNotifierItem"
_SNW_SERVICE = "org.kde.StatusNotifierWatcher"
_SNW_PATH    = "/StatusNotifierWatcher"
_PROPS_IFACE = "org.freedesktop.DBus.Properties"


# ---------------------------------------------------------------------------
# Icons
# ---------------------------------------------------------------------------

def _make_icon(color: str, size: int = 64) -> Image.Image:
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx   = size // 2
    draw.polygon([(cx,4),(size-4,12),(size-4,size//2+4),
                  (cx,size-4),(4,size//2+4),(4,12)], fill=color)
    r, cy = max(4, size//10), size//2 - max(4,size//10) - 2
    draw.ellipse((cx-r, cy, cx+r, cy+r*2), fill="white")
    draw.rectangle((cx-r, cy+r, cx+r, cy+2*r+r//2), fill="white")
    return img

icon_idle     = lambda: _make_icon("#2196F3")
icon_busy     = lambda: _make_icon("#FF9800")
icon_error    = lambda: _make_icon("#F44336")
icon_unpaired = lambda: _make_icon("#9E9E9E")


def _img_to_sni_pixmap(img: Image.Image):
    """Convert PIL RGBA image → SNI IconPixmap ARGB32 big-endian."""
    img  = img.convert("RGBA").resize((22, 22))
    raw  = img.tobytes()
    data = bytearray()
    for i in range(0, len(raw), 4):
        r, g, b, a = raw[i], raw[i+1], raw[i+2], raw[i+3]
        data += struct.pack(">I", (a << 24) | (r << 16) | (g << 8) | b)
    return dbus.Array(
        [dbus.Struct([dbus.Int32(22), dbus.Int32(22),
                      dbus.Array(data, signature="y")], signature=None)],
        signature="(iiay)",
    )


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def gen_rsa_keypair() -> dict:
    key  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.DER,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    pub  = key.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"private": base64.b64encode(priv).decode(),
            "public":  base64.b64encode(pub).decode()}


def gen_ecdsa_keypair() -> dict:
    key  = ec.generate_private_key(ec.SECP256R1())
    priv = key.private_bytes(serialization.Encoding.DER,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    pub  = key.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"private": base64.b64encode(priv).decode(),
            "public":  base64.b64encode(pub).decode()}


def _load_priv(b64_der: str):
    return load_der_private_key(base64.b64decode(b64_der), password=None)


def decrypt_token(encrypted_b64: str, rsa_priv) -> str:
    ct = base64.b64decode(encrypted_b64)
    return rsa_priv.decrypt(
        ct,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),
                     algorithm=hashes.SHA512(), label=None),
    ).decode("utf-8")


# ---------------------------------------------------------------------------
# Request signing
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.b64encode(data).decode().replace("+", "-").replace("/", "_")

def _hash_body(body: str = "") -> str:
    return _b64url(hashlib.sha256((body or "").encode()).digest())

def _rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def sign_request(method: str, url: str, body: str, ecdsa_priv) -> dict:
    p      = urlparse(url)
    path   = unquote(p.path)
    query  = p.query or ""
    ts     = _rfc3339()
    nonce  = _b64url(secrets.token_bytes(NONCE_BYTES))
    bsha   = _hash_body(body)
    canon  = "\n".join([f"v:{SIGNATURE_VERSION}", f"method:{method.upper()}",
                        f"path:{path}", f"query:{query}", f"body_sha256:{bsha}",
                        f"timestamp:{ts}", f"nonce:{nonce}"])
    sig    = ecdsa_priv.sign(canon.encode(), ec.ECDSA(hashes.SHA256()))
    return {"X-2FAS-Signature-Version": SIGNATURE_VERSION,
            "X-2FAS-Signature-Timestamp": ts,
            "X-2FAS-Signature-Nonce": nonce,
            "X-2FAS-Body-Sha256": bsha,
            "X-2FAS-Signature": _b64url(sig)}


def ws_signing_protocols(ws_url: str, ecdsa_priv) -> list | None:
    try:
        h = sign_request("GET", ws_url, "", ecdsa_priv)
    except Exception:
        return None
    payload   = {"X-2fas-Signature-Version":  h["X-2FAS-Signature-Version"],
                 "X-2fas-Signature-Timestamp": h["X-2FAS-Signature-Timestamp"],
                 "X-2fas-Signature-Nonce":     h["X-2FAS-Signature-Nonce"],
                 "X-2fas-Body-Sha256":         h["X-2FAS-Body-Sha256"],
                 "X-2fas-Signature":           h["X-2FAS-Signature"]}
    jb  = json.dumps(payload, separators=(",", ":")).encode()
    jb += b" " * ((3 - len(jb) % 3) % 3)
    return ["2FAS", _b64url(jb)]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(cfg: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def _jh(extra=None) -> dict:
    h = {"Accept": "application/json", "Content-Type": "application/json"}
    if extra:
        h.update(extra)
    return h


def register_extension(rsa_pub: str, ecdsa_pub: str) -> str:
    r = requests.post(f"{API_URL}/browser_extensions", headers=_jh(),
                      json={"name": EXT_NAME, "browser_name": "Chrome",
                            "browser_version": "1.0",
                            "public_key": rsa_pub,
                            "public_signing_key": ecdsa_pub}, timeout=15)
    r.raise_for_status()
    return r.json()["id"]


def api_request_token(ext_id: str, domain: str, ecdsa_priv) -> str:
    url  = f"{API_URL}/browser_extensions/{ext_id}/commands/request_2fa_token"
    body = json.dumps({"domain": domain})
    r    = requests.post(url, headers=_jh(sign_request("POST", url, body, ecdsa_priv)),
                         data=body, timeout=15)
    r.raise_for_status()
    return r.json()["token_request_id"]


def api_close_request(ext_id: str, req_id: str, ecdsa_priv, completed=True):
    try:
        url  = (f"{API_URL}/browser_extensions/{ext_id}"
                f"/2fa_requests/{req_id}/commands/close_2fa_request")
        body = json.dumps({"status": "completed" if completed else "terminated"})
        requests.post(url, headers=_jh(sign_request("POST", url, body, ecdsa_priv)),
                      data=body, timeout=10)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------

def copy_to_clipboard(text: str) -> bool:
    for cmd in [["wl-copy"], ["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"]]:
        try:
            subprocess.run(cmd, input=text.encode(), check=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    return False


# ---------------------------------------------------------------------------
# Desktop notifications
# ---------------------------------------------------------------------------

def notify(title: str, body: str = "", urgency: str = "normal"):
    try:
        subprocess.run(["notify-send", "-u", urgency, "-t", "4000", title, body],
                       check=False, timeout=5)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Dialogs
# ---------------------------------------------------------------------------

def dialog_info(title: str, text: str):
    try:
        subprocess.run(["zenity", "--info", f"--title={title}",
                        f"--text={text}", "--width=420"],
                       timeout=120, check=False)
    except Exception:
        pass


def show_pairing_dialog(ext_id: str):
    link = f"twofas_c://{ext_id}"
    qr_path = None
    try:
        import qrcode, tempfile
        qr  = qrcode.make(link)
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        qr.save(tmp.name)
        qr_path = tmp.name
        subprocess.Popen(["xdg-open", tmp.name])
    except Exception:
        pass
    msg = (f"Open 2FAS on your phone → tap ⊕ → scan QR\n\n"
           f"Or enter manually:\n{link}")
    if qr_path:
        msg += f"\n\nQR image: {qr_path}"
    dialog_info("2FAS – Pair your phone", msg)


# ---------------------------------------------------------------------------
# Async WebSocket flows
# ---------------------------------------------------------------------------

async def ws_wait_pairing(ext_id: str, ecdsa_priv) -> dict | None:
    ws_url    = f"{WS_URL}/browser_extensions/{ext_id}"
    protocols = ws_signing_protocols(ws_url, ecdsa_priv)
    kw        = {"open_timeout": 15, **({"subprotocols": protocols} if protocols else {})}
    try:
        async with websockets.connect(ws_url, **kw) as ws:
            raw = await asyncio.wait_for(ws.recv(), timeout=WS_TIMEOUT_SECONDS)
            msg = json.loads(raw)
            if msg.get("event") == "browser_extensions.pairing.success":
                return {"device_id":         msg.get("device_id"),
                        "device_name":        msg.get("device_name", ""),
                        "device_public_key":  msg.get("device_public_key")}
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"[2FAS] pairing WS: {e}", file=sys.stderr)
    return None


async def ws_wait_token(ext_id: str, req_id: str, ecdsa_priv) -> str | None:
    ws_url    = f"{WS_URL}/browser_extensions/{ext_id}/2fa_requests/{req_id}"
    protocols = ws_signing_protocols(ws_url, ecdsa_priv)
    kw        = {"open_timeout": 15, **({"subprotocols": protocols} if protocols else {})}
    try:
        async with websockets.connect(ws_url, **kw) as ws:
            raw = await asyncio.wait_for(ws.recv(), timeout=WS_TIMEOUT_SECONDS)
            msg = json.loads(raw)
            if msg.get("event") == "browser_extensions.device.2fa_response":
                return msg.get("token")
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"[2FAS] token WS: {e}", file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# StatusNotifierItem DBus service
# ---------------------------------------------------------------------------

class _SniService(dbus.service.Object):
    """
    Minimal StatusNotifierItem.
    Left click  → Activate()    → on_activate callback
    Right click → waybar reads  /MenuBar via com.canonical.dbusmenu
    """

    def __init__(self, bus, on_activate):
        self._cb_activate = on_activate
        self._img         = icon_unpaired()
        self._title       = "2FAS"

        svc = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        self.bus_name = dbus.service.BusName(svc, bus)
        super().__init__(self.bus_name, "/StatusNotifierItem")

        snw = bus.get_object(_SNW_SERVICE, _SNW_PATH)
        dbus.Interface(snw, _SNW_SERVICE).RegisterStatusNotifierItem(svc)

    # ── SNI methods ────────────────────────────────────────────────

    @dbus.service.method(_SNI_IFACE, in_signature="ii")
    def Activate(self, x, y):
        GLib.idle_add(self._cb_activate)

    @dbus.service.method(_SNI_IFACE, in_signature="ii")
    def ContextMenu(self, x, y):
        pass  # waybar uses dbusmenu at /MenuBar instead

    @dbus.service.method(_SNI_IFACE, in_signature="ii")
    def SecondaryActivate(self, x, y):
        GLib.idle_add(self._cb_activate)

    @dbus.service.method(_SNI_IFACE, in_signature="is")
    def Scroll(self, delta, orientation):
        pass

    # ── Signals ────────────────────────────────────────────────────

    @dbus.service.signal(_SNI_IFACE)
    def NewIcon(self): pass

    @dbus.service.signal(_SNI_IFACE)
    def NewTitle(self): pass

    @dbus.service.signal(_SNI_IFACE)
    def NewStatus(self): pass

    # ── Properties ─────────────────────────────────────────────────

    def _all_props(self):
        pix = _img_to_sni_pixmap(self._img)
        return {
            "Category":            dbus.String("ApplicationStatus"),
            "Id":                  dbus.String("twofas-applet"),
            "Title":               dbus.String(self._title),
            "Status":              dbus.String("Active"),
            "WindowId":            dbus.UInt32(0),
            "IconName":            dbus.String(""),
            "IconThemePath":       dbus.String(""),
            "IconPixmap":          pix,
            "OverlayIconName":     dbus.String(""),
            "OverlayIconPixmap":   dbus.Array([], signature="(iiay)"),
            "AttentionIconName":   dbus.String(""),
            "AttentionIconPixmap": dbus.Array([], signature="(iiay)"),
            "AttentionMovieName":  dbus.String(""),
            "ToolTip":             dbus.Struct(
                ["", dbus.Array([], signature="(iiay)"), self._title, ""],
                signature=None),
            "Menu":                dbus.ObjectPath("/MenuBar"),
            "ItemIsMenu":          dbus.Boolean(False),
        }

    @dbus.service.method(_PROPS_IFACE, in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        return self._all_props()[prop]

    @dbus.service.method(_PROPS_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        return self._all_props()

    @dbus.service.method(_PROPS_IFACE, in_signature="ssv")
    def Set(self, iface, prop, val):
        pass

    # ── Update ─────────────────────────────────────────────────────

    def set_icon(self, img: Image.Image, title: str | None = None):
        self._img = img
        if title is not None:
            self._title = title
        self.NewIcon()
        if title is not None:
            self.NewTitle()


# ---------------------------------------------------------------------------
# com.canonical.dbusmenu  (right-click context menu — waybar reads this)
# ---------------------------------------------------------------------------

class _DbusMenu(dbus.service.Object):
    """
    Minimal com.canonical.dbusmenu implementation.
    The SNI Menu property points here; the tray host (waybar) fetches and
    renders the menu natively at the cursor position.

    Item IDs:
        0 = root  1 = status-label  2 = sep  3 = Pair Device
        4 = Auto-type toggle  5 = sep  6 = Exit
    """
    _IFACE = "com.canonical.dbusmenu"

    def __init__(self, bus_name, applet):
        super().__init__(bus_name, "/MenuBar")
        self._applet   = applet
        self._revision = 1

    # ── helpers ────────────────────────────────────────────────────

    def _items(self):
        cfg        = self._applet.cfg
        configured = self._applet._is_configured
        n          = len(cfg.get("devices", []))
        status     = ("Not paired" if not configured
                      else f"Paired ({n} device{'s' if n != 1 else ''})")
        return [
            (1, {"label": dbus.String(status),
                 "enabled": dbus.Boolean(False)}, []),
            (2, {"type": dbus.String("separator")}, []),
            (3, {"label": dbus.String("Pair Device")}, []),
            (4, {"label": dbus.String("Settings…")}, []),
            (5, {"type": dbus.String("separator")}, []),
            (6, {"label": dbus.String("Exit")}, []),
        ]

    def _struct(self, id, props, children):
        return dbus.Struct(
            [dbus.Int32(id),
             dbus.Dictionary(props, signature="sv"),
             dbus.Array([self._struct(*c) for c in children], signature="v")],
            signature=None,
        )

    def _root(self):
        return self._struct(
            0, {"children-display": dbus.String("submenu")}, self._items()
        )

    # ── dbusmenu methods ───────────────────────────────────────────

    @dbus.service.method(_IFACE, in_signature="iias", out_signature="u(ia{sv}av)")
    def GetLayout(self, parentId, recursionDepth, propertyNames):
        return (dbus.UInt32(self._revision), self._root())

    @dbus.service.method(_IFACE, in_signature="aias", out_signature="a(ia{sv})")
    def GetGroupProperties(self, ids, propertyNames):
        by_id = {id: props for (id, props, _) in self._items()}
        return dbus.Array(
            [dbus.Struct([dbus.Int32(id),
                          dbus.Dictionary(by_id.get(id, {}), signature="sv")],
                         signature=None)
             for id in ids if id in by_id],
            signature="(ia{sv})",
        )

    @dbus.service.method(_IFACE, in_signature="i", out_signature="b")
    def AboutToShow(self, id):
        return dbus.Boolean(False)

    @dbus.service.method(_IFACE, in_signature="ai", out_signature="aib")
    def AboutToShowGroup(self, ids):
        return (dbus.Array([], signature="i"), dbus.Boolean(False))

    @dbus.service.method(_IFACE, in_signature="isvu")
    def Event(self, id, eventId, data, timestamp):
        if eventId != "clicked":
            return
        applet = self._applet
        if id == 3:
            threading.Thread(target=applet._flow_pair, daemon=True).start()
        elif id == 4:
            GLib.idle_add(applet._show_settings)
        elif id == 6:
            GLib.idle_add(applet._quit)

    @dbus.service.method(_IFACE, in_signature="a(isvu)", out_signature="ai")
    def EventGroup(self, events):
        for (id, eventId, data, ts) in events:
            self.Event(id, eventId, data, ts)
        return dbus.Array([], signature="i")

    # ── signals ────────────────────────────────────────────────────

    @dbus.service.signal(_IFACE, signature="ui")
    def LayoutUpdated(self, revision, parent): pass

    @dbus.service.signal(_IFACE, signature="a(ia{sv})a(ia{sv})")
    def ItemsPropertiesUpdated(self, updated, removed): pass

    # ── properties ─────────────────────────────────────────────────

    def _menu_props(self):
        return {"Version":       dbus.UInt32(3),
                "TextDirection": dbus.String("ltr"),
                "Status":        dbus.String("normal"),
                "IconThemePath": dbus.Array([], signature="s")}

    @dbus.service.method(_PROPS_IFACE, in_signature="ss", out_signature="v")
    def Get(self, iface, prop):
        return self._menu_props()[prop]

    @dbus.service.method(_PROPS_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        return self._menu_props()

    @dbus.service.method(_PROPS_IFACE, in_signature="ssv")
    def Set(self, iface, prop, val):
        pass


# ---------------------------------------------------------------------------
# Main applet
# ---------------------------------------------------------------------------

class TwoFasApplet:

    def __init__(self):
        self.cfg           = load_config()
        self._loop         = None
        self._sni          = None
        self._dbus_menu    = None
        self._glib_loop    = None
        self._request_lock = threading.Lock()

    # ── Async loop ────────────────────────────────────────────────

    def _start_async_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _submit(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    # ── Key helpers ───────────────────────────────────────────────

    @property
    def _is_configured(self):
        return bool(self.cfg.get("extensionID") and self.cfg.get("configured"))

    @property
    def _rsa_priv(self):
        return _load_priv(self.cfg["keys"]["rsa_private"])

    @property
    def _ecdsa_priv(self):
        return _load_priv(self.cfg["keys"]["ecdsa_private"])

    # ── Icon helpers ──────────────────────────────────────────────

    def _set_icon(self, img, title=None):
        if self._sni:
            GLib.idle_add(lambda: self._sni.set_icon(img, title))

    # ── Settings window ───────────────────────────────────────────

    def _show_settings(self):
        win = Gtk.Window()
        win.set_title("2FAS – Paired Devices")
        win.set_default_size(420, 300)
        win.set_resizable(True)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        outer.set_margin_start(16)
        outer.set_margin_end(16)
        outer.set_margin_top(16)
        outer.set_margin_bottom(16)
        win.set_child(outer)

        # ── Device list ──
        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        frame = Gtk.Frame()
        frame.set_child(listbox)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_child(frame)
        outer.append(scrolled)

        def _rebuild():
            while True:
                row = listbox.get_row_at_index(0)
                if row is None:
                    break
                listbox.remove(row)

            devices = self.cfg.get("devices", [])
            if not devices:
                lbl = Gtk.Label(label="No devices paired yet.")
                lbl.set_margin_start(12)
                lbl.set_margin_end(12)
                lbl.set_margin_top(10)
                lbl.set_margin_bottom(10)
                row = Gtk.ListBoxRow()
                row.set_child(lbl)
                listbox.append(row)
                return

            for i, device in enumerate(devices):
                raw_id   = device.get("device_id", "")
                name     = device.get("device_name", "").strip()
                label    = name if name else f"Device {i + 1}"
                subtitle = raw_id[:32] + ("…" if len(raw_id) > 32 else "")

                row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                row_box.set_margin_start(10)
                row_box.set_margin_end(10)
                row_box.set_margin_top(8)
                row_box.set_margin_bottom(8)

                info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                info_box.set_hexpand(True)
                name_lbl = Gtk.Label(label=label)
                name_lbl.set_halign(Gtk.Align.START)
                id_lbl   = Gtk.Label(label=subtitle)
                id_lbl.set_halign(Gtk.Align.START)
                id_lbl.add_css_class("dim-label")
                info_box.append(name_lbl)
                info_box.append(id_lbl)
                row_box.append(info_box)

                rm_btn = Gtk.Button(label="Remove")
                rm_btn.add_css_class("destructive-action")

                def _make_remove(device_id):
                    def _on_remove(_):
                        self.cfg["devices"] = [
                            d for d in self.cfg.get("devices", [])
                            if d.get("device_id") != device_id
                        ]
                        if not self.cfg["devices"]:
                            self.cfg["configured"] = False
                        save_config(self.cfg)
                        if self._dbus_menu:
                            self._dbus_menu._revision += 1
                            self._dbus_menu.LayoutUpdated(
                                self._dbus_menu._revision, 0)
                        self._set_icon(
                            icon_idle() if self._is_configured else icon_unpaired(),
                            "2FAS" if self._is_configured else "2FAS (not paired)")
                        _rebuild()
                    return _on_remove

                rm_btn.connect("clicked", _make_remove(raw_id))
                row_box.append(rm_btn)

                row = Gtk.ListBoxRow()
                row.set_child(row_box)
                listbox.append(row)

        _rebuild()

        # ── Pair new device button ──
        pair_btn = Gtk.Button(label="Pair New Device…")
        pair_btn.connect("clicked", lambda _: (
            win.close(),
            threading.Thread(target=self._flow_pair, daemon=True).start(),
        ))
        outer.append(pair_btn)

        win.present()

    # ── Left click: request code ──────────────────────────────────

    def _on_left_click(self):
        if not self._is_configured:
            notify("2FAS", "Pair your phone first (right-click → Pair Device).")
            return
        if not self._request_lock.acquire(blocking=False):
            notify("2FAS", "A code request is already in progress.")
            return
        threading.Thread(target=self._flow_request_code, daemon=True).start()

    def _flow_request_code(self):
        try:
            self._do_request_code()
        finally:
            self._request_lock.release()

    def _do_request_code(self):
        self._set_icon(icon_busy(), "2FAS (requesting…)")
        notify("2FAS", "Asking phone for a code…")

        ext_id      = self.cfg["extensionID"]
        ecdsa_priv  = self._ecdsa_priv
        rsa_priv    = self._rsa_priv

        # 1 – request token
        try:
            req_id = api_request_token(ext_id, "https://desktop.local", ecdsa_priv)
        except Exception as e:
            notify("2FAS – Request failed", str(e), urgency="critical")
            self._set_icon(icon_error(), "2FAS (error)")
            return

        # 2 – wait for encrypted token via WebSocket
        fut = self._submit(ws_wait_token(ext_id, req_id, ecdsa_priv))
        encrypted = None
        try:
            encrypted = fut.result(timeout=WS_TIMEOUT_SECONDS + 10)
        except Exception as e:
            notify("2FAS – Connection error", str(e), urgency="critical")
            api_close_request(ext_id, req_id, ecdsa_priv, completed=False)
        finally:
            self._set_icon(icon_idle(), "2FAS")

        if encrypted is None:
            notify("2FAS – Timed out", "Phone did not respond within 3 minutes.")
            api_close_request(ext_id, req_id, ecdsa_priv, completed=False)
            return

        # 3 – decrypt
        try:
            token = decrypt_token(encrypted, rsa_priv)
        except Exception as e:
            notify("2FAS – Decryption failed", str(e), urgency="critical")
            api_close_request(ext_id, req_id, ecdsa_priv, completed=False)
            return

        api_close_request(ext_id, req_id, ecdsa_priv, completed=True)

        # 4 – deliver: clipboard always, then auto-type if enabled
        if copy_to_clipboard(token):
            notify("2FAS – Code copied!", "Your 2FA code is in the clipboard.")
        else:
            dialog_info("2FAS – Your code",
                        f"{token}\n\n(Clipboard unavailable — copy manually.)")

    # ── Pairing flow ──────────────────────────────────────────────

    def _flow_pair(self):
        if not self.cfg.get("extensionID"):
            notify("2FAS", "Registering with 2FAS…")
            self._set_icon(icon_busy(), "2FAS (registering)")
            try:
                rsa_kp   = gen_rsa_keypair()
                ecdsa_kp = gen_ecdsa_keypair()
                ext_id   = register_extension(rsa_kp["public"], ecdsa_kp["public"])
            except Exception as e:
                notify("2FAS – Registration failed", str(e), urgency="critical")
                self._set_icon(icon_error(), "2FAS (error)")
                return
            self.cfg = {"extensionID": ext_id, "configured": False, "devices": [],
                        "keys": {"rsa_private": rsa_kp["private"],
                                 "rsa_public":  rsa_kp["public"],
                                 "ecdsa_private": ecdsa_kp["private"],
                                 "ecdsa_public":  ecdsa_kp["public"]}}
            save_config(self.cfg)
            notify("2FAS – Registered", "Scan the QR code with your phone.")

        ext_id = self.cfg["extensionID"]
        self._set_icon(icon_busy(), "2FAS (waiting for pairing)")
        threading.Thread(target=show_pairing_dialog, args=(ext_id,), daemon=True).start()

        fut = self._submit(ws_wait_pairing(ext_id, self._ecdsa_priv))
        try:
            result = fut.result(timeout=WS_TIMEOUT_SECONDS + 10)
        except Exception as e:
            notify("2FAS – Pairing error", str(e), urgency="critical")
            self._set_icon(icon_error(), "2FAS (error)")
            return

        if result is None:
            notify("2FAS – Pairing timed out", "No phone paired within 3 minutes.")
            self._set_icon(icon_unpaired(), "2FAS (not paired)")
            return

        devices = self.cfg.get("devices", [])
        if not any(d.get("device_id") == result.get("device_id") for d in devices):
            devices.append(result)
        self.cfg["devices"]    = devices
        self.cfg["configured"] = True
        save_config(self.cfg)
        notify("2FAS – Paired!", "Left-click the icon to request a 2FA code.")
        self._set_icon(icon_idle(), "2FAS")

    # ── Quit ─────────────────────────────────────────────────────

    def _quit(self):
        if self._glib_loop:
            self._glib_loop.quit()
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)

    # ── Entry point ───────────────────────────────────────────────

    def run(self):
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        bus = dbus.SessionBus()

        threading.Thread(target=self._start_async_loop, daemon=True).start()

        try:
            self._sni = _SniService(bus, self._on_left_click)
            self._dbus_menu = _DbusMenu(self._sni.bus_name, self)
        except Exception as e:
            print(f"[2FAS] Could not create StatusNotifierItem: {e}", file=sys.stderr)
            print("Is a StatusNotifierWatcher running? (e.g. waybar with tray module)",
                  file=sys.stderr)
            sys.exit(1)

        img   = icon_idle() if self._is_configured else icon_unpaired()
        title = "2FAS"      if self._is_configured else "2FAS (not paired)"
        self._sni.set_icon(img, title)

        if not self.cfg.get("extensionID"):
            threading.Thread(target=self._flow_pair, daemon=True).start()

        self._glib_loop = GLib.MainLoop()
        self._glib_loop.run()


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    TwoFasApplet().run()
