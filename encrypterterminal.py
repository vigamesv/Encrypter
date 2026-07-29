#!/usr/bin/env python3
"""Encrypter -- cross-platform password vault / text & file encryption tool.
Runs on Windows, macOS, and Linux. Requires Python 3.8+ with tkinter and the
`cryptography` package (AES-256-GCM, OpenSSL-backed, identical on every OS).
Passphrase strings can't be wiped from memory (CPython str immutability) --
key material is routed through bytearrays and explicitly zeroed/locked instead,
which is possible in Python and closes most of the gap versus a C++ build's
sodium_memzero/mlock. Locking is best-effort: on Linux it's commonly refused
for an unprivileged process (RLIMIT_MEMLOCK) and is silently skipped -- the
zeroing still happens regardless of whether the lock succeeded."""

import sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit(
        "Missing dependency: 'cryptography'.\n"
        "Install it with:\n    " + sys.executable + " -m pip install cryptography"
    )

import ctypes
import os
import struct
import json
import hashlib
import secrets
import tkinter as tk
from tkinter import ttk, filedialog

KEY_LEN = 32
IV_LEN = 12
TAG_LEN = 16
SALT_LEN = 16
WRAP_LEN = SALT_LEN + IV_LEN + TAG_LEN + KEY_LEN

MAGIC = b"PYE1"
VAULT_MAGIC = b"PYV1"

AAD_TEXT_CTX = b"PYENC-TEXT-v1"
AAD_FILE_CTX = b"PYENC-FILE-v1"
AAD_VAULT_CTX = b"PYENC-VAULT-v1"
AAD_ROLE_PRIMARY = b"role:primary"
AAD_ROLE_RECOVERY = b"role:recovery"

SCRYPT_N = 1 << 16
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 192 * 1024 * 1024


# =====================================================================
#  Memory hygiene: zero/lock bytearrays holding key material.
#  Locking uses the right OS call for the current platform; if it's
#  unavailable or refused (unprivileged process), we skip it silently --
#  zeroing still always happens.
# =====================================================================


def _zero(buf: bytearray):
    if buf:
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


if sys.platform == "win32":
    _kernel32 = ctypes.windll.kernel32

    def _lock(buf: bytearray):
        try:
            addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
            _kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf)))
        except Exception:
            pass

    def _unlock(buf: bytearray):
        try:
            addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
            _kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf)))
        except Exception:
            pass

else:
    try:
        _libc = ctypes.CDLL("libc.so.6" if sys.platform.startswith("linux") else None, use_errno=True)
    except OSError:
        _libc = None

    def _lock(buf: bytearray):
        if not _libc:
            return
        try:
            addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
            _libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf)))
        except Exception:
            pass  # commonly refused for an unprivileged process (RLIMIT_MEMLOCK)

    def _unlock(buf: bytearray):
        if not _libc:
            return
        try:
            addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
            _libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf)))
        except Exception:
            pass


# =====================================================================
#  AES-256-GCM via the `cryptography` package (OpenSSL-backed, identical
#  on Windows/macOS/Linux). Kept the exact same function signatures as the
#  original Windows-CNG implementation so nothing else in this file changes.
# =====================================================================

class BCryptError(Exception):
    """Generic crypto-operation error. Name kept as-is (rather than renamed)
    so the many call sites elsewhere in this file that catch it don't need
    to change."""
    pass


def aes_gcm_encrypt(key, nonce, plaintext, aad: bytes = b""):
    combined = AESGCM(bytes(key)).encrypt(bytes(nonce), bytes(plaintext), aad if aad else None)
    return combined[:-TAG_LEN], combined[-TAG_LEN:]


def aes_gcm_decrypt(key, nonce, ciphertext, tag, aad: bytes = b"") -> bytearray:
    try:
        plaintext = AESGCM(bytes(key)).decrypt(bytes(nonce), bytes(ciphertext) + bytes(tag), aad if aad else None)
    except Exception as e:
        raise BCryptError(f"decrypt failed (authentication failed): {e}")
    return bytearray(plaintext)



# =====================================================================
#  Key derivation + key-wrap (mirrors the C++ KeyWrap layout: salt|nonce|tag|enc_key)
# =====================================================================

def derive_key(passphrase: str, salt: bytes) -> bytearray:
    raw = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAXMEM, dklen=KEY_LEN)
    key = bytearray(raw)
    _lock(key)
    return key


class KeyWrap:
    __slots__ = ("salt", "nonce", "tag", "enc_key")

    def __init__(self, salt, nonce, tag, enc_key):
        self.salt, self.nonce, self.tag, self.enc_key = salt, nonce, tag, enc_key


def wrap_key(passphrase: str, dek, role_aad: bytes) -> KeyWrap:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(IV_LEN)
    kek = derive_key(passphrase, salt)
    try:
        enc_key, tag = aes_gcm_encrypt(kek, nonce, dek, role_aad)
    finally:
        _zero(kek)
        _unlock(kek)
    return KeyWrap(salt, nonce, tag, enc_key)


def unwrap_key(passphrase: str, wrap: KeyWrap, role_aad: bytes) -> bytearray:
    kek = derive_key(passphrase, wrap.salt)
    try:
        dek = aes_gcm_decrypt(kek, wrap.nonce, wrap.enc_key, wrap.tag, role_aad)
    finally:
        _zero(kek)
        _unlock(kek)
    _lock(dek)
    return dek


def wrap_to_bytes(w: KeyWrap) -> bytes:
    return w.salt + w.nonce + w.tag + w.enc_key


def wrap_from_bytes(b: bytes) -> KeyWrap:
    p = 0
    salt = b[p:p + SALT_LEN]; p += SALT_LEN
    nonce = b[p:p + IV_LEN]; p += IV_LEN
    tag = b[p:p + TAG_LEN]; p += TAG_LEN
    enc_key = b[p:p + KEY_LEN]
    return KeyWrap(salt, nonce, tag, enc_key)


def to_hex(b: bytes) -> str:
    return b.hex()


def from_hex(s: str) -> bytes:
    return bytes.fromhex(s.strip())


def generate_passphrase(num_groups=6, group_size=4) -> str:
    charset = "ABCDEFGHJKLMNPQRSTUVWXYZ" "abcdefghijkmnpqrstuvwxyz" "23456789"
    groups = ["".join(secrets.choice(charset) for _ in range(group_size)) for _ in range(num_groups)]
    return "-".join(groups)


def generate_site_password(length=20) -> str:
    charset = "ABCDEFGHJKLMNPQRSTUVWXYZ" "abcdefghijkmnpqrstuvwxyz" "23456789" "!@#$%^&*()-_=+[]{}"
    return "".join(secrets.choice(charset) for _ in range(length))


# =====================================================================
#  Dark theme
# =====================================================================

ACCENT_COLOR = "#121318"
ACCENT_SUBTEXT = "#8c94a8"
BODY_COLOR = "#1c1e24"
EDIT_BG_COLOR = "#14161b"
TEXT_COLOR = "#e6e8ed"
BORDER_COLOR = "#3c404a"
BTN_BG = "#2a2d36"
BTN_BG_HOVER = "#383c48"
BTN_BG_PRESSED = "#1e2027"
BTN_PRIMARY_BG = "#4a66d6"
BTN_PRIMARY_BG_HOVER = "#5c78e6"
BTN_PRIMARY_BG_PRESSED = "#3a54b2"
ERROR_TEXT = "#ff8080"

FONT_NORMAL = ("Segoe UI", 10)
FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_SUBTITLE = ("Segoe UI", 9)

MARGIN = 18


def hex_to_rgb(color):
    color = color.lstrip("#")
    return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))


def rgb_to_hex(r, g, b):
    return f"#{r:02x}{g:02x}{b:02x}"


def adjust_brightness(color, delta):
    r, g, b = hex_to_rgb(color)
    r = max(0, min(255, r + delta))
    g = max(0, min(255, g + delta))
    b = max(0, min(255, b + delta))
    return rgb_to_hex(r, g, b)


def draw_vertical_gradient(canvas, x1, y1, x2, y2, color_top, color_bottom):
    r1, g1, b1 = hex_to_rgb(color_top)
    r2, g2, b2 = hex_to_rgb(color_bottom)
    height = int(y2 - y1)
    if height <= 0:
        return
    for i in range(height):
        t = i / max(height - 1, 1)
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        canvas.create_line(x1, y1 + i, x2, y1 + i, fill=rgb_to_hex(r, g, b))


def rounded_rect_points(x1, y1, x2, y2, r):
    r = min(r, (x2 - x1) / 2, (y2 - y1) / 2)
    return [
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    ]


def draw_rounded_rect(canvas, x1, y1, x2, y2, r=8, **kwargs):
    return canvas.create_polygon(rounded_rect_points(x1, y1, x2, y2, r), smooth=True, **kwargs)


def apply_dark_titlebar(window):
    """Windows-only cosmetic touch (dark titlebar via DWM). No-op elsewhere --
    macOS follows the system light/dark appearance automatically, and most
    Linux window managers don't expose an equivalent per-window API."""
    if sys.platform != "win32":
        return
    try:
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        dwmapi = ctypes.windll.dwmapi
        value = ctypes.c_int(1)
        for attr in (20, 19):
            hr = dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(value), ctypes.sizeof(value))
            if hr == 0:
                break
    except Exception:
        pass


def center_window(win, parent, width, height):
    win.update_idletasks()
    if parent is not None and parent.winfo_exists():
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
    else:
        px, py = 0, 0
        pw, ph = win.winfo_screenwidth(), win.winfo_screenheight()
    x = px + (pw - width) // 2
    y = py + (ph - height) // 2
    win.geometry(f"{width}x{height}+{x}+{y}")


class RoundedButton(tk.Canvas):
    def __init__(self, parent, text, command=None, width=200, height=40, primary=False, radius=8, font=None, bg=BODY_COLOR):
        super().__init__(parent, width=width, height=height, bg=bg, highlightthickness=0, bd=0, cursor="hand2")
        self.command = command
        self.primary = primary
        self.radius = radius
        self.text = text
        self.font = font or FONT_NORMAL
        self.w = width
        self.h = height
        self._state = "idle"
        self._draw()
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _colors(self):
        if self.primary:
            return {"idle": BTN_PRIMARY_BG, "hover": BTN_PRIMARY_BG_HOVER, "pressed": BTN_PRIMARY_BG_PRESSED}
        return {"idle": BTN_BG, "hover": BTN_BG_HOVER, "pressed": BTN_BG_PRESSED}

    def _draw(self):
        self.delete("all")
        color = self._colors()[self._state]
        border = color if self.primary else BORDER_COLOR
        draw_rounded_rect(self, 1, 1, self.w - 1, self.h - 1, self.radius, fill=color, outline=border)
        fg = "#ffffff" if self.primary else TEXT_COLOR
        self.create_text(self.w // 2, self.h // 2, text=self.text, fill=fg, font=self.font)

    def _on_enter(self, _e):
        if self._state != "pressed":
            self._state = "hover"
            self._draw()

    def _on_leave(self, _e):
        self._state = "idle"
        self._draw()

    def _on_press(self, _e):
        self._state = "pressed"
        self._draw()

    def _on_release(self, e):
        inside = 0 <= e.x <= self.w and 0 <= e.y <= self.h
        self._state = "hover" if inside else "idle"
        self._draw()
        if inside and self.command:
            self.command()


# =====================================================================
#  Dialogs
# =====================================================================

def show_message(parent, title, message, is_error=False):
    win = tk.Toplevel(parent)
    win.title(title)
    win.configure(bg=BODY_COLOR)
    win.resizable(False, False)
    win.transient(parent)
    width, height = 420, 170
    apply_dark_titlebar(win)

    fg = ERROR_TEXT if is_error else TEXT_COLOR
    tk.Label(win, text=message, bg=BODY_COLOR, fg=fg, font=FONT_NORMAL, justify="left",
             wraplength=width - 2 * MARGIN, anchor="w").pack(padx=MARGIN, pady=(MARGIN, 10), fill="both", expand=True)

    btn_frame = tk.Frame(win, bg=BODY_COLOR)
    btn_frame.pack(pady=(0, MARGIN))
    RoundedButton(btn_frame, "OK", command=win.destroy, width=100, height=32, primary=True).pack()

    win.protocol("WM_DELETE_WINDOW", win.destroy)
    win.bind("<Return>", lambda e: win.destroy())
    win.bind("<Escape>", lambda e: win.destroy())
    center_window(win, parent, width, height)
    win.grab_set()
    win.wait_window()


def show_input_dialog(parent, title, prompt, masked=False, multiline=False, default="", read_only=False):
    result = {"ok": False, "value": ""}
    win = tk.Toplevel(parent)
    win.title(title)
    win.configure(bg=BODY_COLOR)
    win.resizable(False, False)
    win.transient(parent)
    width = 480
    height = (230 if multiline else 130) + (0 if not read_only else 8)
    apply_dark_titlebar(win)

    tk.Label(win, text=prompt, bg=BODY_COLOR, fg=TEXT_COLOR, font=FONT_NORMAL, anchor="w",
             justify="left", wraplength=width - 2 * MARGIN).pack(fill="x", padx=MARGIN, pady=(MARGIN, 6))

    entry = None
    var = None
    if multiline:
        frame = tk.Frame(win, bg=BORDER_COLOR)
        frame.pack(fill="both", expand=True, padx=MARGIN, pady=(0, 6))
        entry = tk.Text(frame, height=8, bg=EDIT_BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR,
                         relief="flat", wrap="word", font=FONT_NORMAL)
        entry.pack(fill="both", expand=True, padx=1, pady=1)
        if default:
            entry.insert("1.0", default)
        if read_only:
            entry.configure(state="disabled")
    else:
        var = tk.StringVar(value=default)
        entry = tk.Entry(win, textvariable=var, show="*" if masked else "", bg=EDIT_BG_COLOR, fg=TEXT_COLOR,
                          insertbackground=TEXT_COLOR, relief="flat", font=FONT_NORMAL, highlightthickness=1,
                          highlightbackground=BORDER_COLOR, highlightcolor=BTN_PRIMARY_BG)
        entry.pack(fill="x", padx=MARGIN, pady=(0, 6), ipady=4)
        if read_only:
            entry.configure(state="readonly", readonlybackground=EDIT_BG_COLOR)

    def get_value():
        if multiline:
            prev_state = str(entry.cget("state"))
            if prev_state == "disabled":
                entry.configure(state="normal")
                val = entry.get("1.0", "end-1c")
                entry.configure(state="disabled")
                return val
            return entry.get("1.0", "end-1c")
        return var.get()

    def on_ok():
        result["value"] = get_value()
        result["ok"] = True
        win.destroy()

    def on_cancel():
        result["ok"] = False
        win.destroy()

    def on_copy():
        win.clipboard_clear()
        win.clipboard_append(get_value())

    btn_frame = tk.Frame(win, bg=BODY_COLOR)
    btn_frame.pack(fill="x", padx=MARGIN, pady=(6, MARGIN))

    if read_only:
        RoundedButton(btn_frame, "Copy to Clipboard", command=on_copy, width=170, height=30).pack(side="left")
        RoundedButton(btn_frame, "Close", command=on_cancel, width=90, height=30, primary=True).pack(side="right")
    else:
        RoundedButton(btn_frame, "Cancel", command=on_cancel, width=90, height=30).pack(side="right")
        RoundedButton(btn_frame, "OK", command=on_ok, width=90, height=30, primary=True).pack(side="right", padx=(0, 8))

    def on_return(_e):
        if read_only:
            on_cancel()
        elif multiline and win.focus_get() is entry:
            return
        else:
            on_ok()

    win.bind("<Return>", on_return)
    win.bind("<Escape>", lambda e: on_cancel())
    win.protocol("WM_DELETE_WINDOW", on_cancel)

    entry.focus_set()
    center_window(win, parent, width, height)
    win.grab_set()
    win.wait_window()
    return result["value"], result["ok"]


def show_copyable_dialog(parent, title, prompt, text, multiline):
    show_input_dialog(parent, title, prompt, masked=False, multiline=multiline, default=text, read_only=True)


def show_choice_dialog(parent, title, message, option1, option2):
    result = {"choice": 0}
    win = tk.Toplevel(parent)
    win.title(title)
    win.configure(bg=BODY_COLOR)
    win.resizable(False, False)
    win.transient(parent)
    width, height = 440, 170
    apply_dark_titlebar(win)

    tk.Label(win, text=message, bg=BODY_COLOR, fg=TEXT_COLOR, font=FONT_NORMAL, justify="left",
             wraplength=width - 2 * MARGIN, anchor="w").pack(padx=MARGIN, pady=(MARGIN, 14), fill="x")

    btn_frame = tk.Frame(win, bg=BODY_COLOR)
    btn_frame.pack()

    def pick(n):
        result["choice"] = n
        win.destroy()

    RoundedButton(btn_frame, option1, command=lambda: pick(1), width=170, height=34, primary=True).pack(side="left", padx=8)
    RoundedButton(btn_frame, option2, command=lambda: pick(2), width=170, height=34).pack(side="left", padx=8)

    win.protocol("WM_DELETE_WINDOW", lambda: pick(0))
    win.bind("<Return>", lambda e: pick(1))
    win.bind("<Escape>", lambda e: pick(0))

    center_window(win, parent, width, height)
    win.grab_set()
    win.wait_window()
    return result["choice"]


def obtain_passphrase_gui(parent, label):
    choice = show_choice_dialog(parent, f"{label.capitalize()} passphrase",
        f"Generate a strong random {label} passphrase,\nor enter your own?", "Generate for me", "I'll enter my own")
    if choice == 0:
        return ""
    if choice == 1:
        generated = generate_passphrase()
        show_message(parent, f"Generated {label} passphrase",
            "A random passphrase has been generated for you.\n\n"
            "It is shown ONLY ONCE and is never saved by this program.\n"
            "Write it down now (password manager, paper, etc.) -- without it,\n"
            "this can NEVER be decrypted again, by this program or anyone else.")
        show_copyable_dialog(parent, f"Your generated {label} passphrase", "Copy this now -- it will not be shown again:", generated, False)
        return generated
    p1, ok1 = show_input_dialog(parent, f"Enter {label} passphrase", f"Enter your {label} passphrase:", masked=True)
    if not ok1:
        return ""
    p2, ok2 = show_input_dialog(parent, f"Confirm {label} passphrase", f"Confirm your {label} passphrase:", masked=True)
    if not ok2:
        return ""
    if p1 != p2:
        show_message(parent, "Mismatch", "Passphrases did not match.", is_error=True)
        return ""
    return p1


# =====================================================================
#  Text / file actions
# =====================================================================

def do_encrypt_text(parent):
    plaintext, ok = show_input_dialog(parent, "Encrypt Text", "Enter text to encrypt:", multiline=True)
    if not ok or not plaintext:
        return
    primary_pass = obtain_passphrase_gui(parent, "primary")
    if not primary_pass:
        return
    recovery_pass = obtain_passphrase_gui(parent, "recovery")
    if not recovery_pass:
        return

    dek = bytearray(secrets.token_bytes(KEY_LEN))
    _lock(dek)
    try:
        primary_wrap = wrap_key(primary_pass, dek, AAD_ROLE_PRIMARY)
        recovery_wrap = wrap_key(recovery_pass, dek, AAD_ROLE_RECOVERY)
        data_nonce = secrets.token_bytes(IV_LEN)
        ciphertext, data_tag = aes_gcm_encrypt(dek, data_nonce, plaintext.encode("utf-8"), AAD_TEXT_CTX)
    except BCryptError as e:
        show_message(parent, "Error", f"Encryption failed.\n{e}", is_error=True)
        return
    finally:
        _zero(dek)
        _unlock(dek)

    packed = wrap_to_bytes(primary_wrap) + wrap_to_bytes(recovery_wrap) + data_nonce + data_tag + ciphertext
    show_copyable_dialog(parent, "Encrypted text", "Your encrypted text (copy and store it):", to_hex(packed), True)


def do_decrypt_text(parent):
    packed_hex, ok = show_input_dialog(parent, "Decrypt Text", "Paste encrypted text:", multiline=True)
    if not ok or not packed_hex:
        return
    try:
        raw = from_hex(packed_hex)
    except ValueError:
        show_message(parent, "Error", "That doesn't look like valid encrypted text (invalid hex data).", is_error=True)
        return

    header_len = WRAP_LEN * 2 + IV_LEN + TAG_LEN
    if len(raw) < header_len:
        show_message(parent, "Error", "That doesn't look like valid encrypted data.", is_error=True)
        return

    primary_wrap = wrap_from_bytes(raw[0:WRAP_LEN])
    recovery_wrap = wrap_from_bytes(raw[WRAP_LEN:WRAP_LEN * 2])
    pos = WRAP_LEN * 2
    data_nonce = raw[pos:pos + IV_LEN]; pos += IV_LEN
    data_tag = raw[pos:pos + TAG_LEN]; pos += TAG_LEN
    ciphertext = raw[pos:]

    which = show_choice_dialog(parent, "Unlock", "Unlock with which passphrase?", "Primary", "Recovery")
    if which == 0:
        return
    passphrase, ok = show_input_dialog(parent, "Passphrase", "Enter passphrase:", masked=True)
    if not ok:
        return

    role_aad = AAD_ROLE_RECOVERY if which == 2 else AAD_ROLE_PRIMARY
    wrap = recovery_wrap if which == 2 else primary_wrap
    try:
        dek = unwrap_key(passphrase, wrap, role_aad)
    except BCryptError:
        show_message(parent, "Failed", "Wrong passphrase for that option (or the data is corrupted).", is_error=True)
        return
    try:
        plaintext = aes_gcm_decrypt(dek, data_nonce, ciphertext, data_tag, AAD_TEXT_CTX)
    except BCryptError:
        show_message(parent, "Failed", "The data appears to be corrupted or tampered with.", is_error=True)
        return
    finally:
        _zero(dek)
        _unlock(dek)

    show_copyable_dialog(parent, "Decrypted text", "Decrypted result:", plaintext.decode("utf-8", errors="replace"), True)


def do_encrypt_file(parent):
    in_path = filedialog.askopenfilename(parent=parent, title="Choose a file to encrypt")
    if not in_path:
        return
    try:
        with open(in_path, "rb") as f:
            file_bytes = f.read()
    except OSError as e:
        show_message(parent, "Error", f"Could not open that file.\n{e}", is_error=True)
        return

    ext_bytes = os.path.splitext(in_path)[1].encode("utf-8")
    combined = bytearray(struct.pack("<I", len(ext_bytes)) + ext_bytes + file_bytes)

    default_name = os.path.basename(in_path) + ".enc"
    out_path = filedialog.asksaveasfilename(parent=parent, title="Save encrypted file as", initialfile=default_name)
    if not out_path:
        return

    primary_pass = obtain_passphrase_gui(parent, "primary")
    if not primary_pass:
        return
    recovery_pass = obtain_passphrase_gui(parent, "recovery")
    if not recovery_pass:
        return

    dek = bytearray(secrets.token_bytes(KEY_LEN))
    _lock(dek)
    try:
        primary_wrap = wrap_key(primary_pass, dek, AAD_ROLE_PRIMARY)
        recovery_wrap = wrap_key(recovery_pass, dek, AAD_ROLE_RECOVERY)
        data_nonce = secrets.token_bytes(IV_LEN)
        ciphertext, data_tag = aes_gcm_encrypt(dek, data_nonce, bytes(combined), AAD_FILE_CTX)
    except BCryptError as e:
        show_message(parent, "Error", f"Encryption failed.\n{e}", is_error=True)
        return
    finally:
        _zero(dek)
        _unlock(dek)
        _zero(combined)

    try:
        with open(out_path, "wb") as f:
            f.write(MAGIC)
            f.write(wrap_to_bytes(primary_wrap))
            f.write(wrap_to_bytes(recovery_wrap))
            f.write(data_nonce)
            f.write(data_tag)
            f.write(ciphertext)
    except OSError as e:
        show_message(parent, "Error", f"Could not write output file.\n{e}", is_error=True)
        return

    show_message(parent, "Done", f"Encrypted file written to:\n{out_path}")


def do_decrypt_file(parent):
    in_path = filedialog.askopenfilename(parent=parent, title="Choose a file to decrypt")
    if not in_path:
        return
    try:
        with open(in_path, "rb") as f:
            raw = f.read()
    except OSError as e:
        show_message(parent, "Error", f"Could not open that file.\n{e}", is_error=True)
        return

    header_len = 4 + WRAP_LEN * 2 + IV_LEN + TAG_LEN
    if len(raw) < header_len or raw[:4] != MAGIC:
        show_message(parent, "Error", "This does not look like a file created by this program.", is_error=True)
        return

    pos = 4
    primary_wrap = wrap_from_bytes(raw[pos:pos + WRAP_LEN]); pos += WRAP_LEN
    recovery_wrap = wrap_from_bytes(raw[pos:pos + WRAP_LEN]); pos += WRAP_LEN
    data_nonce = raw[pos:pos + IV_LEN]; pos += IV_LEN
    data_tag = raw[pos:pos + TAG_LEN]; pos += TAG_LEN
    ciphertext = raw[pos:]

    which = show_choice_dialog(parent, "Unlock", "Unlock with which passphrase?", "Primary", "Recovery")
    if which == 0:
        return
    passphrase, ok = show_input_dialog(parent, "Passphrase", "Enter passphrase:", masked=True)
    if not ok:
        return

    role_aad = AAD_ROLE_RECOVERY if which == 2 else AAD_ROLE_PRIMARY
    wrap = recovery_wrap if which == 2 else primary_wrap
    try:
        dek = unwrap_key(passphrase, wrap, role_aad)
    except BCryptError:
        show_message(parent, "Failed", "Wrong passphrase for that option (or the file is corrupted).", is_error=True)
        return
    try:
        combined = aes_gcm_decrypt(dek, data_nonce, ciphertext, data_tag, AAD_FILE_CTX)
    except BCryptError:
        show_message(parent, "Failed", "The file appears to be corrupted or tampered with.", is_error=True)
        return
    finally:
        _zero(dek)
        _unlock(dek)

    ext_len = struct.unpack_from("<I", combined, 0)[0]
    ext = combined[4:4 + ext_len].decode("utf-8", errors="replace")
    file_data = combined[4 + ext_len:]

    base = in_path[:-4] if in_path.lower().endswith(".enc") else in_path
    if not os.path.splitext(base)[1] and ext:
        base += ext
    out_path = filedialog.asksaveasfilename(parent=parent, title="Save decrypted file as", initialfile=os.path.basename(base))
    if not out_path:
        _zero(combined)
        return
    try:
        with open(out_path, "wb") as f:
            f.write(file_data)
    except OSError as e:
        show_message(parent, "Error", f"Could not write output file.\n{e}", is_error=True)
        _zero(combined)
        return

    _zero(combined)
    show_message(parent, "Done", f"Decrypted file written to:\n{out_path}")


# =====================================================================
#  Password vault
# =====================================================================

class VaultSession:
    def __init__(self, path):
        self.path = path
        self.dek = bytearray()
        self.primary_wrap = None
        self.recovery_wrap = None
        self.entries = []
        self.modified = False

    def wipe(self):
        _zero(self.dek)
        _unlock(self.dek)
        self.dek = bytearray()


def default_vault_path():
    base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.join(base_dir, "vault.pyenc")


def open_or_create_vault_gui(parent):
    default_path = default_vault_path()
    path, ok = show_input_dialog(parent, "Vault Location", "Vault file path:", default=default_path)
    if not ok or not path:
        return None

    session = VaultSession(path)

    if not os.path.exists(path):
        confirm = show_choice_dialog(parent, "New Vault", "No vault found at that path.\nCreate a new one?", "Create new vault", "Cancel")
        if confirm != 1:
            return None
        primary_pass = obtain_passphrase_gui(parent, "primary")
        if not primary_pass:
            return None
        recovery_pass = obtain_passphrase_gui(parent, "recovery")
        if not recovery_pass:
            return None
        session.dek = bytearray(secrets.token_bytes(KEY_LEN))
        _lock(session.dek)
        try:
            session.primary_wrap = wrap_key(primary_pass, session.dek, AAD_ROLE_PRIMARY)
            session.recovery_wrap = wrap_key(recovery_pass, session.dek, AAD_ROLE_RECOVERY)
        except BCryptError as e:
            show_message(parent, "Error", f"Key setup failed.\n{e}", is_error=True)
            return None
        session.entries = []
        session.modified = True
        return session

    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        show_message(parent, "Error", f"Could not open vault file.\n{e}", is_error=True)
        return None

    header_len = 4 + WRAP_LEN * 2 + IV_LEN + TAG_LEN
    if len(raw) < header_len or raw[:4] != VAULT_MAGIC:
        show_message(parent, "Error", "That file doesn't look like a vault created by this program.", is_error=True)
        return None

    pos = 4
    session.primary_wrap = wrap_from_bytes(raw[pos:pos + WRAP_LEN]); pos += WRAP_LEN
    session.recovery_wrap = wrap_from_bytes(raw[pos:pos + WRAP_LEN]); pos += WRAP_LEN
    data_nonce = raw[pos:pos + IV_LEN]; pos += IV_LEN
    data_tag = raw[pos:pos + TAG_LEN]; pos += TAG_LEN
    ciphertext = raw[pos:]

    which = show_choice_dialog(parent, "Unlock Vault", "Unlock with which passphrase?", "Primary", "Recovery")
    if which == 0:
        return None
    passphrase, ok = show_input_dialog(parent, "Passphrase", "Enter passphrase:", masked=True)
    if not ok:
        return None

    role_aad = AAD_ROLE_RECOVERY if which == 2 else AAD_ROLE_PRIMARY
    wrap = session.recovery_wrap if which == 2 else session.primary_wrap
    try:
        session.dek = unwrap_key(passphrase, wrap, role_aad)
    except BCryptError:
        show_message(parent, "Failed", "Wrong passphrase (or the vault is corrupted).", is_error=True)
        return None
    try:
        plain = aes_gcm_decrypt(session.dek, data_nonce, ciphertext, data_tag, AAD_VAULT_CTX)
    except BCryptError:
        show_message(parent, "Failed", "Failed to decrypt vault contents -- it may be corrupted.", is_error=True)
        return None

    try:
        session.entries = json.loads(bytes(plain).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        session.entries = []
    finally:
        _zero(plain)
    session.modified = False
    return session


def save_vault_gui(parent, session):
    plain = bytearray(json.dumps(session.entries).encode("utf-8"))
    data_nonce = secrets.token_bytes(IV_LEN)
    try:
        ciphertext, data_tag = aes_gcm_encrypt(session.dek, data_nonce, bytes(plain), AAD_VAULT_CTX)
    except BCryptError as e:
        show_message(parent, "Error", f"Failed to save vault.\n{e}", is_error=True)
        return
    finally:
        _zero(plain)
    try:
        with open(session.path, "wb") as f:
            f.write(VAULT_MAGIC)
            f.write(wrap_to_bytes(session.primary_wrap))
            f.write(wrap_to_bytes(session.recovery_wrap))
            f.write(data_nonce)
            f.write(data_tag)
            f.write(ciphertext)
    except OSError as e:
        show_message(parent, "Error", f"Failed to save vault.\n{e}", is_error=True)
        return
    session.modified = False
    show_message(parent, "Saved", f"Vault saved to:\n{session.path}")


class VaultWindow(tk.Toplevel):
    HEADER_H = 68

    def __init__(self, parent, session):
        super().__init__(parent)
        self.session = session
        self.title("Password Vault")
        self.configure(bg=BODY_COLOR)
        self.resizable(False, False)
        self.transient(parent)
        width, height = 580, 520
        apply_dark_titlebar(self)

        header = tk.Canvas(self, width=width, height=self.HEADER_H, bg=ACCENT_COLOR, highlightthickness=0)
        header.place(x=0, y=0)
        draw_vertical_gradient(header, 0, 0, width, self.HEADER_H, adjust_brightness(ACCENT_COLOR, 14), ACCENT_COLOR)
        header.create_line(0, self.HEADER_H - 1, width, self.HEADER_H - 1, fill=BORDER_COLOR)
        header.create_text(MARGIN, self.HEADER_H // 2, text="Password Vault", anchor="w", fill="#ffffff", font=FONT_TITLE)

        body = tk.Frame(self, bg=BODY_COLOR)
        body.place(x=0, y=self.HEADER_H, width=width, height=height - self.HEADER_H)

        self.status_label = tk.Label(body, bg=BODY_COLOR, fg=ACCENT_SUBTEXT, font=FONT_NORMAL, anchor="w")
        self.status_label.pack(fill="x", padx=MARGIN, pady=(14, 8))

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Vault.Treeview", background=EDIT_BG_COLOR, fieldbackground=EDIT_BG_COLOR,
                        foreground=TEXT_COLOR, rowheight=24, borderwidth=0, font=FONT_NORMAL)
        style.configure("Vault.Treeview.Heading", background=ACCENT_COLOR, foreground=TEXT_COLOR, relief="flat", font=FONT_NORMAL)
        style.map("Vault.Treeview", background=[("selected", BTN_PRIMARY_BG)], foreground=[("selected", "#ffffff")])
        style.map("Vault.Treeview.Heading", background=[("active", ACCENT_COLOR)])

        list_frame = tk.Frame(body, bg=BORDER_COLOR)
        list_frame.pack(fill="both", expand=True, padx=MARGIN, pady=(0, 10))
        self.tree = ttk.Treeview(list_frame, columns=("site", "user"), show="headings", style="Vault.Treeview", selectmode="browse", height=10)
        self.tree.heading("site", text="Site / Service")
        self.tree.heading("user", text="Username")
        self.tree.column("site", width=310)
        self.tree.column("user", width=230)
        self.tree.pack(fill="both", expand=True, padx=1, pady=1)
        self.tree.bind("<Double-1>", lambda e: self.view_entry())

        row1 = tk.Frame(body, bg=BODY_COLOR)
        row1.pack(fill="x", padx=MARGIN, pady=(0, 8))
        RoundedButton(row1, "Add", command=self.add_entry, width=122, height=30).pack(side="left", padx=(0, 10))
        RoundedButton(row1, "View", command=self.view_entry, width=122, height=30).pack(side="left", padx=(0, 10))
        RoundedButton(row1, "Edit", command=self.edit_entry, width=122, height=30).pack(side="left", padx=(0, 10))
        RoundedButton(row1, "Delete", command=self.delete_entry, width=122, height=30).pack(side="left")

        row2 = tk.Frame(body, bg=BODY_COLOR)
        row2.pack(fill="x", padx=MARGIN, pady=(0, MARGIN))
        RoundedButton(row2, "Save Vault", command=self.save, width=150, height=30, primary=True).pack(side="left", padx=(0, 10))
        RoundedButton(row2, "Change Passphrases", command=self.change_passphrases, width=200, height=30).pack(side="left", padx=(0, 10))
        RoundedButton(row2, "Close", command=self.on_close, width=148, height=30).pack(side="left")

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.refresh_list()
        self.update_status()
        center_window(self, parent, width, height)
        self.grab_set()

    def refresh_list(self):
        self.tree.delete(*self.tree.get_children())
        for i, e in enumerate(self.session.entries):
            self.tree.insert("", "end", iid=str(i), values=(e["site"], e["username"]))

    def update_status(self):
        state = "  *unsaved changes*" if self.session.modified else "  (saved)"
        self.status_label.configure(text=f"Vault:  {self.session.path}{state}")

    def selected_index(self):
        sel = self.tree.selection()
        if not sel:
            show_message(self, "No selection", "Select an entry first.", is_error=True)
            return None
        return int(sel[0])

    def add_entry(self):
        site, ok = show_input_dialog(self, "Add Entry", "Site/service name:")
        if not ok or not site:
            return
        username, ok = show_input_dialog(self, "Add Entry", "Username/email:")
        if not ok:
            return
        choice = show_choice_dialog(self, "Password", "Generate a strong password, or enter your own?", "Generate", "Enter my own")
        if choice == 0:
            return
        if choice == 1:
            password = generate_site_password()
            show_copyable_dialog(self, "Generated password", f"Generated password for {site}:", password, False)
        else:
            password, ok = show_input_dialog(self, "Password", "Enter password:", masked=True)
            if not ok:
                return
        notes, ok = show_input_dialog(self, "Notes", "Notes (optional):")
        self.session.entries.append({"site": site, "username": username, "password": password, "notes": notes if ok else ""})
        self.session.modified = True
        self.refresh_list()
        self.update_status()

    def view_entry(self):
        idx = self.selected_index()
        if idx is None:
            return
        e = self.session.entries[idx]
        msg = f"Site: {e['site']}\nUsername: {e['username']}\nPassword: {e['password']}"
        if e.get("notes"):
            msg += f"\nNotes: {e['notes']}"
        show_copyable_dialog(self, "Entry Details", "Details (read-only):", msg, True)

    def edit_entry(self):
        idx = self.selected_index()
        if idx is None:
            return
        e = self.session.entries[idx]
        new_site, ok = show_input_dialog(self, "Edit Entry", "Site name:", default=e["site"])
        if ok and new_site:
            e["site"] = new_site
        new_user, ok = show_input_dialog(self, "Edit Entry", "Username:", default=e["username"])
        if ok:
            e["username"] = new_user
        choice = show_choice_dialog(self, "Password", "Change the password?", "Generate new", "Enter new")
        if choice == 1:
            e["password"] = generate_site_password()
            show_copyable_dialog(self, "Generated password", "New generated password:", e["password"], False)
        elif choice == 2:
            new_pass, ok = show_input_dialog(self, "Password", "Enter new password:", masked=True)
            if ok and new_pass:
                e["password"] = new_pass
        new_notes, ok = show_input_dialog(self, "Edit Entry", "Notes:", default=e.get("notes", ""))
        if ok:
            e["notes"] = new_notes
        self.session.modified = True
        self.refresh_list()
        self.update_status()

    def delete_entry(self):
        idx = self.selected_index()
        if idx is None:
            return
        site = self.session.entries[idx]["site"]
        confirm = show_choice_dialog(self, "Confirm Delete", f"Delete '{site}'?", "Yes, delete", "Cancel")
        if confirm == 1:
            del self.session.entries[idx]
            self.session.modified = True
            self.refresh_list()
            self.update_status()

    def change_passphrases(self):
        new_primary = obtain_passphrase_gui(self, "new primary")
        if not new_primary:
            return
        new_recovery = obtain_passphrase_gui(self, "new recovery")
        if not new_recovery:
            return
        try:
            self.session.primary_wrap = wrap_key(new_primary, self.session.dek, AAD_ROLE_PRIMARY)
            self.session.recovery_wrap = wrap_key(new_recovery, self.session.dek, AAD_ROLE_RECOVERY)
        except BCryptError as e:
            show_message(self, "Error", f"Failed to update passphrases.\n{e}", is_error=True)
            return
        self.session.modified = True
        self.update_status()
        show_message(self, "Updated", "Passphrases updated in memory. Click Save to make this permanent.")

    def save(self):
        save_vault_gui(self, self.session)
        self.update_status()

    def on_close(self):
        if self.session.modified:
            choice = show_choice_dialog(self, "Unsaved Changes", "You have unsaved changes.\nSave before closing?", "Save", "Discard")
            if choice == 1:
                save_vault_gui(self, self.session)
        self.session.wipe()
        self.grab_release()
        self.destroy()


# =====================================================================
#  Main window
# =====================================================================

class MainApp(tk.Tk):
    HEADER_H = 96

    def __init__(self):
        super().__init__()
        self.title("Encrypter")
        self.configure(bg=BODY_COLOR)
        self.resizable(False, False)
        width, height = 300, 500
        self.geometry(f"{width}x{height}")
        apply_dark_titlebar(self)

        header = tk.Canvas(self, width=width, height=self.HEADER_H, bg=ACCENT_COLOR, highlightthickness=0)
        header.place(x=0, y=0)
        draw_vertical_gradient(header, 0, 0, width, self.HEADER_H, adjust_brightness(ACCENT_COLOR, 14), ACCENT_COLOR)
        header.create_line(0, self.HEADER_H - 1, width, self.HEADER_H - 1, fill=BORDER_COLOR)
        header.create_text(MARGIN, 30, text="Encrypter", anchor="w", fill="#ffffff", font=FONT_TITLE)
        header.create_text(MARGIN, 60, text="Encrypt any file type, text,", anchor="w", fill=ACCENT_SUBTEXT, font=FONT_SUBTITLE)
        header.create_text(MARGIN, 78, text="or manage your vault.", anchor="w", fill=ACCENT_SUBTEXT, font=FONT_SUBTITLE)

        body = tk.Frame(self, bg=BODY_COLOR)
        body.place(x=0, y=self.HEADER_H, width=width, height=height - self.HEADER_H)

        buttons = [
            ("Encrypt Text", self.encrypt_text, False),
            ("Decrypt Text", self.decrypt_text, False),
            ("Encrypt File", self.encrypt_file, False),
            ("Decrypt File", self.decrypt_file, False),
            ("Password Vault", self.open_vault, True),
            ("Exit", self.destroy, False),
        ]
        y = 16
        for text, cmd, primary in buttons:
            RoundedButton(body, text, command=cmd, width=260, height=40, primary=primary).place(x=MARGIN, y=y)
            y += 40 + 12
            if text == "Password Vault":
                y += 10

    def encrypt_text(self):
        do_encrypt_text(self)

    def decrypt_text(self):
        do_decrypt_text(self)

    def encrypt_file(self):
        do_encrypt_file(self)

    def decrypt_file(self):
        do_decrypt_file(self)

    def open_vault(self):
        session = open_or_create_vault_gui(self)
        if session is None:
            return
        vault_win = VaultWindow(self, session)
        self.wait_window(vault_win)


if __name__ == "__main__":
    MainApp().mainloop()