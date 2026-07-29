# Encrypter
A cool tool for encrypting your passwords and files.

# Setup
Download `installer.py` and run it:
```
python installer.py
```
(or `python3 installer.py` on macOS/Linux, depending on how Python is set up on your system)

The installer is a small GUI that walks you through the rest. It automatically detects your OS — Windows 10/11, macOS, or Linux (Debian/Ubuntu, Fedora, Arch, Gentoo, openSUSE, Alpine, and others) — and tells you what it found. If something's missing (Python, tkinter, etc.) it'll give you the exact command to install it for your specific system instead of a generic error.

By default it just installs the app and its one dependency (`cryptography`). Two things are optional and off/on by default in the installer window:
- **Build a standalone executable** — bundles everything into a single native executable via PyInstaller, so you don't need Python installed to run it afterward. If you want to build this yourself instead of using the installer's checkbox:
  ```
  pip install pyinstaller
  python -m PyInstaller --onefile --noconsole --name "Encrypter" installer.py
  ```
  Note this only builds for whatever OS you run it on — it doesn't cross-compile, so building a Windows .exe requires running this on Windows, etc.
- **Create a shortcut/launcher** — a Desktop shortcut on Windows, a Desktop launcher on macOS, or an application menu entry on Linux.

**Requires Python 3.8+.** The installer will tell you if it's missing and how to get it for your system.

# About Encrypter
Encrypter is a personal tool for encrypting text and files, plus a small password vault, all running locally on your machine — nothing is sent anywhere. It'll most likely become a company at some point, at which point this repo goes private.

# How it works
- Encryption is AES-256-GCM, done through the `cryptography` library (the same OpenSSL-backed implementation on every OS, not a custom crypto implementation).
- Your passphrase never becomes the encryption key directly — it's run through scrypt (a slow, memory-hard key derivation function) with a random salt, specifically to make brute-forcing a stolen vault file expensive.
- The vault supports both a primary and a recovery passphrase, each independently able to unlock it.
- Passphrase-derived key material is zeroed out of memory (and locked in memory where the OS allows it) as soon as it's no longer needed, rather than just left to get garbage collected.

# File Info
- `installer.py` — the installer. This is the file you actually download and run; it has the whole app embedded inside it, so it's the only file you need.
- `encrypter.py` — the app itself, as plain source, so it's readable without decoding anything out of the installer.

Please DM me on Discord (`_vigames_`) if you want a version of the code in a different language.
