"""
utils.py
========
Shared display helpers and prompt utilities for the SFEDST CLI.
"""

import getpass
import sys
from pathlib import Path

# ── Visual chrome ────────────────────────────────────────────────────────────

BANNER = r"""
  ███████╗███████╗███████╗██████╗ ███████╗████████╗
  ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝
  ███████╗█████╗  █████╗  ██║  ██║███████╗   ██║
  ╚════██║██╔══╝  ██╔══╝  ██║  ██║╚════██║   ██║
  ███████║██║     ███████╗██████╔╝███████║   ██║
  ╚══════╝╚═╝     ╚══════╝╚═════╝ ╚══════╝   ╚═╝

   Secure File Encryption & Digital Signature Tool  v1.0
   ──────────────────────────────────────────────────────
   Algorithms: RSA-2048/4096 · AES-256-GCM · RSA-PSS · X.509
"""

MENU = """
  ┌──────────────────────────────────────────────┐
  │                  MAIN MENU                   │
  ├──────────────────────────────────────────────┤
  │  1.  Generate RSA Key Pair                   │
  │  2.  Generate Certificate                    │
  │  3.  Sign File                               │
  │  4.  Verify File Signature                   │
  │  5.  Encrypt File                            │
  │  6.  Decrypt File                            │
  │  7.  Simulate Unauthorized Signature Attack  │
  │  8.  List Keys & Certificates                │
  │  9.  Exit                                    │
  └──────────────────────────────────────────────┘
"""


def section(title: str) -> None:
    print(f"\n  {'─' * 52}")
    print(f"  {title}")
    print(f"  {'─' * 52}")


def pause() -> None:
    input("\n  Press Enter to continue… ")


def ask(label: str, default: str = "") -> str:
    """Prompt the user; return *default* if they press Enter."""
    suffix = f" [{default}]" if default else ""
    val = input(f"  {label}{suffix}: ").strip()
    return val if val else default


def ask_password(label: str = "Password") -> str:
    """Read a password without echo."""
    return getpass.getpass(f"  {label}: ")


def ask_password_confirm(label: str = "Password") -> str:
    """Read and confirm a new password; retry until they match."""
    while True:
        pw  = getpass.getpass(f"  {label}: ")
        pw2 = getpass.getpass(f"  Confirm {label.lower()}: ")
        if pw == pw2:
            return pw
        print("  [!] Passwords do not match — try again.")


def require_file(path: str, label: str = "File") -> bool:
    """Print an error and return False if *path* does not exist."""
    if not Path(path).exists():
        print(f"  [!] {label} not found: {path}")
        return False
    return True


def success(msg: str) -> None:
    print(f"\n  ✅  {msg}")


def failure(msg: str) -> None:
    print(f"\n  ❌  {msg}")
