"""Colored, timestamped logger for VulnScan Pro.

Wraps colorama so terminal output is color-coded (green = safe, red =
vulnerable, yellow = warning, cyan = info). Every log call is prefixed
with a UTC timestamp so output can be redirected to a file and still
make sense.
"""
from __future__ import annotations

import sys
import threading
from datetime import datetime, timezone
from typing import Optional

from colorama import Fore, Style, init as colorama_init

# Initialize colorama once at import time. autoreset=True so each print
# automatically resets the color, which avoids bleed-through across lines.
colorama_init(autoreset=True)


class Logger:
    """Thread-safe colored logger.

    Multiple scanner modules can call into this logger from worker
    threads, so writes to stdout/stderr are guarded by a lock to avoid
    interleaved output.
    """

    _lock = threading.Lock()

    def __init__(self, verbose: bool = True, log_file: Optional[str] = None) -> None:
        self.verbose = verbose
        self.log_file = log_file

    @staticmethod
    def _ts() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def _write(self, prefix: str, color: str, message: str, stream=sys.stdout) -> None:
        line = f"[{self._ts()}] {prefix} {message}"
        with self._lock:
            stream.write(f"{color}{line}{Style.RESET_ALL}\n")
            stream.flush()
            if self.log_file:
                try:
                    with open(self.log_file, "a", encoding="utf-8") as f:
                        f.write(line + "\n")
                except OSError:
                    # Logging must never crash the scanner.
                    pass

    def info(self, message: str) -> None:
        if self.verbose:
            self._write("[*]", Fore.CYAN, message)

    def success(self, message: str) -> None:
        self._write("[+]", Fore.GREEN, message)

    def warning(self, message: str) -> None:
        self._write("[!]", Fore.YELLOW, message)

    def error(self, message: str) -> None:
        self._write("[x]", Fore.RED, message, stream=sys.stderr)

    def vuln(self, message: str) -> None:
        """Log a confirmed vulnerability finding."""
        self._write("[VULN]", Fore.RED + Style.BRIGHT, message)

    def progress(self, current: int, total: int, label: str = "") -> None:
        """Inline progress bar that overwrites itself in the terminal."""
        if total <= 0:
            return
        pct = int((current / total) * 100)
        bar_len = 30
        filled = int(bar_len * current / total)
        bar = "#" * filled + "-" * (bar_len - filled)
        with self._lock:
            sys.stdout.write(
                f"\r{Fore.CYAN}[*] {label} [{bar}] {pct:3d}% ({current}/{total}){Style.RESET_ALL}"
            )
            sys.stdout.flush()
            if current >= total:
                sys.stdout.write("\n")
                sys.stdout.flush()
