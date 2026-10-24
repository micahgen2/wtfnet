"""Running external commands safely and capturing what they print."""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional

from .platform_cmds import detect_system


@dataclass
class CommandResult:
    argv: List[str]
    returncode: Optional[int]
    output: str  # stdout and stderr merged, in the order they were printed
    elapsed: float  # wall-clock seconds
    error: Optional[str] = None  # None | "not_found" | "timeout" | "os_error"

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0


def format_command(argv: List[str], system: Optional[str] = None) -> str:
    """Render argv as a string you could paste into a terminal."""
    if (system or detect_system()) == "windows":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def run_command(argv: List[str], timeout: float = 30) -> CommandResult:
    """Run argv (no shell!) and never raise: failures come back in `.error`."""
    # Force English, un-localised output so our regex parsers can read it.
    env = dict(os.environ, LC_ALL="C", LANG="C")
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merge stderr into stdout
            stdin=subprocess.DEVNULL,  # never sit waiting for keyboard input
            timeout=timeout,
            env=env,
            text=True,
            errors="replace",  # garbled bytes become '?' instead of crashing
        )
        return CommandResult(argv, proc.returncode, proc.stdout, time.monotonic() - start)
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        return CommandResult(argv, None, partial or "", time.monotonic() - start, "timeout")
    except FileNotFoundError:
        msg = "command not found: " + argv[0]
        return CommandResult(argv, None, msg, time.monotonic() - start, "not_found")
    except OSError as exc:
        return CommandResult(argv, None, str(exc), time.monotonic() - start, "os_error")
