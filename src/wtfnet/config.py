"""Finding and reading the optional config file (TOML).

Precedence, lowest to highest:  built-in defaults  <  config file  <  command-line flags.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # Python 3.11+ ships a TOML reader; older versions use the `tomli` package.
    import tomllib as _toml
except ImportError:  # pragma: no cover - depends on the Python version
    import tomli as _toml

CONFIG_NAME = "wtfnet.toml"

EXAMPLE = """\
# wtfnet configuration. Every key is optional; command-line flags override these.

target = "example.com"        # host for traceroute, port and HTTPS checks
ports = [80, 443]             # or a string: "80,443,8000-8005"
dns_name = "example.com"      # name looked up in the DNS timing test
ping_hosts = []               # extra machines to ping, e.g. ["192.168.1.50", "nas.lan"]

ipv6 = true                   # false = never run the IPv6 tests
wifi = true                   # false = never inspect the Wi-Fi link
clean = false                 # true = swap the profanity for milder words
quiet = false                 # true = one line per step
# watch = 60                  # repeat every N seconds
# html_report = "wtfnet-report.html"
# log = "wtfnet-log.csv"      # .csv = summary row per run, anything else = JSON lines
"""

# key -> what it's for. Anything else in the file is reported as a typo.
KEYS = ("target", "ports", "dns_name", "ping_hosts", "ipv6", "wifi", "clean", "quiet",
        "watch", "html_report", "log")


class ConfigError(Exception):
    pass


def user_config_path() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "wtfnet" / "config.toml"


def candidate_paths() -> List[Path]:
    return [Path.cwd() / CONFIG_NAME, user_config_path()]


def find_config(explicit: Optional[str]) -> Optional[Path]:
    """--config wins and must exist. Otherwise: ./wtfnet.toml, then the per-user file."""
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError("config file not found: {}".format(path))
        return path
    for path in candidate_paths():
        if path.is_file():
            return path
    return None


def load_config(path: Path) -> Dict[str, Any]:
    try:
        with open(path, "rb") as fh:
            return _toml.load(fh)
    except _toml.TOMLDecodeError as exc:
        raise ConfigError("{} isn't valid TOML: {}".format(path, exc))
    except OSError as exc:
        raise ConfigError("can't read {}: {}".format(path, exc))
