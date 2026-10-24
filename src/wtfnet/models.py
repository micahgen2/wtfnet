"""Plain data containers shared by the rest of the program."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Dict, List

# Step / verdict severities.
OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"

# The layers we can blame, ordered from "closest to your keyboard" to
# "furthest away". The order matters: if two layers are broken, the lower one
# is blamed first, because it usually causes the later ones.
LAYERS = ["local", "gateway", "portal", "isp", "dns", "remote", "hosts", "ipv6"]


@dataclass
class Exec:
    """One command (or in-process probe) and what came back."""

    display: str  # the exact command line shown to the user
    output: str  # raw output, untouched
    elapsed: float = 0.0


@dataclass
class StepResult:
    key: str
    title: str
    layer: str
    status: str
    explanation: str
    execs: List[Exec] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Verdict:
    layer: str  # "none" or one of LAYERS
    status: str  # OK / WARN / FAIL
    headline: str
    detail: str
    fixes: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


@dataclass
class Run:
    started: _dt.datetime
    results: List[StepResult]
    verdict: Verdict
