"""Machine-readable output: --json for scripts, --log for graphing flakiness over time."""

from __future__ import annotations

import csv
import dataclasses
import datetime as dt
import json
import os
from typing import Any, Dict, List, Optional

from . import __version__
from .models import Run, StepResult


def to_jsonable(obj: Any) -> Any:
    """Turn dataclasses, datetimes and other odd objects into plain JSON types."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, dt.datetime):
        return obj.isoformat(timespec="seconds")
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)


def step_dict(step: StepResult) -> Dict[str, Any]:
    return {
        "key": step.key,
        "title": step.title,
        "layer": step.layer,
        "status": step.status,
        "explanation": step.explanation,
        "commands": [{"command": e.display, "output": e.output, "seconds": round(e.elapsed, 3)}
                     for e in step.execs],
        "data": to_jsonable(step.data),
    }


def run_dict(run: Run, system: str, target: str) -> Dict[str, Any]:
    v = run.verdict
    return {
        "wtfnet": __version__,
        "system": system,
        "target": target,
        "started": to_jsonable(run.started),
        "verdict": {"layer": v.layer, "status": v.status, "headline": v.headline,
                    "detail": v.detail, "fixes": v.fixes, "evidence": v.evidence},
        "steps": [step_dict(s) for s in run.results],
    }


def run_json(run: Run, system: str, target: str, indent: Optional[int] = None) -> str:
    return json.dumps(run_dict(run, system, target), indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------- the log
CSV_COLUMNS = [
    "time", "verdict_layer", "verdict_status",
    "gateway_ms", "gateway_loss_pct",
    "cloudflare_ms", "cloudflare_loss_pct", "google_ms", "google_loss_pct",
    "dns_system_ms", "dns_cloudflare_ms", "dns_google_ms",
    "https_ms", "wifi_dbm",
]


def _stats(run: Run, key: str, host: Optional[str] = None):
    for s in run.results:
        if s.key == key:
            stats = s.data.get("stats")
            return stats.get(host) if host and isinstance(stats, dict) else stats
    return None


def _dns_ms(run: Run, label: str) -> Optional[float]:
    for s in run.results:
        if s.key == "dns":
            for row in s.data.get("rows", []):
                if row["label"] == label and row["ok"]:
                    return round(row["ms"], 1)
    return None


def summary_row(run: Run) -> Dict[str, Any]:
    """One flat row of the numbers worth graphing. Empty cell = not measured."""
    def ping(key, host=None):
        st = _stats(run, key, host)
        return (st.avg_ms, st.loss_pct) if st is not None else (None, None)

    gw, cf, g = ping("gateway"), ping("internet", "1.1.1.1"), ping("internet", "8.8.8.8")
    https_ms = wifi = None
    for s in run.results:
        if s.key == "https" and s.data.get("total_ms") is not None:
            https_ms = round(s.data["total_ms"], 1)
        if s.key == "wifi" and s.data.get("info") is not None:
            wifi = s.data["info"].signal_dbm
    return {
        "time": to_jsonable(run.started),
        "verdict_layer": run.verdict.layer, "verdict_status": run.verdict.status,
        "gateway_ms": gw[0], "gateway_loss_pct": gw[1],
        "cloudflare_ms": cf[0], "cloudflare_loss_pct": cf[1],
        "google_ms": g[0], "google_loss_pct": g[1],
        "dns_system_ms": _dns_ms(run, "system"), "dns_cloudflare_ms": _dns_ms(run, "Cloudflare"),
        "dns_google_ms": _dns_ms(run, "Google"),
        "https_ms": https_ms, "wifi_dbm": wifi,
    }


def append_log(path: str, run: Run, system: str, target: str) -> None:
    """Append one run to a log. `.csv` gets a summary row; anything else gets a full JSON line."""
    if path.lower().endswith(".csv"):
        new_file = not os.path.exists(path) or os.path.getsize(path) == 0
        with open(path, "a", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
            if new_file:
                writer.writeheader()
            writer.writerow(summary_row(run))
    else:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(run_json(run, system, target) + "\n")
