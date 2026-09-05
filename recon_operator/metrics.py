"""In-process Prometheus-style metrics for Recon Operator.

No external dependencies: counters, gauges, and a simple histogram are
updated from job lifecycle hooks and rendered as Prometheus text.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any


def _labels_key(labels: Mapping[str, str] | None) -> tuple[tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


def _format_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    parts = [f'{k}="{_escape_label(v)}"' for k, v in labels]
    return "{" + ",".join(parts) + "}"


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


# Default duration buckets (seconds) for scan runtime histogram.
DEFAULT_DURATION_BUCKETS: tuple[float, ...] = (
    1.0,
    5.0,
    15.0,
    30.0,
    60.0,
    120.0,
    300.0,
    600.0,
    1800.0,
    3600.0,
)


class MetricsRegistry:
    """Thread-safe metrics registry with Prometheus text exposition."""

    def __init__(self, duration_buckets: Sequence[float] = DEFAULT_DURATION_BUCKETS) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._histograms: dict[tuple[str, tuple[tuple[str, str], ...]], dict[str, Any]] = {}
        self._duration_buckets = tuple(sorted(float(b) for b in duration_buckets))
        self._started_at = time.time()
        # HELP/TYPE metadata for known series.
        self._meta: dict[str, tuple[str, str]] = {
            "recon_operator_info": ("gauge", "Constant 1 labeled with product version"),
            "recon_operator_up": ("gauge", "1 when the metrics process is up"),
            "recon_operator_jobs_created_total": (
                "counter",
                "Scan jobs created (queued)",
            ),
            "recon_operator_jobs_finished_total": (
                "counter",
                "Scan jobs finished by terminal status",
            ),
            "recon_operator_jobs_queued": ("gauge", "Jobs currently queued"),
            "recon_operator_jobs_running": ("gauge", "Jobs currently running"),
            "recon_operator_jobs_known": ("gauge", "In-memory job records"),
            "recon_operator_scheduled_tasks": ("gauge", "Local scheduled task coroutines"),
            "recon_operator_scan_duration_seconds": (
                "histogram",
                "Wall time from job start to terminal status",
            ),
            "recon_operator_http_requests_total": (
                "counter",
                "HTTP requests handled (by route family when labeled)",
            ),
            "recon_operator_rate_limit_exceeded_total": (
                "counter",
                "Requests rejected by rate limiting",
            ),
        }

    def inc(self, name: str, amount: float = 1.0, **labels: str) -> None:
        key = (name, _labels_key(labels))
        with self._lock:
            self._counters[key] += float(amount)

    def set_gauge(self, name: str, value: float, **labels: str) -> None:
        key = (name, _labels_key(labels))
        with self._lock:
            self._gauges[key] = float(value)

    def observe(self, name: str, value: float, **labels: str) -> None:
        """Observe a histogram sample (cumulative buckets + sum + count)."""
        key = (name, _labels_key(labels))
        sample = float(value)
        with self._lock:
            hist = self._histograms.get(key)
            if hist is None:
                hist = {
                    "buckets": {b: 0 for b in self._duration_buckets},
                    "sum": 0.0,
                    "count": 0,
                }
                self._histograms[key] = hist
            for bound in self._duration_buckets:
                if sample <= bound:
                    hist["buckets"][bound] += 1
            hist["sum"] += sample
            hist["count"] += 1

    def counter_value(self, name: str, **labels: str) -> float:
        key = (name, _labels_key(labels))
        with self._lock:
            return float(self._counters.get(key, 0.0))

    def gauge_value(self, name: str, **labels: str) -> float:
        key = (name, _labels_key(labels))
        with self._lock:
            return float(self._gauges.get(key, 0.0))

    def histogram_count(self, name: str, **labels: str) -> int:
        key = (name, _labels_key(labels))
        with self._lock:
            hist = self._histograms.get(key)
            return int(hist["count"]) if hist else 0

    def reset(self) -> None:
        """Clear series (tests only)."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()
            self._started_at = time.time()

    def render_prometheus(
        self,
        *,
        extra_gauges: Mapping[tuple[str, tuple[tuple[str, str], ...]], float] | None = None,
        info_labels: Mapping[str, str] | None = None,
    ) -> str:
        """Render Prometheus text exposition format (0.0.4)."""
        lines: list[str] = []
        emitted_help: set = set()

        def ensure_meta(name: str) -> None:
            if name in emitted_help:
                return
            kind, help_text = self._meta.get(name, ("untyped", name.replace("_", " ")))
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {kind}")
            emitted_help.add(name)

        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            histograms = {
                k: {
                    "buckets": dict(v["buckets"]),
                    "sum": v["sum"],
                    "count": v["count"],
                }
                for k, v in self._histograms.items()
            }

        # Process info + up.
        ensure_meta("recon_operator_info")
        info_lbl = _format_labels(_labels_key(info_labels or {}))
        lines.append(f"recon_operator_info{info_lbl} 1")
        ensure_meta("recon_operator_up")
        lines.append("recon_operator_up 1")

        if extra_gauges:
            for key, value in extra_gauges.items():
                gauges[key] = float(value)

        # Group by metric name for stable output.
        names = sorted(
            {n for n, _ in counters} | {n for n, _ in gauges} | {n for n, _ in histograms}
        )
        for name in names:
            ensure_meta(name)
            for (n, labels), value in sorted(
                ((k, v) for k, v in counters.items() if k[0] == name),
                key=lambda item: item[0][1],
            ):
                lines.append(f"{n}{_format_labels(labels)} {value}")
            for (n, labels), value in sorted(
                ((k, v) for k, v in gauges.items() if k[0] == name),
                key=lambda item: item[0][1],
            ):
                lines.append(f"{n}{_format_labels(labels)} {value}")
            for (n, labels), hist in sorted(
                ((k, v) for k, v in histograms.items() if k[0] == name),
                key=lambda item: item[0][1],
            ):
                # observe() increments every bucket where sample <= bound → cumulative.
                for bound in self._duration_buckets:
                    count = hist["buckets"].get(bound, 0)
                    le_key = tuple(sorted(labels + (("le", _format_le(bound)),)))
                    lines.append(f"{n}_bucket{_format_labels(le_key)} {count}")
                inf_labels = tuple(sorted(labels + (("le", "+Inf"),)))
                lines.append(f"{n}_bucket{_format_labels(inf_labels)} {hist['count']}")
                lines.append(f"{n}_sum{_format_labels(labels)} {hist['sum']}")
                lines.append(f"{n}_count{_format_labels(labels)} {hist['count']}")

        lines.append("")  # trailing newline
        return "\n".join(lines)


def _format_le(bound: float) -> str:
    if bound == int(bound):
        return str(int(bound))
    return f"{bound:g}"


# Process-wide default registry used by the server.
METRICS = MetricsRegistry()
