"""Pure metrics over the append-only events table.

Every function takes a sequence of ``Event`` rows (or anything exposing the same
attributes) and returns plain dictionaries. No database or network access here,
which makes the numbers reproducible and independently testable.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from app.models import Event

CREATED = "finding.created"
NOTIFIED = "notification.sent"
TERMINAL_KINDS = {
    "finding.accepted",
    "finding.muted",
    "finding.fixed",
    "finding.auto_resolved",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]


def percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * p
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return float(ordered[lower])
    fraction = rank - lower
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)


def _ordered(events: Iterable[Event]) -> list[Event]:
    return sorted(events, key=lambda event: (event.created_at, str(event.id)))


def _bucket(durations: list[float]) -> dict[str, Any]:
    return {
        "n": len(durations),
        "median_seconds": round(percentile(durations, 0.5), 3),
        "p90_seconds": round(percentile(durations, 0.9), 3),
    }


def _created_map(events: Sequence[Event]) -> dict[str, tuple[datetime, dict[str, Any]]]:
    created: dict[str, tuple[datetime, dict[str, Any]]] = {}
    for event in _ordered(events):
        if event.kind != CREATED or event.finding_id is None:
            continue
        key = str(event.finding_id)
        if key not in created:
            created[key] = (event.created_at, dict(event.payload or {}))
    return created


def _first_terminal(events: Sequence[Event]) -> dict[str, datetime]:
    terminal: dict[str, datetime] = {}
    for event in _ordered(events):
        if event.finding_id is None or event.kind not in TERMINAL_KINDS:
            continue
        key = str(event.finding_id)
        if key not in terminal:
            terminal[key] = event.created_at
    return terminal


def median_time_to_triage(events: Sequence[Event]) -> dict[str, Any]:
    created = _created_map(events)
    terminal = _first_terminal(events)
    overall: list[float] = []
    by_severity: dict[str, list[float]] = defaultdict(list)
    for finding_id, (created_at, payload) in created.items():
        finished = terminal.get(finding_id)
        if finished is None:
            continue
        seconds = (finished - created_at).total_seconds()
        if seconds < 0:
            continue
        overall.append(seconds)
        severity = str(payload.get("severity") or "unknown")
        by_severity[severity].append(seconds)

    ordered_severities = [s for s in SEVERITY_ORDER if s in by_severity]
    ordered_severities += sorted(s for s in by_severity if s not in SEVERITY_ORDER)
    return {
        "overall": _bucket(overall),
        "by_severity": {
            severity: _bucket(by_severity[severity]) for severity in ordered_severities
        },
    }


def false_positive_rate_by_rule(events: Sequence[Event], min_n: int = 5) -> list[dict[str, Any]]:
    created = _created_map(events)
    latest_terminal: dict[str, str] = {}
    for event in _ordered(events):
        if event.finding_id is None or event.kind not in TERMINAL_KINDS:
            continue
        latest_terminal[str(event.finding_id)] = event.kind

    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"muted": 0, "accepted": 0})
    for finding_id, (_created_at, payload) in created.items():
        outcome = latest_terminal.get(finding_id)
        if outcome == "finding.muted":
            counts[str(payload.get("rule_id") or "unknown")]["muted"] += 1
        elif outcome == "finding.accepted":
            counts[str(payload.get("rule_id") or "unknown")]["accepted"] += 1

    rows: list[dict[str, Any]] = []
    for rule_id, count in counts.items():
        n = count["muted"] + count["accepted"]
        if n < min_n:
            continue
        rows.append(
            {
                "rule_id": rule_id,
                "muted": count["muted"],
                "accepted": count["accepted"],
                "fp_rate": round(count["muted"] / n, 4),
            }
        )
    rows.sort(key=lambda row: (-row["fp_rate"], -row["muted"], row["rule_id"]))
    return rows


def _normal_cdf(value: float) -> float:
    return 0.5 * (1.0 + math.erf(value / math.sqrt(2.0)))


def two_proportion_z_test(
    successes_a: int, total_a: int, successes_b: int, total_b: int
) -> tuple[float | None, float | None]:
    if total_a <= 0 or total_b <= 0:
        return None, None
    rate_a = successes_a / total_a
    rate_b = successes_b / total_b
    pooled = (successes_a + successes_b) / (total_a + total_b)
    standard_error = math.sqrt(pooled * (1 - pooled) * (1 / total_a + 1 / total_b))
    if standard_error == 0:
        return None, None
    z = (rate_b - rate_a) / standard_error
    p_value = 2 * (1 - _normal_cdf(abs(z)))
    return z, p_value


def variant_comparison(events: Sequence[Event]) -> dict[str, Any]:
    created = _created_map(events)
    terminal = _first_terminal(events)
    variants: dict[str, str] = {}
    for event in _ordered(events):
        if event.kind != NOTIFIED or event.finding_id is None:
            continue
        variant = str((event.payload or {}).get("variant") or "")
        if variant in {"A", "B"}:
            variants.setdefault(str(event.finding_id), variant)

    stats: dict[str, dict[str, Any]] = {}
    for variant in ("A", "B"):
        population = [
            finding_id for finding_id, assigned in variants.items() if assigned == variant
        ]
        durations: list[float] = []
        triaged = 0
        for finding_id in population:
            finished = terminal.get(finding_id)
            created_at = created.get(finding_id)
            if finished is not None and created_at is not None:
                seconds = (finished - created_at[0]).total_seconds()
                if seconds >= 0:
                    durations.append(seconds)
                    triaged += 1
        stats[variant] = {
            "variant": variant,
            "n": len(population),
            "triaged": triaged,
            "triage_rate": round(triaged / len(population), 4) if population else 0.0,
            "median_seconds": round(percentile(durations, 0.5), 3) if durations else None,
        }

    rate_a = stats["A"]["triage_rate"]
    rate_b = stats["B"]["triage_rate"]
    absolute_delta = round(abs(rate_b - rate_a), 4) if stats["A"]["n"] and stats["B"]["n"] else None
    z, p_value = two_proportion_z_test(
        stats["A"]["triaged"], stats["A"]["n"], stats["B"]["triaged"], stats["B"]["n"]
    )
    significant = bool(p_value is not None and p_value < 0.05)
    if p_value is None:
        verdict = "Not enough data to compare variants."
    elif significant:
        winner = "B" if rate_b > rate_a else "A"
        verdict = (
            f"Statistically significant at p<0.05; variant {winner} had the higher triage rate."
        )
    else:
        verdict = "Not statistically significant at p<0.05; do not pick a winner from this sample."
    return {
        "variant_a": stats["A"],
        "variant_b": stats["B"],
        "absolute_delta": absolute_delta,
        "z": round(z, 4) if z is not None else None,
        "p_value": round(p_value, 6) if p_value is not None else None,
        "significant": significant,
        "verdict": verdict,
    }


def summarize(events: Sequence[Event]) -> dict[str, Any]:
    return {
        "time_to_triage": median_time_to_triage(events),
        "false_positive_rate_by_rule": false_positive_rate_by_rule(events),
        "variant_comparison": variant_comparison(events),
    }
