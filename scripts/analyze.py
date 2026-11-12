#!/usr/bin/env python
"""Compute metrics from Postgres and write results/metrics.json + results/metrics.md."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import distinct, func, select  # noqa: E402

from app.analytics.metrics import summarize  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.models import Event, Finding  # noqa: E402

RESULTS = ROOT / "results"


def human_seconds(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    total = int(round(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def main() -> None:
    with SessionLocal() as db:
        events = list(db.scalars(select(Event).order_by(Event.created_at)).all())
        finding_count = db.scalar(select(func.count()).select_from(Finding)) or 0
        repo_count = db.scalar(select(func.count(distinct(Finding.repo)))) or 0
        rule_count = db.scalar(select(func.count(distinct(Finding.rule_id)))) or 0
        event_count = len(events)
        transition_count = sum(
            1
            for event in events
            if event.kind
            in {"finding.accepted", "finding.muted", "finding.fixed", "finding.auto_resolved"}
        )

    metrics = summarize(events)
    metadata = {
        "findings": finding_count,
        "events": event_count,
        "terminal_transitions": transition_count,
        "repos": repo_count,
        "rules": rule_count,
    }
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": metadata,
        "metrics": metrics,
    }

    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "metrics.json").write_text(json.dumps(payload, indent=2) + "\n")

    ttt = metrics["time_to_triage"]
    lines: list[str] = [
        "# TriageHub metrics",
        "",
        f"Generated {payload['generated_at']} from {finding_count} findings, "
        f"{event_count} events ({transition_count} terminal transitions), "
        f"{rule_count} rules and {repo_count} repositories.",
        "",
        "## Time to triage",
        "",
        "| Scope | n | Median (s) | Median | p90 (s) | p90 |",
        "|---|---:|---:|---|---:|---|",
    ]
    overall = ttt["overall"]
    lines.append(
        f"| overall | {overall['n']} | {overall['median_seconds']:.2f} | "
        f"{human_seconds(overall['median_seconds'])} | {overall['p90_seconds']:.2f} | "
        f"{human_seconds(overall['p90_seconds'])} |"
    )
    for severity, bucket in ttt["by_severity"].items():
        lines.append(
            f"| {severity} | {bucket['n']} | {bucket['median_seconds']:.2f} | "
            f"{human_seconds(bucket['median_seconds'])} | {bucket['p90_seconds']:.2f} | "
            f"{human_seconds(bucket['p90_seconds'])} |"
        )

    lines += [
        "",
        "## False-positive rate by rule (n >= 5 accepted or muted)",
        "",
        "| Rule | Muted | Accepted | n | FP rate |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in metrics["false_positive_rate_by_rule"]:
        n = row["muted"] + row["accepted"]
        lines.append(
            f"| `{row['rule_id']}` | {row['muted']} | {row['accepted']} | {n} | "
            f"{row['fp_rate'] * 100:.2f}% |"
        )

    comparison = metrics["variant_comparison"]
    a = comparison["variant_a"]
    b = comparison["variant_b"]
    lines += [
        "",
        "## A/B notification experiment",
        "",
        "| Variant | n | Triaged | Triage rate | Median time to triage (s) | Median |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for stats in (a, b):
        lines.append(
            f"| {stats['variant']} | {stats['n']} | {stats['triaged']} | "
            f"{stats['triage_rate'] * 100:.2f}% | "
            f"{stats['median_seconds']:.2f} | {human_seconds(stats['median_seconds'])} |"
            if stats["median_seconds"] is not None
            else f"| {stats['variant']} | {stats['n']} | {stats['triaged']} | "
            f"{stats['triage_rate'] * 100:.2f}% | — | — |"
        )
    lines += [
        "",
        f"Absolute difference in triage rate: {comparison['absolute_delta']}",
        f"Two-proportion z-test: z = {comparison['z']}, two-sided p = {comparison['p_value']}",
        f"Verdict: **{comparison['verdict']}**",
        "",
    ]
    (RESULTS / "metrics.md").write_text("\n".join(lines))
    print(f"wrote results/metrics.json and results/metrics.md for {event_count} events")


if __name__ == "__main__":
    main()
