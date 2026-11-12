#!/usr/bin/env python
"""Generate a deterministic, realistic triage history over the seeded findings.

Every transition goes through ``app.services.triage.apply_transition`` and every
notification through the same variant picker the Slack renderer uses, so the
events are produced by application code rather than hand-written rows.

Usage: python scripts/simulate.py
"""

from __future__ import annotations

import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import func, select  # noqa: E402

from app.db import SessionLocal  # noqa: E402
from app.integrations.slack.format import pick_variant  # noqa: E402
from app.models import Event, Finding, Surface, User  # noqa: E402
from app.services.triage import apply_transition  # noqa: E402

SEED = 20261112
AS_OF = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)

# Deliberately noisy rules: the false-positive metric should surface these.
MUTE_PROBABILITY = {
    "python.lang.correctness.useless-comparison": 0.85,
    "python.flask.security.audit.debug-enabled": 0.8,
    "python.lang.security.audit.weak-hash": 0.72,
    "javascript.lang.security.audit.prototype-pollution": 0.68,
    "python.cryptography.security.insufficient-key-size": 0.6,
    "javascript.lang.security.audit.innerhtml": 0.45,
    "go.lang.security.audit.insecure-tls": 0.35,
}

SEVERITY_BASE_HOURS = {"critical": 2.0, "high": 5.0, "medium": 11.0, "low": 19.0}
VARIANT_COMPLETION = {"A": 0.86, "B": 0.70}
VARIANT_DELAY_FACTOR = {"A": 0.65, "B": 1.2}


def event_time_for(finding: Finding, delay_hours: float) -> datetime:
    candidate = finding.first_seen_at + timedelta(hours=delay_hours)
    if candidate >= AS_OF:
        elapsed = (AS_OF - finding.first_seen_at).total_seconds()
        candidate = finding.first_seen_at + timedelta(seconds=max(60.0, elapsed * 0.5))
    return candidate


def main() -> None:
    rng = random.Random(SEED)
    with SessionLocal() as db:
        already = db.scalar(select(func.count()).select_from(Event).where(Event.kind == "notification.sent"))
        if already:
            print(f"simulation already present ({already} notification.sent events); nothing to do")
            return

        findings = list(db.scalars(select(Finding).order_by(Finding.id)).all())
        users = list(db.scalars(select(User)).all())
        users_by_workspace: dict[str, list[User]] = {}
        for user in users:
            users_by_workspace.setdefault(str(user.workspace_id), []).append(user)

        notifications = 0
        transitions = 0
        auto_resolved = 0
        for index, finding in enumerate(findings):
            variant = pick_variant(finding.id)
            finding.notification_variant = variant
            notified_at = finding.first_seen_at + timedelta(seconds=45)
            db.add(
                Event(
                    workspace_id=finding.workspace_id,
                    finding_id=finding.id,
                    kind="notification.sent",
                    surface=Surface.slack,
                    payload={
                        "variant": variant.value,
                        "rule_id": finding.rule_id,
                        "repo": finding.repo,
                        "severity": finding.severity.value,
                    },
                    created_at=notified_at,
                )
            )
            notifications += 1

            workspace_users = users_by_workspace.get(str(finding.workspace_id), [])
            actor = rng.choice(workspace_users) if workspace_users else None

            if index % 17 == 0:
                resolved_at = event_time_for(finding, rng.uniform(24, 96))
                apply_transition(
                    finding,
                    "resolve",
                    None,
                    Surface.github,
                    db=db,
                    now=resolved_at,
                    event_kind="finding.auto_resolved",
                    payload_extra={"reason": "line_changed_or_removed", "ref": "simulated-head"},
                )
                transitions += 1
                auto_resolved += 1
                continue

            if rng.random() > VARIANT_COMPLETION[variant.value]:
                continue

            noise = MUTE_PROBABILITY.get(finding.rule_id, 0.16)
            action = "mute" if rng.random() < noise else "accept"
            base = SEVERITY_BASE_HOURS.get(finding.severity.value, 12.0)
            delay = base * VARIANT_DELAY_FACTOR[variant.value] * rng.lognormvariate(0.0, 0.55)
            happened_at = event_time_for(finding, delay)
            surface = rng.choices(
                [Surface.slack, Surface.github, Surface.console],
                weights=[0.42, 0.23, 0.35],
                k=1,
            )[0]
            apply_transition(
                finding,
                action,
                actor,
                surface,
                db=db,
                now=happened_at,
                payload_extra={"simulated": True},
            )
            transitions += 1

        db.commit()

    print(
        f"simulated {notifications} notifications, {transitions} triage transitions "
        f"({auto_resolved} auto-resolved) across {len(findings)} findings"
    )


if __name__ == "__main__":
    main()
