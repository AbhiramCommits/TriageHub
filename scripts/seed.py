#!/usr/bin/env python
"""Idempotently seed TriageHub with two workspaces, users and a findings stream.

Usage (from the repo root, with .venv active):

    python scripts/seed.py
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.config import settings  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.integrations.github.fingerprint import fingerprint_line  # noqa: E402
from app.models import (  # noqa: E402
    Event,
    Finding,
    Role,
    Severity,
    Surface,
    User,
    Workspace,
)

NS = uuid.UUID("6f1d0f0e-3f0e-4b3e-9f1c-2a5b7c8d9e0f")

WORKSPACES = [
    {
        "slug": "acme-security",
        "name": "Acme Security",
        "sso_only": False,
        "oidc_issuer": None,
        "oidc_client_id": None,
        "users": [
            ("ada@acme.test", "admin"),
            ("grace@acme.test", "reviewer"),
            ("linus@acme.test", "reviewer"),
            ("mira@acme.test", "reviewer"),
        ],
    },
    {
        "slug": "northwind-labs",
        "name": "Northwind Labs",
        "sso_only": True,
        "oidc_issuer": settings.oidc_issuer,
        "oidc_client_id": settings.oidc_client_id,
        "users": [
            ("ops@northwind.test", "admin"),
            ("sam@northwind.test", "reviewer"),
        ],
    },
]


def stable_id(*parts: str) -> uuid.UUID:
    return uuid.uuid5(NS, "|".join(parts))


def seed_workspace(db: Session, spec: dict) -> tuple[Workspace, dict[str, User]]:
    ws = db.scalars(select(Workspace).where(Workspace.slug == spec["slug"])).first()
    if ws is None:
        ws = Workspace(
            id=stable_id("workspace", spec["slug"]),
            name=spec["name"],
            slug=spec["slug"],
            sso_only=spec["sso_only"],
            oidc_issuer=spec["oidc_issuer"],
            oidc_client_id=spec["oidc_client_id"],
        )
        db.add(ws)
        db.flush()
    users: dict[str, User] = {}
    for email, role in spec["users"]:
        user = db.scalars(
            select(User).where(User.workspace_id == ws.id, User.email == email)
        ).first()
        if user is None:
            user = User(
                id=stable_id("user", spec["slug"], email),
                workspace_id=ws.id,
                email=email,
                external_subject=stable_id("subject", spec["slug"], email).hex,
                role=Role(role),
            )
            db.add(user)
        users[email] = user
    db.flush()
    return ws, users


def main() -> None:
    sample_path = ROOT / "data" / "findings_sample.json"
    findings = json.loads(sample_path.read_text())
    created_findings = 0
    created_events = 0

    with SessionLocal() as db:
        workspaces = [seed_workspace(db, spec) for spec in WORKSPACES]
        for ws_index, (ws, _users) in enumerate(workspaces):
            # Split the sample stream deterministically across the workspaces.
            share = [f for i, f in enumerate(findings) if i % len(WORKSPACES) == ws_index]
            for item in share:
                key = "|".join(
                    [
                        ws.slug,
                        item["repo"],
                        item["file_path"],
                        str(item["start_line"]),
                        item["rule_id"],
                        item["code_snippet"],
                    ]
                )
                fid = stable_id("finding", key)
                existing = db.get(Finding, fid)
                if existing is not None:
                    continue
                first_seen = datetime.fromisoformat(item["first_seen_at"])
                finding = Finding(
                    id=fid,
                    workspace_id=ws.id,
                    rule_id=item["rule_id"],
                    severity=Severity(item["severity"]),
                    message=item["message"],
                    repo=item["repo"],
                    file_path=item["file_path"],
                    start_line=item["start_line"],
                    end_line=item["end_line"],
                    line_fingerprint=fingerprint_line(item["code_snippet"]),
                    code_snippet=item["code_snippet"],
                    rule_rationale=item["rule_rationale"],
                    first_seen_at=first_seen,
                )
                db.add(finding)
                db.flush()
                db.add(
                    Event(
                        id=stable_id("event", key, "finding.created"),
                        workspace_id=ws.id,
                        finding_id=fid,
                        kind="finding.created",
                        surface=Surface.system,
                        payload={
                            "rule_id": item["rule_id"],
                            "severity": item["severity"],
                            "repo": item["repo"],
                        },
                        created_at=first_seen,
                    )
                )
                created_findings += 1
                created_events += 1
        db.commit()

    print(f"seeded {len(WORKSPACES)} workspaces")
    print(f"created {created_findings} findings and {created_events} finding.created events")


if __name__ == "__main__":
    main()
