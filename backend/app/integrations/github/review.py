"""Group findings into a single GitHub PR review with inline comments."""

from __future__ import annotations

from typing import Any

from app.clients.base import GitHubClient
from app.models import Finding


def inline_comment(finding: Finding) -> dict[str, Any]:
    body = f"**{finding.severity.value.upper()}** · `{finding.rule_id}`\n\n" f"{finding.message}"
    if finding.rule_rationale:
        body += f"\n\n_{finding.rule_rationale}_"
    return {
        "path": finding.file_path,
        "line": finding.start_line,
        "side": "RIGHT",
        "body": body,
    }


def post_findings_as_review(
    client: GitHubClient,
    installation_token: str,
    repo: str,
    pr_number: int,
    commit_id: str,
    findings: list[Finding],
) -> dict[str, Any]:
    comments = [inline_comment(finding) for finding in findings]
    body = f"TriageHub found {len(findings)} finding(s) on this pull request."
    return client.post_review(installation_token, repo, pr_number, commit_id, body, comments)
