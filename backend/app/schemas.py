"""Pydantic v2 request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models import FindingState, Provider, Role, Severity, Surface, Variant


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class WorkspaceOut(ORMModel):
    id: uuid.UUID
    name: str
    slug: str
    sso_only: bool
    oidc_issuer: str | None
    created_at: datetime


class UserOut(ORMModel):
    id: uuid.UUID
    workspace_id: uuid.UUID
    email: str
    role: Role
    created_at: datetime


class FindingOut(ORMModel):
    id: uuid.UUID
    workspace_id: uuid.UUID
    rule_id: str
    severity: Severity
    message: str
    repo: str
    file_path: str
    start_line: int
    end_line: int
    line_fingerprint: str
    code_snippet: str | None
    rule_rationale: str | None
    state: FindingState
    assignee_user_id: uuid.UUID | None
    first_seen_at: datetime
    triaged_at: datetime | None
    notification_variant: Variant | None


class FindingPage(BaseModel):
    items: list[FindingOut]
    next_cursor: str | None = None


class EventOut(ORMModel):
    id: uuid.UUID
    workspace_id: uuid.UUID
    finding_id: uuid.UUID | None
    actor_user_id: uuid.UUID | None
    kind: str
    surface: Surface
    payload: dict[str, object]
    created_at: datetime


class TransitionRequest(BaseModel):
    action: str = Field(description="accept | mute | reopen | assign | resolve")
    assignee_user_id: uuid.UUID | None = None


class BulkTransitionRequest(BaseModel):
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)
    action: str
    assignee_user_id: uuid.UUID | None = None


class BulkTransitionResult(BaseModel):
    updated: list[FindingOut]
    skipped: list[dict[str, str]]


class InstallationOut(ORMModel):
    id: uuid.UUID
    workspace_id: uuid.UUID
    provider: Provider
    external_id: str
    expires_at: datetime | None
    scopes: str | None
    created_at: datetime


class SessionUser(BaseModel):
    user_id: uuid.UUID
    workspace_id: uuid.UUID
    email: str
    role: Role


# ---- Metrics ----


class TimeBucket(BaseModel):
    n: int
    median_seconds: float
    p90_seconds: float


class TimeToTriage(BaseModel):
    overall: TimeBucket
    by_severity: dict[str, TimeBucket]


class RuleFpRate(BaseModel):
    rule_id: str
    muted: int
    accepted: int
    fp_rate: float


class VariantStats(BaseModel):
    variant: str
    n: int
    triaged: int
    triage_rate: float
    median_seconds: float | None


class VariantComparison(BaseModel):
    variant_a: VariantStats
    variant_b: VariantStats
    absolute_delta: float | None
    z: float | None
    p_value: float | None
    significant: bool
    verdict: str


class MetricsSummary(BaseModel):
    time_to_triage: TimeToTriage
    false_positive_rate_by_rule: list[RuleFpRate]
    variant_comparison: VariantComparison
