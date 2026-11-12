"""Typed SQLAlchemy 2.x models for TriageHub."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class Role(enum.StrEnum):
    admin = "admin"
    reviewer = "reviewer"


class Provider(enum.StrEnum):
    slack = "slack"
    github = "github"


class Severity(enum.StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingState(enum.StrEnum):
    open = "open"
    accepted = "accepted"
    muted = "muted"
    fixed = "fixed"


class Variant(enum.StrEnum):
    A = "A"
    B = "B"


class Surface(enum.StrEnum):
    slack = "slack"
    github = "github"
    console = "console"
    system = "system"


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        length=32,
        values_callable=lambda members: [str(member.value) for member in members],
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Workspace(Base, TimestampMixin):
    __tablename__ = "workspaces"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    sso_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    oidc_issuer: Mapped[str | None] = mapped_column(String(500), nullable=True)
    oidc_client_id: Mapped[str | None] = mapped_column(String(200), nullable=True)

    users: Mapped[list[User]] = relationship(back_populates="workspace")
    findings: Mapped[list[Finding]] = relationship(back_populates="workspace")


class User(Base, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("workspace_id", "email", name="uq_user_workspace_email"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    external_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(
        _enum(Role, "user_role"), nullable=False, default=Role.reviewer
    )

    workspace: Mapped[Workspace] = relationship(back_populates="users")


class Installation(Base, TimestampMixin):
    __tablename__ = "installations"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id", "provider", "external_id", name="uq_installation_workspace_provider_ext"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[Provider] = mapped_column(_enum(Provider, "provider"), nullable=False)
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    encrypted_access_token: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_refresh_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scopes: Mapped[str | None] = mapped_column(Text, nullable=True)

    workspace: Mapped[Workspace] = relationship()


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_workspace_state", "workspace_id", "state"),
        Index("ix_findings_workspace_severity", "workspace_id", "severity"),
        Index("ix_findings_workspace_rule", "workspace_id", "rule_id"),
        Index("ix_findings_workspace_repo", "workspace_id", "repo"),
        Index("ix_findings_cursor", "first_seen_at", "id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    repo: Mapped[str] = mapped_column(String(200), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False)
    line_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[FindingState] = mapped_column(
        _enum(FindingState, "finding_state"), nullable=False, default=FindingState.open
    )
    assignee_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notification_variant: Mapped[Variant | None] = mapped_column(
        _enum(Variant, "variant"), nullable=True
    )

    __mapper_args__ = {"eager_defaults": True}

    workspace: Mapped[Workspace] = relationship(back_populates="findings")
    assignee: Mapped[User | None] = relationship(foreign_keys=[assignee_user_id])


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_workspace_kind_created", "workspace_id", "kind", "created_at"),
        Index("ix_events_finding", "finding_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    kind: Mapped[str] = mapped_column(String(120), nullable=False)
    surface: Mapped[Surface] = mapped_column(_enum(Surface, "surface"), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
