"""Shared test fixtures: a real Postgres test database, rollback per test,
httpx ASGI transport and recording fakes for every external provider."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.clients.deps import get_github_client, get_oidc_provider, get_slack_client
from app.clients.fakes import FakeGitHubClient, FakeOIDCProvider, FakeSlackClient
from app.config import settings
from app.db import Base, get_db
from app.integrations.github.fingerprint import fingerprint_line
from app.main import create_app
from app.models import Finding, FindingState, Role, Severity, User, Workspace


def _database_url() -> str:
    explicit = os.environ.get("TEST_DATABASE_URL")
    if explicit:
        return explicit
    url = make_url(settings.database_url)
    return url.set(database=f"{url.database}_test").render_as_string(hide_password=False)


TEST_DATABASE_URL = _database_url()


@pytest.fixture(scope="session")
def engine() -> Iterator[object]:
    url = make_url(TEST_DATABASE_URL)
    admin = create_engine(
        url.set(database="postgres").render_as_string(hide_password=False),
        isolation_level="AUTOCOMMIT",
    )
    with admin.connect() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": url.database}
        ).scalar()
        if not exists:
            conn.execute(text(f'CREATE DATABASE "{url.database}"'))
    admin.dispose()

    test_engine = create_engine(TEST_DATABASE_URL, pool_pre_ping=True, future=True)
    Base.metadata.drop_all(test_engine)
    Base.metadata.create_all(test_engine)
    yield test_engine
    Base.metadata.drop_all(test_engine)
    test_engine.dispose()


@pytest.fixture
def db(engine: object) -> Iterator[Session]:
    connection = engine.connect()  # type: ignore[attr-defined]
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture(autouse=True)
def _reset_installation_token_cache() -> Iterator[None]:
    from app.integrations.github.app_auth import installation_token_cache

    installation_token_cache.clear()
    yield
    installation_token_cache.clear()


@pytest.fixture
def slack() -> FakeSlackClient:
    return FakeSlackClient()


@pytest.fixture
def github() -> FakeGitHubClient:
    return FakeGitHubClient()


@pytest.fixture
def oidc() -> FakeOIDCProvider:
    return FakeOIDCProvider()


@pytest_asyncio.fixture
async def client(
    db: Session, slack: FakeSlackClient, github: FakeGitHubClient, oidc: FakeOIDCProvider
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_slack_client] = lambda: slack
    app.dependency_overrides[get_github_client] = lambda: github
    app.dependency_overrides[get_oidc_provider] = lambda: oidc
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


# ---- Factories ----


def make_workspace(
    db: Session,
    *,
    slug: str = "acme",
    sso_only: bool = False,
    oidc_issuer: str | None = None,
) -> Workspace:
    ws = Workspace(
        name=slug.title(),
        slug=slug,
        sso_only=sso_only,
        oidc_issuer=oidc_issuer or settings.oidc_issuer,
        oidc_client_id=settings.oidc_client_id,
    )
    db.add(ws)
    db.flush()
    return ws


def make_user(
    db: Session,
    workspace: Workspace,
    *,
    email: str = "reviewer@acme.test",
    role: Role = Role.reviewer,
) -> User:
    user = User(
        workspace_id=workspace.id,
        email=email,
        external_subject=f"subject-{uuid.uuid4()}",
        role=role,
    )
    db.add(user)
    db.flush()
    return user


def make_finding(
    db: Session,
    workspace: Workspace,
    *,
    rule_id: str = "python.lang.security.audit.eval-detected",
    severity: Severity = Severity.high,
    repo: str = "acme/payments-api",
    file_path: str = "app/api/charges.py",
    start_line: int = 42,
    snippet: str = 'result = eval(request.args["expr"])',
    state: FindingState = FindingState.open,
) -> Finding:
    finding = Finding(
        workspace_id=workspace.id,
        rule_id=rule_id,
        severity=severity,
        message="Avoid eval() on untrusted input",
        repo=repo,
        file_path=file_path,
        start_line=start_line,
        end_line=start_line,
        line_fingerprint=fingerprint_line(snippet),
        code_snippet=snippet,
        rule_rationale="eval executes arbitrary code.",
        state=state,
        first_seen_at=datetime.now(UTC),
    )
    db.add(finding)
    db.flush()
    return finding
