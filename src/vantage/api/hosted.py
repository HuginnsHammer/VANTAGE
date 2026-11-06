"""Hosted VANTAGE identity and workspace API.

Requires PostgreSQL, a restricted runtime database role and a trusted OIDC
issuer. The local development API remains a separate application.
"""
from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from vantage.auth.oidc import OIDCTokenVerifier
from vantage.persistence.postgres import (
    AuditEvent,
    Membership,
    Organization,
    Project,
    UserIdentity,
    create_postgres_engine,
    create_session_factory,
    set_tenant_context,
    validate_runtime_role,
)

TokenVerifier = Callable[[str], dict[str, Any]]


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(
        min_length=3, max_length=63,
        pattern=r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$",
    )


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(
        min_length=2, max_length=63,
        pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$",
    )


class UserIdentityView(BaseModel):
    id: UUID
    email: str | None
    display_name: str | None
    personal_organization_id: UUID


def personal_workspace_id(issuer: str, subject: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"vantage-personal:{issuer}:{subject}")


def identity_from_claims(session: Session, claims: dict[str, Any]) -> UserIdentity:
    issuer, subject = claims["iss"], claims["sub"]
    identity_id = uuid5(NAMESPACE_URL, f"vantage-identity:{issuer}:{subject}")
    set_tenant_context(session, None, identity_id)
    identity = session.scalar(select(UserIdentity).where(
        UserIdentity.issuer == issuer,
        UserIdentity.subject == subject,
    ))
    email = claims.get("email") if claims.get("email_verified") is True else None
    display_name = claims.get("name") or claims.get("preferred_username")
    if identity is None:
        identity = UserIdentity(
            id=identity_id,
            issuer=issuer,
            subject=subject,
            email=email[:320] if isinstance(email, str) else None,
            display_name=display_name[:200] if isinstance(display_name, str) else None,
        )
        session.add(identity)
        session.flush()
    else:
        if isinstance(email, str):
            identity.email = email[:320]
        if isinstance(display_name, str):
            identity.display_name = display_name[:200]
        session.flush()
    return identity


def ensure_personal_workspace(
    factory: sessionmaker[Session],
    identity_id: UUID,
    issuer: str,
    subject: str,
    display_name: str | None,
) -> Organization:
    org_id = personal_workspace_id(issuer, subject)
    try:
        with factory.begin() as session:
            set_tenant_context(session, org_id, identity_id)
            membership = session.get(Membership, (org_id, identity_id))
            if membership is None:
                label = f"{(display_name or 'Personal')[:180]} workspace"
                session.add(Organization(
                    id=org_id, slug=f"p-{org_id.hex}", name=label[:200],
                    kind="personal", status="active",
                ))
                session.flush()
                session.add(Membership(
                    organization_id=org_id, user_id=identity_id,
                    role="owner", status="active",
                ))
                session.flush()
                session.add(AuditEvent(
                    organization_id=org_id, actor_user_id=identity_id,
                    action="workspace.personal.provisioned",
                    resource_type="organization", resource_id=str(org_id),
                    details={"kind": "personal"},
                ))
                session.flush()
            elif membership.status != "active":
                raise HTTPException(403, "Personal workspace access is suspended.")
            organization = session.get(Organization, org_id)
            if organization is None or organization.status != "active":
                raise HTTPException(403, "Personal workspace is unavailable.")
            return organization
    except IntegrityError:
        # A concurrent first login may have provisioned the deterministic workspace.
        with factory.begin() as session:
            set_tenant_context(session, org_id, identity_id)
            membership = session.get(Membership, (org_id, identity_id))
            organization = session.get(Organization, org_id)
            if membership is None or membership.status != "active" or organization is None:
                raise HTTPException(503, "Workspace provisioning can be retried.")
            return organization


def create_app(
    database_url: str | None = None,
    token_verifier: TokenVerifier | None = None,
    session_factory: sessionmaker[Session] | None = None,
) -> FastAPI:
    """Build the hosted API. Test-only dependencies can be injected explicitly."""
    if session_factory is None:
        configured_url = database_url or os.environ.get("VANTAGE_DATABASE_URL")
        if not configured_url:
            raise RuntimeError("VANTAGE_DATABASE_URL is required")
        engine = create_postgres_engine(configured_url)
        validate_runtime_role(engine)
        session_factory = create_session_factory(engine)
    verifier = token_verifier or OIDCTokenVerifier.from_environment()

    app = FastAPI(
        title="VANTAGE Hosted Control Plane",
        version="0.3.0",
        docs_url="/api/docs",
        redoc_url=None,
    )
    origins = [
        item.strip() for item in os.environ.get("VANTAGE_CORS_ORIGINS", "").split(",")
        if item.strip()
    ]
    if "*" in origins:
        raise RuntimeError("VANTAGE_CORS_ORIGINS must contain explicit trusted origins")
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
        )

    bearer = HTTPBearer(auto_error=False)

    def current_identity(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> UserIdentityView:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="A valid OIDC access token is required.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            claims = verifier(credentials.credentials)
            issuer, subject = claims["iss"], claims["sub"]
            if not isinstance(issuer, str) or not issuer or len(issuer) > 500:
                raise ValueError("Invalid issuer")
            if not isinstance(subject, str) or not subject or len(subject) > 255:
                raise ValueError("Invalid subject")
        except Exception as exc:
            raise HTTPException(
                status_code=401,
                detail="The supplied access token is invalid or expired.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        try:
            with session_factory.begin() as session:
                identity = identity_from_claims(session, claims)
                data = (identity.id, identity.issuer, identity.subject,
                        identity.email, identity.display_name)
        except IntegrityError:
            with session_factory.begin() as session:
                identity = session.scalar(select(UserIdentity).where(
                    UserIdentity.issuer == issuer,
                    UserIdentity.subject == subject,
                ))
                if identity is None:
                    raise HTTPException(503, "Identity provisioning can be retried.")
                data = (identity.id, identity.issuer, identity.subject,
                        identity.email, identity.display_name)

        organization = ensure_personal_workspace(
            session_factory, data[0], data[1], data[2], data[4]
        )
        return UserIdentityView(
            id=data[0], email=data[3], display_name=data[4],
            personal_organization_id=organization.id,
        )

    def require_membership(
        session: Session, organization_id: UUID, identity_id: UUID
    ) -> Membership:
        set_tenant_context(session, organization_id, identity_id)
        membership = session.get(Membership, (organization_id, identity_id))
        if membership is None or membership.status != "active":
            # Do not reveal whether an inaccessible organization exists.
            raise HTTPException(404, "Workspace not found.")
        return membership

    @app.get("/api/v2/health")
    def health() -> dict[str, str]:
        with session_factory() as session:
            session.execute(select(1))
        return {"status": "ok", "service": "VANTAGE hosted control plane", "database": "postgresql"}

    @app.get("/api/v2/me")
    def me(identity: UserIdentityView = Depends(current_identity)) -> dict[str, Any]:
        workspaces = []
        with session_factory.begin() as session:
            set_tenant_context(session, None, identity.id)
            memberships = session.scalars(select(Membership).where(
                Membership.user_id == identity.id,
                Membership.status == "active",
            )).all()
            for membership in memberships:
                set_tenant_context(session, membership.organization_id, identity.id)
                organization = session.get(Organization, membership.organization_id)
                if organization is not None and organization.status == "active":
                    workspaces.append({
                        "id": str(organization.id), "name": organization.name,
                        "slug": organization.slug, "kind": organization.kind,
                        "role": membership.role,
                    })
        return {
            "user": {"id": str(identity.id), "email": identity.email,
                     "display_name": identity.display_name},
            "personal_organization_id": str(identity.personal_organization_id),
            "workspaces": workspaces,
        }

    @app.post("/api/v2/organizations", status_code=201)
    def create_organization(
        payload: OrganizationCreate,
        identity: UserIdentityView = Depends(current_identity),
    ) -> dict[str, str]:
        organization_id = uuid4()
        try:
            with session_factory.begin() as session:
                set_tenant_context(session, organization_id, identity.id)
                organization = Organization(
                    id=organization_id, slug=payload.slug, name=payload.name.strip(),
                    kind="organization", status="active",
                )
                session.add(organization)
                session.flush()
                session.add(Membership(
                    organization_id=organization_id, user_id=identity.id,
                    role="owner", status="active",
                ))
                session.flush()
                session.add(AuditEvent(
                    organization_id=organization_id, actor_user_id=identity.id,
                    action="workspace.organization.created",
                    resource_type="organization", resource_id=str(organization_id),
                    details={"slug": payload.slug},
                ))
                session.flush()
        except IntegrityError as exc:
            raise HTTPException(409, "That workspace slug is already in use.") from exc
        return {"id": str(organization.id), "name": organization.name,
                "slug": organization.slug, "kind": organization.kind, "role": "owner"}

    @app.get("/api/v2/organizations/{organization_id}")
    def get_organization(
        organization_id: UUID,
        identity: UserIdentityView = Depends(current_identity),
    ) -> dict[str, str]:
        with session_factory.begin() as session:
            membership = require_membership(session, organization_id, identity.id)
            organization = session.get(Organization, organization_id)
            if organization is None or organization.status != "active":
                raise HTTPException(404, "Workspace not found.")
            return {"id": str(organization.id), "name": organization.name,
                    "slug": organization.slug, "kind": organization.kind,
                    "role": membership.role}

    @app.get("/api/v2/organizations/{organization_id}/members")
    def list_members(
        organization_id: UUID,
        identity: UserIdentityView = Depends(current_identity),
    ) -> dict[str, Any]:
        with session_factory.begin() as session:
            membership = require_membership(session, organization_id, identity.id)
            if membership.role not in {"owner", "admin"}:
                raise HTTPException(403, "Workspace administrator role required.")
            rows = session.execute(
                select(Membership, UserIdentity).join(
                    UserIdentity, UserIdentity.id == Membership.user_id
                ).where(Membership.organization_id == organization_id)
            ).all()
            return {"items": [{
                "user_id": str(member.user_id), "email": user.email,
                "display_name": user.display_name, "role": member.role,
                "status": member.status,
            } for member, user in rows]}

    @app.post("/api/v2/organizations/{organization_id}/projects", status_code=201)
    def create_project(
        organization_id: UUID,
        payload: ProjectCreate,
        identity: UserIdentityView = Depends(current_identity),
    ) -> dict[str, str]:
        try:
            with session_factory.begin() as session:
                membership = require_membership(session, organization_id, identity.id)
                if membership.role not in {"owner", "admin", "security_analyst", "operator"}:
                    raise HTTPException(403, "Insufficient workspace permissions.")
                project = Project(
                    organization_id=organization_id, slug=payload.slug,
                    name=payload.name.strip(),
                )
                session.add(project)
                session.flush()
                session.add(AuditEvent(
                    organization_id=organization_id, actor_user_id=identity.id,
                    action="project.created", resource_type="project",
                    resource_id=str(project.id), details={"slug": project.slug},
                ))
                return {"id": str(project.id), "organization_id": str(organization_id),
                        "name": project.name, "slug": project.slug}
        except IntegrityError as exc:
            raise HTTPException(409, "That project slug is already in use.") from exc

    @app.get("/api/v2/organizations/{organization_id}/projects")
    def list_projects(
        organization_id: UUID,
        identity: UserIdentityView = Depends(current_identity),
    ) -> dict[str, Any]:
        with session_factory.begin() as session:
            require_membership(session, organization_id, identity.id)
            projects = session.scalars(select(Project).where(
                Project.organization_id == organization_id
            ).order_by(Project.created_at)).all()
            return {"items": [{
                "id": str(project.id), "name": project.name,
                "slug": project.slug, "created_at": project.created_at.isoformat(),
            } for project in projects]}

    return app
