"""Hosted VANTAGE identity and workspace API.

Requires PostgreSQL, a restricted runtime database role and a trusted OIDC
issuer. The local development API remains a separate application.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
from collections.abc import Callable
from datetime import timedelta
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import dns.exception
import dns.resolver

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from vantage.auth.oidc import OIDCTokenVerifier
from vantage.persistence.postgres import (
    AssetRecord,
    AuditEvent,
    DomainVerificationChallenge,
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


class DomainAssetCreate(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    display_name: str | None = Field(default=None, max_length=255)
    project_id: UUID | None = None


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_RESERVED_SUFFIXES = (
    ".localhost", ".local", ".internal", ".test", ".example", ".invalid",
    ".onion", ".home.arpa",
)
_RESERVED_DOMAINS = {"example.com", "example.net", "example.org"}


def canonicalize_domain(raw: str) -> str:
    candidate = raw.strip().rstrip(".")
    if (
        not candidate
        or "://" in candidate
        or any(character in candidate for character in "/:@?#")
        or any(character.isspace() for character in candidate)
    ):
        raise ValueError("Enter a domain name only, without a URL, path, port or wildcard.")
    try:
        domain = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("The domain name is not valid IDNA.") from exc
    if len(domain) > 234 or "." not in domain:
        raise ValueError("A fully qualified public domain name is required.")
    if domain in _RESERVED_DOMAINS or domain.endswith(_RESERVED_SUFFIXES):
        raise ValueError("Private, reserved and test-only domain names cannot be registered.")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("Register a domain name, not an IP address.")
    labels = domain.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("The domain name contains an invalid label.")
    if len(labels[-1]) < 2:
        raise ValueError("The domain must have a valid public suffix.")
    return domain


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


    @app.get("/api/v2/organizations/{organization_id}/assets")
    def list_assets(
        organization_id: UUID,
        identity: UserIdentityView = Depends(current_identity),
    ) -> dict[str, Any]:
        with session_factory.begin() as session:
            require_membership(session, organization_id, identity.id)
            assets = session.scalars(
                select(AssetRecord)
                .where(AssetRecord.organization_id == organization_id)
                .order_by(AssetRecord.created_at.desc())
            ).all()
            return {"items": [{
                "id": str(asset.id),
                "kind": asset.kind,
                "canonical_value": asset.canonical_value,
                "display_name": asset.display_name,
                "project_id": str(asset.project_id) if asset.project_id else None,
                "ownership_verified": asset.ownership_verified_at is not None,
                "ownership_verified_at": (
                    asset.ownership_verified_at.isoformat()
                    if asset.ownership_verified_at else None
                ),
                "created_at": asset.created_at.isoformat(),
            } for asset in assets]}

    @app.post("/api/v2/organizations/{organization_id}/assets", status_code=201)
    def create_domain_asset(
        organization_id: UUID,
        payload: DomainAssetCreate,
        identity: UserIdentityView = Depends(current_identity),
    ) -> dict[str, Any]:
        try:
            domain = canonicalize_domain(payload.domain)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        with session_factory.begin() as session:
            membership = require_membership(session, organization_id, identity.id)
            if membership.role not in {"owner", "admin", "security_analyst", "operator"}:
                raise HTTPException(403, "Insufficient workspace permissions.")
            if payload.project_id is not None:
                project = session.get(Project, payload.project_id)
                if project is None or project.organization_id != organization_id:
                    raise HTTPException(404, "Project not found.")
            existing = session.scalar(select(AssetRecord).where(
                AssetRecord.organization_id == organization_id,
                AssetRecord.kind == "domain",
                AssetRecord.canonical_value == domain,
                AssetRecord.environment_id.is_(None),
            ))
            if existing is not None:
                raise HTTPException(409, "This domain is already registered in the workspace.")
            asset = AssetRecord(
                organization_id=organization_id,
                project_id=payload.project_id,
                kind="domain",
                canonical_value=domain,
                display_name=((payload.display_name or domain).strip() or domain)[:255],
            )
            session.add(asset)
            session.flush()
            session.add(AuditEvent(
                organization_id=organization_id,
                actor_user_id=identity.id,
                action="asset.domain.registered",
                resource_type="asset",
                resource_id=str(asset.id),
                details={"domain": domain},
            ))
            session.flush()
            return {
                "id": str(asset.id),
                "kind": asset.kind,
                "canonical_value": asset.canonical_value,
                "display_name": asset.display_name,
                "ownership_verified": False,
                "created_at": asset.created_at.isoformat(),
            }

    @app.post(
        "/api/v2/organizations/{organization_id}/assets/{asset_id}/domain-verification",
        status_code=201,
    )
    def create_domain_verification(
        organization_id: UUID,
        asset_id: UUID,
        identity: UserIdentityView = Depends(current_identity),
    ) -> dict[str, Any]:
        with session_factory.begin() as session:
            membership = require_membership(session, organization_id, identity.id)
            if membership.role not in {"owner", "admin", "security_analyst", "operator"}:
                raise HTTPException(403, "Insufficient workspace permissions.")
            asset = session.get(AssetRecord, asset_id)
            if asset is None or asset.kind != "domain":
                raise HTTPException(404, "Domain asset not found.")
            if asset.ownership_verified_at is not None:
                return {"status": "verified", "asset_id": str(asset.id)}
            now = utc_now()
            recent_count = session.scalar(select(func.count()).select_from(
                DomainVerificationChallenge
            ).where(
                DomainVerificationChallenge.organization_id == organization_id,
                DomainVerificationChallenge.asset_id == asset_id,
                DomainVerificationChallenge.created_at >= now - timedelta(hours=1),
            ))
            if recent_count is not None and recent_count >= 5:
                raise HTTPException(429, "Too many verification challenges. Try again later.")
            token = secrets.token_urlsafe(32)
            record_name = f"_vantage-challenge.{asset.canonical_value}"
            record_value = f"vantage-verification={token}"
            challenge = DomainVerificationChallenge(
                organization_id=organization_id,
                asset_id=asset_id,
                requested_by=identity.id,
                method="dns_txt",
                record_name=record_name,
                token_hash=hashlib.sha256(record_value.encode("utf-8")).hexdigest(),
                status="pending",
                created_at=now,
                expires_at=now + timedelta(minutes=30),
            )
            session.add(challenge)
            session.flush()
            session.add(AuditEvent(
                organization_id=organization_id,
                actor_user_id=identity.id,
                action="asset.domain_verification.challenge_created",
                resource_type="asset",
                resource_id=str(asset_id),
                details={"method": "dns_txt", "challenge_id": str(challenge.id)},
            ))
            session.flush()
            return {
                "challenge_id": str(challenge.id),
                "status": "pending",
                "method": "dns_txt",
                "record_type": "TXT",
                "record_name": record_name,
                "record_value": record_value,
                "expires_at": challenge.expires_at.isoformat(),
            }

    @app.post(
        "/api/v2/organizations/{organization_id}/assets/{asset_id}/domain-verification/verify"
    )
    def verify_domain_ownership(
        organization_id: UUID,
        asset_id: UUID,
        identity: UserIdentityView = Depends(current_identity),
    ) -> dict[str, Any]:
        with session_factory.begin() as session:
            membership = require_membership(session, organization_id, identity.id)
            if membership.role not in {"owner", "admin", "security_analyst", "operator"}:
                raise HTTPException(403, "Insufficient workspace permissions.")
            asset = session.get(AssetRecord, asset_id)
            if asset is None or asset.kind != "domain":
                raise HTTPException(404, "Domain asset not found.")
            if asset.ownership_verified_at is not None:
                return {
                    "status": "verified",
                    "asset_id": str(asset.id),
                    "verified_at": asset.ownership_verified_at.isoformat(),
                }
            challenge = session.scalar(
                select(DomainVerificationChallenge)
                .where(
                    DomainVerificationChallenge.organization_id == organization_id,
                    DomainVerificationChallenge.asset_id == asset_id,
                    DomainVerificationChallenge.status == "pending",
                )
                .order_by(DomainVerificationChallenge.created_at.desc())
                .limit(1)
            )
            if challenge is None:
                raise HTTPException(404, "No pending domain verification challenge exists.")
            now = utc_now()
            if challenge.expires_at <= now:
                challenge.status = "expired"
                session.flush()
                return {"status": "expired", "asset_id": str(asset.id)}
            resolver = dns.resolver.Resolver()
            try:
                answer = resolver.resolve(challenge.record_name, "TXT", lifetime=5, search=False)
            except (dns.exception.DNSException, OSError) as exc:
                raise HTTPException(
                    409,
                    "The DNS TXT challenge was not found. Publish the record and try again.",
                ) from exc
            values = {
                b"".join(record.strings).decode("utf-8", errors="replace")
                for record in answer
            }
            matching = any(
                hmac.compare_digest(
                    hashlib.sha256(value.encode("utf-8")).hexdigest(),
                    challenge.token_hash,
                )
                for value in values
            )
            if not matching:
                raise HTTPException(409, "The DNS TXT record does not match this challenge.")
            challenge.status = "verified"
            challenge.verified_at = now
            asset.ownership_verified_at = now
            session.add(AuditEvent(
                organization_id=organization_id,
                actor_user_id=identity.id,
                action="asset.domain_verification.verified",
                resource_type="asset",
                resource_id=str(asset_id),
                details={"method": "dns_txt", "challenge_id": str(challenge.id)},
            ))
            session.flush()
            return {
                "status": "verified",
                "asset_id": str(asset.id),
                "domain": asset.canonical_value,
                "verified_at": now.isoformat(),
                "notice": "Ownership is verified. This does not authorize active security testing.",
            }

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
