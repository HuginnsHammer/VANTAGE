"""Strict OIDC access-token verification for the hosted VANTAGE API."""
from __future__ import annotations

import os
from typing import Any

import jwt
from jwt import PyJWKClient


class OIDCConfigurationError(RuntimeError):
    """Raised when required OIDC verification settings are absent."""


class OIDCTokenVerifier:
    """Verify RS256 JWT access tokens against a configured OIDC issuer/JWKS."""

    def __init__(self, issuer: str, audience: str, jwks_url: str) -> None:
        if not issuer or not audience or not jwks_url:
            raise OIDCConfigurationError(
                "VANTAGE_OIDC_ISSUER, VANTAGE_OIDC_AUDIENCE and "
                "VANTAGE_OIDC_JWKS_URL must all be configured"
            )
        self.issuer = issuer
        self.audience = audience
        self.jwks = PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300)

    @classmethod
    def from_environment(cls) -> OIDCTokenVerifier:
        return cls(
            os.environ.get("VANTAGE_OIDC_ISSUER", ""),
            os.environ.get("VANTAGE_OIDC_AUDIENCE", ""),
            os.environ.get("VANTAGE_OIDC_JWKS_URL", ""),
        )

    def __call__(self, token: str) -> dict[str, Any]:
        try:
            signing_key = self.jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
                leeway=30,
            )
        except Exception as exc:
            raise ValueError("The supplied access token is invalid.") from exc
        if not isinstance(claims.get("sub"), str) or not claims["sub"] or len(claims["sub"]) > 255:
            raise ValueError("The access token subject is invalid.")
        if not isinstance(claims.get("iss"), str) or len(claims["iss"]) > 500:
            raise ValueError("The access token issuer is invalid.")
        return claims
