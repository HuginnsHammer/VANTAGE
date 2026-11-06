from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from vantage.auth.oidc import OIDCConfigurationError, OIDCTokenVerifier


def test_oidc_verifier_requires_explicit_configuration():
    with pytest.raises(OIDCConfigurationError):
        OIDCTokenVerifier("", "vantage-api", "https://issuer.example/jwks")


def test_oidc_verifier_checks_signature_issuer_audience_and_expiry(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = OIDCTokenVerifier(
        "https://issuer.example",
        "vantage-api",
        "https://issuer.example/.well-known/jwks.json",
    )
    monkeypatch.setattr(
        verifier.jwks,
        "get_signing_key_from_jwt",
        lambda token: SimpleNamespace(key=private_key.public_key()),
    )
    now = datetime.now(UTC)
    claims = {
        "iss": "https://issuer.example",
        "sub": "subject-123",
        "aud": "vantage-api",
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test"})
    assert verifier(token)["sub"] == "subject-123"

    wrong_audience = jwt.encode(
        {**claims, "aud": "another-api"},
        private_key,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    with pytest.raises(ValueError, match="invalid"):
        verifier(wrong_audience)

    expired = jwt.encode(
        {**claims, "exp": now - timedelta(minutes=5)},
        private_key,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    with pytest.raises(ValueError, match="invalid"):
        verifier(expired)
