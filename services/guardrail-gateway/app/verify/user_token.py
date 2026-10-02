"""Proof that the person the agent acts for confirmed an action: their identity provider's token.

The host app (not the agent) shows the confirmation summary to the user and, if they approve,
sends the user's ID token (or access token) from your IdP to POST /v1/verifications/{id}/confirm.
The gateway accepts it only if:

- it is signed by the configured issuer (JWKS) and meant for the configured audience;
- `sub` (or the configured claim) equals the `user_id` the agent claimed for this request;
- the user authenticated recently (`auth_time`, else `iat`, within VERIFY_MAX_AUTH_AGE_SECONDS) -
  a stale session token is not a fresh "yes";
- `acr` is one of VERIFY_REQUIRED_ACR, when that is set (step-up / MFA);
- `nonce` equals the verification id (VERIFY_REQUIRE_NONCE, on by default): the host app gets the
  token from a fresh sign-in started for this one confirmation (OIDC `nonce=<verification id>`,
  usually with `prompt=login` or `max_age`).

The nonce is what makes "the agent can't confirm its own request" hold even when the agent can
see the user's ordinary access token (many apps pass it along so the agent can call APIs): that
token wasn't issued for this verification, so it is refused. With VERIFY_REQUIRE_NONCE=false, any
recent token of the user works, and confirmation from a key bound to the requesting agent is
refused instead; give the host app its own key.

Development only: VERIFY_DEV_SECRET accepts HS256 tokens minted with `python -m app.cli dev-user-token`.
It is refused in production at startup.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

JWKS_CACHE_SECONDS = 300
JWKS_MIN_REFETCH_SECONDS = 30


class TokenRejected(Exception):
    pass


def _signing_keys(jwks: Any) -> dict[str | None, Any]:
    """kid -> key for every usable signing key. Encryption keys (`use: enc`, e.g. Keycloak's
    RSA-OAEP key) and keys PyJWT can't load are skipped instead of failing the whole set."""
    out: dict[str | None, Any] = {}
    for k in (jwks or {}).get("keys", []) if isinstance(jwks, dict) else []:
        if not isinstance(k, dict) or k.get("use", "sig") != "sig":
            continue
        try:
            out[k.get("kid")] = jwt.PyJWK(k).key
        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
            continue
    return out


@dataclass(frozen=True)
class UserTokenConfig:
    issuer: str | None = None
    audience: str | None = None
    jwks_url: str | None = None
    jwks_json: str | None = None  # static JWKS (air-gapped installs, tests)
    user_claim: str = "sub"
    max_auth_age_seconds: int = 600
    required_acr: tuple[str, ...] = ()
    dev_secret: str | None = None
    require_nonce: bool = True

    @property
    def enabled(self) -> bool:
        return bool(self.dev_secret or (self.issuer and self.audience and (self.jwks_url or self.jwks_json)))


class UserTokenVerifier:
    def __init__(self, cfg: UserTokenConfig, http: httpx.AsyncClient | None = None, clock: Any = time.time) -> None:
        self.cfg = cfg
        self._http = http
        self._now = clock
        self._keys: dict[str | None, Any] = {}
        self._keys_at = 0.0
        self._fetched_at = -1e9

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled

    async def _key_for(self, kid: str | None) -> Any:
        if self.cfg.jwks_json:
            keys = _signing_keys(json.loads(self.cfg.jwks_json))
        else:
            now = self._now()
            stale = now - self._keys_at > JWKS_CACHE_SECONDS
            # An unknown kid may mean the IdP rotated keys. Either way, fetch at most every
            # JWKS_MIN_REFETCH_SECONDS, so made-up kids or an IdP outage can't make us hammer it.
            due = now - self._fetched_at > JWKS_MIN_REFETCH_SECONDS
            if (stale or kid not in self._keys) and due and self._http is not None and self.cfg.jwks_url:
                self._fetched_at = now
                try:
                    resp = await self._http.get(self.cfg.jwks_url, timeout=3.0)
                    resp.raise_for_status()
                    fresh = _signing_keys(resp.json())
                except (httpx.HTTPError, ValueError):
                    fresh = {}
                if fresh:  # a failed or empty fetch keeps the cached keys (signatures still checked)
                    self._keys, self._keys_at = fresh, now
            keys = self._keys
        if kid in keys:
            return keys[kid]
        if len(keys) == 1 and kid is None:
            return next(iter(keys.values()))
        raise TokenRejected("signing key not found in the identity provider's JWKS")

    async def verify(self, token: str, expected_user: str, expected_nonce: str | None = None) -> dict[str, Any]:
        if not self.enabled:
            raise TokenRejected("user confirmation is not configured on this gateway")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenRejected("malformed token") from exc
        try:
            if self.cfg.dev_secret and header.get("alg") == "HS256":
                claims = jwt.decode(
                    token, self.cfg.dev_secret, algorithms=["HS256"], audience=self.cfg.audience or "guardrail-dev",
                    options={"require": ["exp", "iat", "sub"]},
                )  # fmt: skip
            else:
                if header.get("alg") not in ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256"):
                    raise TokenRejected(f"algorithm {header.get('alg')!r} is not accepted")
                key = await self._key_for(header.get("kid"))
                claims = jwt.decode(
                    token, key, algorithms=[header["alg"]], audience=self.cfg.audience, issuer=self.cfg.issuer,
                    options={"require": ["exp", "iat", "sub"]},
                )  # fmt: skip
        except TokenRejected:
            raise
        except (jwt.PyJWTError, httpx.HTTPError, ValueError) as exc:
            raise TokenRejected(f"token rejected: {exc.__class__.__name__}") from exc
        user = str(claims.get(self.cfg.user_claim) or "")
        if not expected_user or user != expected_user:
            raise TokenRejected("token belongs to a different user than the one the agent acts for")
        authenticated_at = float(claims.get("auth_time") or claims.get("iat") or 0)
        if self._now() - authenticated_at > self.cfg.max_auth_age_seconds:
            raise TokenRejected("the user must sign in again (authentication is too old for a confirmation)")
        if self.cfg.required_acr and str(claims.get("acr") or "") not in self.cfg.required_acr:
            raise TokenRejected("a stronger sign-in (acr) is required for this confirmation")
        if self.cfg.require_nonce and (not expected_nonce or claims.get("nonce") != expected_nonce):
            raise TokenRejected("the token was not issued for this confirmation (nonce must be the verification id)")
        return claims


def mint_dev_token(
    secret: str, user: str, *, nonce: str | None = None, audience: str = "guardrail-dev", ttl: int = 300
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": user, "aud": audience, "iat": now, "auth_time": now, "exp": now + ttl, "iss": "guardrail-dev",
    }  # fmt: skip
    if nonce is not None:
        claims["nonce"] = nonce
    return jwt.encode(claims, secret, algorithm="HS256")
