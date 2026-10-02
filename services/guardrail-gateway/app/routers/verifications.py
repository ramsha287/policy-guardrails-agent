"""User confirmation for outcome "verify" (HTTP 202 with a `verification` object).

GET  /v1/verifications/{id}            status: pending | confirmed | rejected | expired
POST /v1/verifications/{id}/confirm    {"approve": true|false}
     X-API-Key: <any key of the same tenant>
     Authorization: Bearer <the user's token from your identity provider>

The host app shows `verification.summary` to the user, signs them in again for this confirmation
(OIDC `nonce` = the verification id) and sends the resulting token. The token must belong to the
`user_id` the agent claimed, be recent (VERIFY_MAX_AUTH_AGE_SECONDS) and carry that nonce, so the
agent can't confirm its own request even if it can see the user's everyday access token. After a
confirmation the agent retries the identical request; the evidence is bound to it and used once.
"""

from __future__ import annotations

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from app.gateway.auth import Principal
from app.services import Services
from app.verify.engine import VerificationClosed, VerificationEngine, VerificationNotFound
from app.verify.model import Verification
from app.verify.user_token import TokenRejected
from guardrail_sdk import VerificationInfo

router = APIRouter(tags=["guard"])


class ConfirmBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approve: bool


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message})


def _info(v: Verification) -> dict[str, object]:
    return VerificationInfo(
        id=v.id, kind=v.kind, status=v.status, expires_at=v.expires_at, summary=v.summary, user_id=v.user_id
    ).model_dump(mode="json")


async def _engine(request: Request, x_api_key: str | None) -> tuple[Principal, VerificationEngine] | JSONResponse:
    svc: Services = request.app.state.services
    principal = await svc.auth.authenticate(x_api_key)
    if principal is None:
        return _error(401, "Missing, invalid or revoked API key")
    engine = svc.contextual.verifier if svc.contextual is not None else None
    if engine is None:
        return _error(404, "verification is not enabled on this gateway")
    return principal, engine


@router.get("/v1/verifications/{verification_id}", response_model=VerificationInfo)
async def verification_status(
    verification_id: str, request: Request, x_api_key: str | None = Header(default=None, alias="X-API-Key")
) -> JSONResponse:
    got = await _engine(request, x_api_key)
    if isinstance(got, JSONResponse):
        return got
    principal, engine = got
    v = await engine.store.get_verification(principal.tenant_id, verification_id)
    if v is None:
        return _error(404, f"verification {verification_id} not found")
    return JSONResponse(content=_info(v))


@router.post("/v1/verifications/{verification_id}/confirm", response_model=VerificationInfo)
async def confirm_verification(
    verification_id: str,
    body: ConfirmBody,
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    got = await _engine(request, x_api_key)
    if isinstance(got, JSONResponse):
        return got
    principal, engine = got
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return _error(401, "send the user's token from your identity provider as 'Authorization: Bearer <token>'")
    try:
        v = await engine.confirm(
            principal.tenant_id,
            verification_id,
            user_token=token.strip(),
            approve=body.approve,
            caller_agent_id=principal.agent_id,
        )
    except VerificationNotFound as exc:
        return _error(404, str(exc))
    except VerificationClosed as exc:
        return _error(409, str(exc))
    except TokenRejected as exc:
        return _error(403, str(exc))
    return JSONResponse(content=_info(v))
