"""Runs the real Presidio engines (needs requirements.txt + en_core_web_lg). Project-service and
the API-key table are replaced with fakes, so no database or network is needed."""
import os
import sys
from pathlib import Path

os.environ.setdefault("POSTGRES_DSN", "postgresql+asyncpg://unused:unused@localhost:5432/unused")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx  # noqa: E402
import pytest  # noqa: E402

from auth.api_key_repository import ValidatedApiKey  # noqa: E402
from dependencies import get_redaction_service, require_api_key  # noqa: E402
from main import create_app  # noqa: E402
from services.redaction_service import RedactionService, warmup_engines  # noqa: E402

PROJECTS = {
    "11111111-1111-1111-1111-111111111111": {
        "id": "11111111-1111-1111-1111-111111111111",
        "entities": ["EMAIL_ADDRESS", "PERSON", "PHONE_NUMBER", "US_SSN"],
        "customized": [{"regex": r"EMP-\d{6}", "redaction": "[EMPLOYEE_ID]"}],
        "redaction_type": "replace",
    },
    "22222222-2222-2222-2222-222222222222": {
        "id": "22222222-2222-2222-2222-222222222222",
        "entities": ["EMAIL_ADDRESS"],
        "customized": [{"regex": r"ORD-\d{4}", "redaction": "[ORDER_ID]"}],
        "redaction_type": "replace",
    },
}
PROJECTS.update(
    {
        pid: {"id": pid, "entities": ["EMAIL_ADDRESS"], "customized": [], "redaction_type": "hash"}
        for pid in ("44444444-4444-4444-4444-444444444444", "55555555-5555-5555-5555-555555555555")
    }
)
P1, P2, H1, H2 = list(PROJECTS)


class FakeProjectClient:
    def __init__(self):
        self.calls = 0

    async def get_project(self, project_id):
        self.calls += 1
        from fastapi import HTTPException

        if project_id not in PROJECTS:
            raise HTTPException(status_code=404, detail=f"Project {project_id} not found")
        return PROJECTS[project_id]

    async def is_healthy(self):
        return True


@pytest.fixture(scope="session")
def app():
    warmup_engines()  # the lifespan (which normally does this) is not run by ASGITransport
    application = create_app()
    fake = FakeProjectClient()
    application.dependency_overrides[require_api_key] = lambda: ValidatedApiKey(id="k", name="test")
    application.dependency_overrides[get_redaction_service] = lambda: RedactionService(project_service=fake)
    return application


@pytest.fixture
async def client(app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c
