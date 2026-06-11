"""End-to-end test: simulate a full crack session against the API."""

import tempfile
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from hydra.api.main import app
from hydra.api.metrics import setup_metrics
from hydra.engines.base import Engine, EngineCapabilities, EngineResult
from hydra.knowledge.database import Database
from hydra.knowledge.repository import KnowledgeRepository
from hydra.models.base import HashType
from hydra.plugins.loader import PluginLoader


class E2EFakeEngine(Engine):
    name = "hashcat"
    def _default_binary(self) -> str:
        return "hashcat"
    async def detect(self) -> EngineCapabilities:
        return EngineCapabilities(
            name="hashcat", version="e2e",
            supported_hash_modes=[0], supported_attack_modes=[],
            max_wordlist_size=0, supports_rules=True, supports_mask=True,
            supports_opencl=False, supports_cuda=False,
            supports_distribution=False, max_devices=0,
        )
    async def identify_hashes(self, hashes: list[str]) -> list[tuple[str, HashType]]:
        return [(h, HashType.MD5) for h in hashes]
    async def run(self, **kwargs) -> EngineResult:
        return EngineResult(
            cracked={"5d41402abc4b2a76b9719d911017c592": "hello"},
            speed=1_000_000.0, progress=1.0, duration=0.5,
            command=["hashcat"], exit_code=0,
        )


@pytest.fixture
def client():
    db_path = Path(tempfile.mktemp(suffix=".db"))
    db = Database(f"sqlite:///{db_path}")
    kb = KnowledgeRepository(db)
    app.state.db = db
    app.state.kb = kb
    app.state.engines = {"hashcat": E2EFakeEngine()}
    app.state.worker_manager = None
    app.state.chunk_manager = None
    app.state.plugins = PluginLoader("/nonexistent")
    setup_metrics(app)
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_root(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "HYDRA"


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_engines(client):
    resp = await client.get("/engines")
    assert resp.status_code == 200
    assert "hashcat" in resp.json()["engines"]


@pytest.mark.asyncio
async def test_crack_endpoint(client):
    resp = await client.post("/crack", json={
        "hashes": ["5d41402abc4b2a76b9719d911017c592"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["cracked"] >= 1
    assert data["hash_type"] == "MD5"
    assert "session_id" in data


@pytest.mark.asyncio
async def test_crack_unknown_hash_type(client):
    async def unknown_identify(hashes):
        return [(hashes[0], HashType.UNKNOWN)]
    app.state.engines["hashcat"].identify_hashes = unknown_identify
    resp = await client.post("/crack", json={
        "hashes": ["invalid"],
    })
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_crack_no_engines(client):
    app.state.engines = {}
    resp = await client.post("/crack", json={
        "hashes": ["5d41402abc4b2a76b9719d911017c592"],
    })
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_metrics_endpoint(client):
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    assert "hydra_requests_total" in resp.text
