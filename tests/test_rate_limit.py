from __future__ import annotations

import sqlite3
import time

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from gpo_lens.store import init_db
from gpo_lens.web.app import create_app
from gpo_lens.web.rate_limit import RateLimiter


@pytest.fixture()
def rate_db(tmp_path):
    db = tmp_path / "rate_test.db"
    conn = sqlite3.connect(str(db))
    init_db(conn)
    conn.close()
    return str(db)


@pytest.fixture()
def rate_client(rate_db: str, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
    app = create_app(rate_db)
    return TestClient(
        app,
        headers={
            "origin": "http://localhost",
            "Authorization": "Bearer test-secret-token",
        },
    )


class TestRateLimiter:
    def test_under_limit_succeeds(self) -> None:
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            allowed, _ = limiter.check("1.2.3.4")
            assert allowed

    def test_exceeding_limit_blocked(self) -> None:
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.check("1.2.3.4")
        limiter.check("1.2.3.4")
        allowed, retry_after = limiter.check("1.2.3.4")
        assert not allowed
        assert retry_after >= 1

    def test_different_ips_separate(self) -> None:
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        allowed, _ = limiter.check("1.1.1.1")
        assert allowed
        allowed, _ = limiter.check("2.2.2.2")
        assert allowed

    def test_window_slides(self) -> None:
        limiter = RateLimiter(max_requests=1, window_seconds=0.2)
        limiter.check("1.1.1.1")
        allowed, _ = limiter.check("1.1.1.1")
        assert not allowed
        time.sleep(0.5)
        allowed, _ = limiter.check("1.1.1.1")
        assert allowed

    def test_retry_after_within_window(self) -> None:
        limiter = RateLimiter(max_requests=1, window_seconds=10)
        limiter.check("1.1.1.1")
        _, retry_after = limiter.check("1.1.1.1")
        assert 1 <= retry_after <= 10

    def test_retry_after_decreases_over_time(self) -> None:
        limiter = RateLimiter(max_requests=1, window_seconds=5)
        limiter.check("1.1.1.1")
        _, first = limiter.check("1.1.1.1")
        time.sleep(0.1)
        _, second = limiter.check("1.1.1.1")
        assert second <= first

    def test_cleanup_evicts_stale(self) -> None:
        limiter = RateLimiter(max_requests=100, window_seconds=0.1)
        limiter.check("1.1.1.1")
        assert "1.1.1.1" in limiter._requests
        time.sleep(0.15)
        for _ in range(128):
            limiter.check("2.2.2.2")
        assert "1.1.1.1" not in limiter._requests


class TestRateLimitMiddleware:
    def test_request_under_limit_succeeds(self, rate_client: TestClient) -> None:
        resp = rate_client.get("/")
        assert resp.status_code == 200

    def test_exceeding_ask_limit_returns_429(self, rate_client: TestClient) -> None:
        for _ in range(10):
            rate_client.get("/ask")
        resp = rate_client.get("/ask")
        assert resp.status_code == 429

    def test_retry_after_header_on_429(self, rate_client: TestClient) -> None:
        for _ in range(10):
            rate_client.get("/ask")
        resp = rate_client.get("/ask")
        assert resp.status_code == 429
        assert "retry-after" in resp.headers
        assert int(resp.headers["retry-after"]) >= 1

    def test_healthz_not_rate_limited(self, rate_client: TestClient) -> None:
        for _ in range(15):
            resp = rate_client.get("/healthz")
            assert resp.status_code == 200

    def test_static_assets_not_rate_limited(self, rate_client: TestClient) -> None:
        for _ in range(15):
            resp = rate_client.get("/static/favicon.svg")
            assert resp.status_code == 200

    def test_ask_limit_separate_from_general(
        self, rate_client: TestClient
    ) -> None:
        for _ in range(10):
            rate_client.get("/ask")
        resp = rate_client.get("/")
        assert resp.status_code == 200

    def test_ingest_get_separate_from_ask_limit(
        self, rate_client: TestClient
    ) -> None:
        for _ in range(10):
            rate_client.get("/ask")
        resp = rate_client.get("/ingest")
        assert resp.status_code == 200

    def test_ingest_post_rate_limited(self, rate_client: TestClient) -> None:
        for _ in range(3):
            resp = rate_client.post(
                "/ingest",
                files={"file": ("bad.zip", b"not a zip", "application/zip")},
            )
            assert resp.status_code != 429
        resp = rate_client.post(
            "/ingest",
            files={"file": ("bad.zip", b"not a zip", "application/zip")},
        )
        assert resp.status_code == 429

    def test_ingest_post_limit_separate_from_ask(
        self, rate_client: TestClient
    ) -> None:
        for _ in range(10):
            rate_client.get("/ask")
        resp = rate_client.post(
            "/ingest",
            files={"file": ("bad.zip", b"not a zip", "application/zip")},
        )
        assert resp.status_code != 429

    def test_disable_via_env_var(
        self, rate_db: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GPO_LENS_AUTH_TOKEN", "test-secret-token")
        monkeypatch.setenv("GPO_LENS_DISABLE_RATE_LIMIT", "1")
        app = create_app(rate_db)
        client = TestClient(
            app,
            headers={
                "origin": "http://localhost",
                "Authorization": "Bearer test-secret-token",
            },
        )
        for _ in range(15):
            resp = client.get("/ask")
            assert resp.status_code == 200
