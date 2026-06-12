"""Tests for event sinks (NDJSON file and Splunk HEC)."""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch

from gpo_lens.events import append_events, init_events_table, query_events
from gpo_lens.sinks import HecSink, NdjsonSink, emit_events


class TestNdjsonSink:
    def test_writes_valid_ndjson(self, tmp_path: Path) -> None:
        path = tmp_path / "events.ndjson"
        with NdjsonSink(str(path)) as sink:
            sink.write({"type": "test", "id": 1})
            sink.write({"type": "test", "id": 2})

        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"id": 1, "type": "test"}
        assert json.loads(lines[1]) == {"id": 2, "type": "test"}

    def test_appends_on_subsequent_writes(self, tmp_path: Path) -> None:
        path = tmp_path / "events.ndjson"
        with NdjsonSink(str(path)) as sink:
            sink.write({"batch": 1})

        with NdjsonSink(str(path)) as sink2:
            sink2.write({"batch": 2})

        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"batch": 1}
        assert json.loads(lines[1]) == {"batch": 2}

    def test_context_manager(self, tmp_path: Path) -> None:
        path = tmp_path / "events.ndjson"
        with NdjsonSink(str(path)) as sink:
            sink.write({"key": "value"})
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1
        assert json.loads(lines[0]) == {"key": "value"}

    def test_write_batch(self, tmp_path: Path) -> None:
        path = tmp_path / "events.ndjson"
        with NdjsonSink(str(path)) as sink:
            sink.write_batch([{"a": 1}, {"b": 2}])
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"a": 1}
        assert json.loads(lines[1]) == {"b": 2}

    def test_thread_safety(self, tmp_path: Path) -> None:
        path = tmp_path / "events.ndjson"
        with NdjsonSink(str(path)) as sink:

            def worker(n: int) -> None:
                for i in range(10):
                    sink.write({"worker": n, "i": i})

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 50
        for line in lines:
            assert "worker" in json.loads(line)


class _StubHandler(BaseHTTPRequestHandler):
    def __init__(self, response_code: int = 200, *args: Any, **kwargs: Any):
        self.response_code = response_code
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(content_length)
        self.send_response(self.response_code)
        self.end_headers()


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestHecSink:
    def test_success_returns_true(self) -> None:
        port = _get_free_port()
        server = HTTPServer(("127.0.0.1", port), _make_handler(200))
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            sink = HecSink(f"http://127.0.0.1:{port}", "test-token")
            result = sink.send({"test": "event"})
            assert result is True
        finally:
            server.shutdown()

    def test_4xx_returns_false_no_raise(self) -> None:
        port = _get_free_port()
        server = HTTPServer(("127.0.0.1", port), _make_handler(403))
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            sink = HecSink(f"http://127.0.0.1:{port}", "test-token")
            result = sink.send({"test": "event"})
            assert result is False
        finally:
            server.shutdown()

    def test_timeout_returns_false_no_raise(self) -> None:
        port = _get_free_port()
        sink = HecSink(f"http://127.0.0.1:{port}", "test-token", timeout=1)
        result = sink.send({"test": "event"})
        assert result is False

    def test_send_batch(self) -> None:
        port = _get_free_port()
        server = HTTPServer(("127.0.0.1", port), _make_handler(200))
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            sink = HecSink(f"http://127.0.0.1:{port}", "test-token")
            result = sink.send_batch([{"a": 1}, {"b": 2}])
            assert result is True
        finally:
            server.shutdown()

    def test_from_env_none_when_not_set(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            assert HecSink.from_env() is None

    def test_from_env_returns_sink_when_set(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GPO_LENS_HEC_URL": "http://splunk.test:8088",
                "GPO_LENS_HEC_TOKEN": "tok-123",
            },
        ):
            sink = HecSink.from_env()
            assert sink is not None
            assert sink.url == "http://splunk.test:8088"
            assert sink.token == "tok-123"
            assert sink.verify_tls is True

    def test_from_env_respects_verify_tls_false(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GPO_LENS_HEC_URL": "http://splunk.test:8088",
                "GPO_LENS_HEC_TOKEN": "tok-123",
                "GPO_LENS_HEC_VERIFY_TLS": "false",
            },
        ):
            sink = HecSink.from_env()
            assert sink is not None
            assert sink.verify_tls is False

    def test_hec_payload_contains_sourcetype(self) -> None:
        received: list[dict[str, Any]] = []

        class CaptureHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                received.append(body)
                self.send_response(200)
                self.end_headers()

        port = _get_free_port()
        server = HTTPServer(("127.0.0.1", port), CaptureHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            sink = HecSink(f"http://127.0.0.1:{port}", "test-token")
            sink.send({"key": "value"})
            assert len(received) == 1
            assert received[0]["sourcetype"] == "gpo_lens:change"
            assert received[0]["event"] == {"key": "value"}
        finally:
            server.shutdown()

    def test_hec_includes_auth_header(self) -> None:
        received_headers: dict[str, str | None] = {}

        class HeaderHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                nonlocal received_headers
                received_headers = dict(self.headers.items())
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self.send_response(200)
                self.end_headers()

        port = _get_free_port()
        server = HTTPServer(("127.0.0.1", port), HeaderHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            sink = HecSink(f"http://127.0.0.1:{port}", "test-token")
            sink.send({"key": "value"})
            auth = received_headers.get("Authorization", "")
            assert auth == "Splunk test-token"
        finally:
            server.shutdown()


def _make_handler(code: int):
    def handler(*args: Any, **kwargs: Any):
        return _StubHandler(code, *args, **kwargs)
    return handler


class TestEmitEvents:
    def test_emit_to_ndjson_only(self, tmp_path: Path) -> None:
        ndjson_path = tmp_path / "out.ndjson"
        results = emit_events(
            [{"a": 1}, {"b": 2}],
            ndjson_path=str(ndjson_path),
        )
        assert results == {"ndjson": True, "hec": False}
        lines = ndjson_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2

    def test_emit_to_both_sinks_one_fails(self, tmp_path: Path, capsys) -> None:
        ndjson_path = tmp_path / "out.ndjson"
        hec_sink = HecSink("http://127.0.0.1:1", "token", timeout=1)
        results = emit_events(
            [{"a": 1}],
            ndjson_path=str(ndjson_path),
            hec_sink=hec_sink,
        )
        assert results["ndjson"] is True
        assert results["hec"] is False
        captured = capsys.readouterr()
        assert "Warning" in captured.err or "" == captured.err

    def test_emit_continues_on_sink_failure(self, tmp_path: Path, capsys) -> None:
        ndjson_path = tmp_path / "out.ndjson"
        port = _get_free_port()
        server = HTTPServer(("127.0.0.1", port), _make_handler(200))
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            bad_hec = HecSink(f"http://127.0.0.1:{port}", "token")
            with patch.object(bad_hec, "send_batch", side_effect=RuntimeError("splunk down")):
                results = emit_events(
                    [{"a": 1}],
                    ndjson_path=str(ndjson_path),
                    hec_sink=bad_hec,
                )
                assert results["ndjson"] is True
                assert results["hec"] is False
                assert "Warning" in capsys.readouterr().err
        finally:
            server.shutdown()


class TestReplay:
    def test_replay_after_simulated_outage(self, tmp_path: Path) -> None:
        db_path = tmp_path / "events.db"
        conn = sqlite3.connect(str(db_path))
        init_events_table(conn)

        events = [
            ("ingest", {"domain": "test.local", "gpos": 5}),
            ("change", {"gpo_id": "aaa", "type": "added"}),
            ("change", {"gpo_id": "bbb", "type": "modified"}),
        ]
        append_events(conn, events)
        conn.close()

        ndjson_path = tmp_path / "replay.ndjson"
        conn = sqlite3.connect(str(db_path))
        stored = query_events(conn, limit=1000)
        conn.close()

        result = emit_events(stored, ndjson_path=str(ndjson_path))
        assert result["ndjson"] is True

        lines = ndjson_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3
        parsed = [json.loads(line) for line in lines]
        event_types = [e["event_type"] for e in parsed]
        assert event_types == ["ingest", "change", "change"]

        stored_ids = [e["id"] for e in stored]
        parsed_ids = [e["id"] for e in parsed]
        assert parsed_ids == stored_ids
