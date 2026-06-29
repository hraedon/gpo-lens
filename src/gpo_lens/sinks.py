"""Event sinks for NDJSON file and Splunk HEC (stdlib-only)."""

from __future__ import annotations

import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from typing import Any


class NdjsonSink:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._closed = False
        self._fh: Any = None

    def write(self, event: dict[str, Any]) -> None:
        if self._closed:
            return
        if self._fh is None:
            raise RuntimeError(
                "NdjsonSink.write() called outside context manager; use 'with' block"
            )
        line = json.dumps(event, sort_keys=True)
        with self._lock:
            if self._closed or self._fh is None:
                return
            self._fh.write(line + "\n")
            self._fh.flush()

    def write_batch(self, events: list[dict[str, Any]]) -> None:
        if self._closed:
            return
        if self._fh is None:
            raise RuntimeError(
                "NdjsonSink.write_batch() called outside context manager; use 'with' block"
            )
        with self._lock:
            if self._closed or self._fh is None:
                return
            for event in events:
                self._fh.write(json.dumps(event, sort_keys=True) + "\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._fh is not None:
                self._fh.close()

    def __enter__(self) -> NdjsonSink:
        with self._lock:
            if self._fh is not None and not self._closed:
                self._fh.close()
            self._closed = False
            self._fh = open(self.path, "a", encoding="utf-8", newline="\n")
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class HecSink:
    def __init__(
        self,
        url: str,
        token: str,
        *,
        verify_tls: bool = True,
        timeout: int = 30,
    ) -> None:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            raise ValueError("HEC URL must include http:// or https:// scheme")
        if parsed.scheme not in ("https", "http"):
            raise ValueError(f"HEC URL must be http(s)://, got {parsed.scheme}://")
        if parsed.scheme == "http":
            warnings.warn(
                f"HEC URL {parsed.netloc} is http:// — the Splunk token "
                "will be sent in plaintext. Use https:// for production.",
                stacklevel=2,
            )
        self.url = url.rstrip("/")
        self.token = token
        self.verify_tls = verify_tls
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> HecSink | None:
        hec_url = os.environ.get("GPO_LENS_HEC_URL")
        hec_token = os.environ.get("GPO_LENS_HEC_TOKEN")
        if not hec_url or not hec_token:
            return None
        verify = os.environ.get("GPO_LENS_HEC_VERIFY_TLS", "true").lower() != "false"
        try:
            return cls(url=hec_url, token=hec_token, verify_tls=verify)
        except ValueError as exc:
            warnings.warn(f"Invalid HEC URL configuration: {exc}", stacklevel=2)
            return None

    def _post(self, payload: str, max_retries: int = 3) -> bool:
        endpoint = f"{self.url}/services/collector/event"
        data = payload.encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        if not self.verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = None
        kwargs: dict[str, Any] = {"timeout": self.timeout}
        if ctx is not None:
            kwargs["context"] = ctx
        for attempt in range(max_retries):
            try:
                with urllib.request.urlopen(req, **kwargs) as resp:
                    code: int = resp.getcode()
                    return code == 200
            except urllib.error.HTTPError as exc:
                print(f"Warning: HEC returned HTTP {exc.code}", file=sys.stderr)
                return False
            except OSError as exc:
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                print(f"Warning: HEC transport error: {exc}", file=sys.stderr)
                return False
        return False

    def send(self, event: dict[str, Any]) -> bool:
        payload = json.dumps({"event": event, "sourcetype": "gpo_lens:change"})
        return self._post(payload)

    def send_batch(self, events: list[dict[str, Any]]) -> bool:
        if not events:
            return True
        payload = "\n".join(
            json.dumps({"event": e, "sourcetype": "gpo_lens:change"}) for e in events
        )
        return self._post(payload)


def emit_events(
    events: list[dict[str, Any]],
    *,
    ndjson_path: str | None = None,
    hec_sink: HecSink | None = None,
) -> dict[str, bool]:
    results: dict[str, bool] = {"ndjson": False, "hec": False}
    if ndjson_path:
        try:
            with NdjsonSink(ndjson_path) as sink:
                sink.write_batch(events)
            results["ndjson"] = True
        except Exception as exc:
            print(f"Warning: NDJSON sink failed: {exc}", file=sys.stderr)
            results["ndjson"] = False
    if hec_sink:
        try:
            results["hec"] = hec_sink.send_batch(events)
        except Exception as exc:
            print(f"Warning: HEC sink failed: {exc}", file=sys.stderr)
            results["hec"] = False
    return results
