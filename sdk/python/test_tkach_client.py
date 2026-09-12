"""Adversarial and contract tests for the stdlib-only Python adapter."""

from __future__ import annotations

import socketserver
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from tkach_client import (
    MAX_HTTP_BODY_BYTES,
    MAX_RUNTIME_RESPONSE_BYTES,
    ClientResponse,
    ErrorCode,
    TkachClient,
    TkachClientError,
)


class _JsonHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    requests: list[tuple[str, str, dict[str, str], bytes]] = []
    status = 200
    response_body = b'{"status":"ok"}'

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _respond(self) -> None:
        self.close_connection = True
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.response_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(self.response_body)

    def do_GET(self) -> None:
        self.requests.append(("GET", self.path, dict(self.headers.items()), b""))
        self._respond()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.requests.append(("POST", self.path, dict(self.headers.items()), body))
        self._respond()


class _RawHandler(socketserver.BaseRequestHandler):
    response = b""
    delay = 0.0

    def handle(self) -> None:
        self.request.settimeout(1.0)
        received = bytearray()
        while b"\r\n\r\n" not in received:
            chunk = self.request.recv(1024)
            if not chunk:
                break
            received.extend(chunk)
        time.sleep(self.delay)
        self.request.sendall(self.response)


class PythonClientTests(unittest.TestCase):
    def setUp(self) -> None:
        _JsonHandler.requests = []
        _JsonHandler.status = 200
        _JsonHandler.response_body = b'{"status":"ok"}'

    def _json_server(self) -> tuple[HTTPServer, threading.Thread]:
        server = HTTPServer(("127.0.0.1", 0), _JsonHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, thread

    def _raw_server(self, response: bytes) -> tuple[socketserver.TCPServer, threading.Thread]:
        handler = type("ConfiguredRawHandler", (_RawHandler,), {"response": response})
        server = socketserver.TCPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, thread

    def test_configuration_is_loopback_only_and_repr_redacts_token(self) -> None:
        for host in ("localhost", "0.0.0.0", "192.0.2.1"):
            with self.subTest(host=host):
                with self.assertRaisesRegex(TkachClientError, ErrorCode.NON_LOOPBACK_ADDRESS.value):
                    TkachClient(host, 8080, "secret")
        with self.assertRaisesRegex(TkachClientError, ErrorCode.INVALID_AUTHENTICATION.value):
            TkachClient("127.0.0.1", 8080, "bad token")
        client = TkachClient("127.0.0.1", 8080, "secret-token")
        self.addCleanup(client.close)
        self.assertNotIn("secret-token", repr(client))
        for timeout in (0, -1, 120.1, float("inf"), True):
            with self.subTest(timeout=timeout):
                with self.assertRaisesRegex(TkachClientError, ErrorCode.INVALID_REQUEST.value):
                    TkachClient("127.0.0.1", 8080, "secret", timeout=timeout)

    def test_health_requires_exact_static_response(self) -> None:
        server, _thread = self._json_server()
        client = TkachClient("127.0.0.1", server.server_port, "secret-token")
        self.addCleanup(client.close)
        client.health()
        self.assertEqual(_JsonHandler.requests[0][0:2], ("GET", "/healthz"))
        self.assertNotIn("Authorization", _JsonHandler.requests[0][2])

        _JsonHandler.response_body = b'{"status":"not-ok"}'
        with self.assertRaisesRegex(
            TkachClientError, ErrorCode.UNEXPECTED_HEALTH_RESPONSE.value
        ):
            client.health()

    def test_run_sends_one_bounded_json_request_and_returns_observation(self) -> None:
        server, _thread = self._json_server()
        _JsonHandler.response_body = b'{"Success":{"output":"bounded response"}}'
        client = TkachClient("127.0.0.1", server.server_port, "secret-token")
        self.addCleanup(client.close)
        response = client.run(
            "request-1",
            "lifecycle-1",
            {"messages": [{"role": "user", "content": "hello"}]},
        )
        self.assertEqual(response, ClientResponse(200, _JsonHandler.response_body))
        method, path, headers, body = _JsonHandler.requests[0]
        self.assertEqual((method, path), ("POST", "/v1/run"))
        self.assertEqual(headers["Authorization"], "Bearer secret-token")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertIn(b'"request_id":"request-1"', body)
        self.assertNotIn("secret-token", repr(response))

    def test_run_accepts_a_bounded_slow_response_without_retry(self) -> None:
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: 2\r\nConnection: close\r\n\r\n{}"
        )
        handler = type("DelayedRawHandler", (_RawHandler,), {"response": response, "delay": 0.8})
        server = socketserver.TCPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        client = TkachClient("127.0.0.1", server.server_address[1], "secret-token")
        self.addCleanup(client.close)
        result = client.run("slow-request", "slow-lifecycle", {"messages": []})
        self.assertEqual(result.status_code, 200)

        short_client = TkachClient(
            "127.0.0.1", server.server_address[1], "secret-token", timeout=0.1
        )
        self.addCleanup(short_client.close)
        with self.assertRaisesRegex(TkachClientError, ErrorCode.IO.value):
            short_client.run("short-request", "short-lifecycle", {"messages": []})

    def test_invalid_response_fails_closed_without_retry(self) -> None:
        raw = (
            b"HTTP/1.1 401 Unauthorized\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 2\r\n"
            b"Connection: close\r\n\r\n{}"
        )
        server, _thread = self._raw_server(raw)
        client = TkachClient("127.0.0.1", server.server_address[1], "secret-token")
        self.addCleanup(client.close)
        response = client.run("request-1", "lifecycle-1", {"messages": []})
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.is_success)

        chunked = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        server, _thread = self._raw_server(chunked)
        client = TkachClient("127.0.0.1", server.server_address[1], "secret-token")
        self.addCleanup(client.close)
        with self.assertRaisesRegex(TkachClientError, ErrorCode.INVALID_RESPONSE.value):
            client.health()

        duplicate_length = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: 2\r\nContent-Length: 2\r\n"
            b"Connection: close\r\n\r\n{}"
        )
        server, _thread = self._raw_server(duplicate_length)
        client = TkachClient("127.0.0.1", server.server_address[1], "secret-token")
        self.addCleanup(client.close)
        with self.assertRaisesRegex(TkachClientError, ErrorCode.INVALID_RESPONSE.value):
            client.health()

    def test_oversized_response_and_request_are_bounded(self) -> None:
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {MAX_RUNTIME_RESPONSE_BYTES + 1}\r\n".encode()
            + b"Connection: close\r\n\r\n"
        )
        server, _thread = self._raw_server(raw)
        client = TkachClient("127.0.0.1", server.server_address[1], "secret-token")
        self.addCleanup(client.close)
        with self.assertRaisesRegex(TkachClientError, ErrorCode.RESPONSE_TOO_LARGE.value):
            client.health()

        raw_headers = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + b"X-Padding: "
            + b"x" * 20_000
            + b"\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
        )
        server, _thread = self._raw_server(raw_headers)
        client = TkachClient("127.0.0.1", server.server_address[1], "secret-token")
        self.addCleanup(client.close)
        with self.assertRaisesRegex(TkachClientError, ErrorCode.RESPONSE_TOO_LARGE.value):
            client.health()

        with self.assertRaisesRegex(TkachClientError, ErrorCode.INVALID_REQUEST.value):
            client.run("request-1", "lifecycle-1", {"payload": "x" * MAX_HTTP_BODY_BYTES})

    def test_close_wipes_owned_token_and_rejects_future_calls(self) -> None:
        client = TkachClient("127.0.0.1", 8080, "secret-token")
        client.close()
        self.assertTrue(client._bearer_token)
        self.assertTrue(all(byte == 0 for byte in client._bearer_token))
        with self.assertRaisesRegex(TkachClientError, ErrorCode.CLOSED.value):
            client.health()


if __name__ == "__main__":
    unittest.main()
