# Tkach Security
#
# Copyright 2026 ECD5A
# Licensed under the Apache License, Version 2.0.
#
# Repository: https://github.com/ECD5A/Tkach-Security
#
# See LICENSE and SECURITY.md.

"""Thin, bounded Python client for the Tkach loopback HTTP contract.

This module deliberately contains transport checks only. It does not implement
Krosna, Zaslon, Ruslo, Propusk, provider orchestration, retries, or authority.
The Rust runtime remains the security boundary; this client only carries a
request to that boundary and returns bounded transport observations.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any


# These values mirror the published v0.1 Rust transport contract. A future
# incompatible wire contract must publish a new SDK contract instead of
# silently widening these limits.
MAX_HTTP_BODY_BYTES = 64 * 1024 - 256 - 256
MAX_HTTP_HEADER_BYTES = 16 * 1024
MAX_RUNTIME_AUTH_BYTES = 256
MAX_RUNTIME_ID_BYTES = 128
MAX_RUNTIME_RESPONSE_BYTES = 128 * 1024
# Keep this above the Rust provider's 30-second default while remaining finite.
HTTP_TIMEOUT_SECONDS = 35.0
MAX_HTTP_TIMEOUT_SECONDS = 120.0

_ID_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
_AUTH_BYTES = _ID_BYTES


class ErrorCode(str, Enum):
    """Stable, payload-free client failure categories."""

    CLOSED = "client_closed"
    INVALID_AUTHENTICATION = "invalid_authentication"
    INVALID_REQUEST = "invalid_request"
    INVALID_RESPONSE = "invalid_response"
    IO = "io_failure"
    NON_LOOPBACK_ADDRESS = "non_loopback_address"
    RESPONSE_TOO_LARGE = "response_too_large"
    UNEXPECTED_HEALTH_RESPONSE = "unexpected_health_response"
    UNEXPECTED_READINESS_RESPONSE = "unexpected_readiness_response"


class TkachClientError(Exception):
    """A static client error that never includes request or token material."""

    def __init__(self, code: ErrorCode):
        self.code = code
        super().__init__(code.value)

    def __repr__(self) -> str:
        return f"TkachClientError({self.code.value!r})"


@dataclass(frozen=True, slots=True)
class ClientResponse:
    """A bounded HTTP observation; the body has no policy meaning by itself."""

    status_code: int
    body: bytes

    @property
    def is_success(self) -> bool:
        """Return whether the peer returned a 2xx status."""

        return 200 <= self.status_code < 300


class TkachClient:
    """Loopback-only client for the published Tkach HTTP adapter.

    ``host`` must be a numeric loopback address. DNS names are rejected so a
    later resolver result cannot silently move the client outside the reviewed
    local boundary. Requests are sent once and are never retried.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        bearer_token: str = "",
        timeout: float = HTTP_TIMEOUT_SECONDS,
    ):
        if not isinstance(host, str) or not host:
            raise TkachClientError(ErrorCode.NON_LOOPBACK_ADDRESS)
        try:
            address = ipaddress.ip_address(host)
        except ValueError as error:
            raise TkachClientError(ErrorCode.NON_LOOPBACK_ADDRESS) from error
        if not address.is_loopback:
            raise TkachClientError(ErrorCode.NON_LOOPBACK_ADDRESS)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise TkachClientError(ErrorCode.INVALID_REQUEST)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
            or timeout > MAX_HTTP_TIMEOUT_SECONDS
        ):
            raise TkachClientError(ErrorCode.INVALID_REQUEST)
        self._host = host
        self._port = port
        self._timeout = float(timeout)
        self._bearer_token = _validated_token(bearer_token)
        self._closed = False

    def __enter__(self) -> TkachClient:
        return self

    def __exit__(self, _exc_type: Any, _exc_value: Any, _traceback: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"TkachClient(host={self._host!r}, port={self._port}, bearer_token=<redacted>)"

    @property
    def address(self) -> tuple[str, int]:
        """Return the validated numeric loopback endpoint."""

        return self._host, self._port

    def close(self) -> None:
        """Best-effort wipe the client's owned token buffer and close it."""

        for index in range(len(self._bearer_token)):
            self._bearer_token[index] = 0
        self._closed = True

    def health(self) -> None:
        """Require the exact unauthenticated ``/healthz`` liveness response."""

        response = self._exchange("GET", "/healthz", None)
        if response.status_code != 200 or response.body != b'{"status":"ok"}':
            raise TkachClientError(ErrorCode.UNEXPECTED_HEALTH_RESPONSE)

    def ready(self) -> None:
        """Require the exact unauthenticated ``/readyz`` admission response."""

        response = self._exchange("GET", "/readyz", None)
        if response.status_code != 200 or response.body != b'{"status":"ready"}':
            raise TkachClientError(ErrorCode.UNEXPECTED_READINESS_RESPONSE)

    def run(self, request_id: str, lifecycle_id: str, request: Any) -> ClientResponse:
        """Send one bounded request and return a transport-only observation.

        The nested request is serialized as data and remains subject to the
        server's strict Gateway parser. This method does not interpret policy,
        create a capability, retry an effect, or turn a non-2xx response into
        authority.
        """

        _validate_identifier(request_id)
        _validate_identifier(lifecycle_id)
        try:
            encoded_request = json.dumps(
                {
                    "request_id": request_id,
                    "lifecycle_id": lifecycle_id,
                    "request": request,
                },
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, UnicodeError, ValueError) as error:
            raise TkachClientError(ErrorCode.INVALID_REQUEST) from error
        if len(encoded_request) > MAX_HTTP_BODY_BYTES:
            raise TkachClientError(ErrorCode.INVALID_REQUEST)
        return self._exchange("POST", "/v1/run", encoded_request)

    def _exchange(self, method: str, path: str, body: bytes | None) -> ClientResponse:
        if self._closed:
            raise TkachClientError(ErrorCode.CLOSED)
        headers = {"Connection": "close"}
        if body is not None:
            headers["Authorization"] = "Bearer " + bytes(self._bearer_token).decode("ascii")
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection(
            self._host,
            self._port,
            timeout=self._timeout,
        )
        deadline = time.monotonic() + self._timeout
        try:
            connection.connect()
            _set_socket_deadline(connection, deadline)
            connection.request(method, path, body=body, headers=headers)
            _set_socket_deadline(connection, deadline)
            response = connection.getresponse()
            return _read_response(response)
        except TkachClientError:
            raise
        except (http.client.HTTPException, OSError, UnicodeError) as error:
            raise TkachClientError(ErrorCode.IO) from error
        finally:
            connection.close()


def _set_socket_deadline(connection: http.client.HTTPConnection, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0 or connection.sock is None:
        raise TkachClientError(ErrorCode.IO)
    connection.sock.settimeout(remaining)


def _validated_token(value: str) -> bytearray:
    if not isinstance(value, str):
        raise TkachClientError(ErrorCode.INVALID_AUTHENTICATION)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise TkachClientError(ErrorCode.INVALID_AUTHENTICATION) from error
    if not encoded or len(encoded) > MAX_RUNTIME_AUTH_BYTES or any(
        byte not in _AUTH_BYTES for byte in encoded
    ):
        raise TkachClientError(ErrorCode.INVALID_AUTHENTICATION)
    return bytearray(encoded)


def _validate_identifier(value: str) -> None:
    try:
        encoded = value.encode("ascii")
    except (AttributeError, UnicodeEncodeError) as error:
        raise TkachClientError(ErrorCode.INVALID_REQUEST) from error
    if not encoded or len(encoded) > MAX_RUNTIME_ID_BYTES or any(
        byte not in _ID_BYTES for byte in encoded
    ):
        raise TkachClientError(ErrorCode.INVALID_REQUEST)


def _read_response(response: http.client.HTTPResponse) -> ClientResponse:
    status_line = (
        f"HTTP/{response.version // 10}.{response.version % 10} "
        f"{response.status} {response.reason}\r\n"
    ).encode("latin-1", "replace")
    if len(status_line) + len(response.msg.as_bytes()) > MAX_HTTP_HEADER_BYTES:
        raise TkachClientError(ErrorCode.RESPONSE_TOO_LARGE)
    transfer_encoding = response.headers.get_all("Transfer-Encoding") or []
    if transfer_encoding:
        raise TkachClientError(ErrorCode.INVALID_RESPONSE)
    content_types = response.headers.get_all("Content-Type") or []
    if content_types != ["application/json"]:
        raise TkachClientError(ErrorCode.INVALID_RESPONSE)
    content_lengths = response.headers.get_all("Content-Length") or []
    if len(content_lengths) != 1 or not content_lengths[0] or not content_lengths[0].isdigit():
        raise TkachClientError(ErrorCode.INVALID_RESPONSE)
    try:
        content_length = int(content_lengths[0], 10)
    except ValueError as error:
        raise TkachClientError(ErrorCode.INVALID_RESPONSE) from error
    if content_length > MAX_RUNTIME_RESPONSE_BYTES:
        raise TkachClientError(ErrorCode.RESPONSE_TOO_LARGE)
    try:
        body = response.read(content_length)
    except (http.client.HTTPException, OSError) as error:
        raise TkachClientError(ErrorCode.IO) from error
    if len(body) != content_length:
        raise TkachClientError(ErrorCode.INVALID_RESPONSE)
    return ClientResponse(response.status, body)
