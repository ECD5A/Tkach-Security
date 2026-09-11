/*
 * Tkach Security
 *
 * Copyright 2026 ECD5A
 * Licensed under the Apache License, Version 2.0.
 *
 * Repository: https://github.com/ECD5A/Tkach-Security
 *
 * See LICENSE and SECURITY.md.
 */

/**
 * Thin, bounded Node.js client for the Tkach loopback HTTP contract.
 *
 * This module is a carrier only. It does not implement Core policy,
 * authority, provider orchestration, effects, retries, or secret handling.
 */

import http from "node:http";
import net from "node:net";

// Mirrors the published v0.1 Rust transport contract. Do not silently widen
// these values without a versioned wire-contract review.
export const MAX_HTTP_BODY_BYTES = 64 * 1024 - 256 - 256;
export const MAX_HTTP_HEADER_BYTES = 16 * 1024;
export const MAX_RUNTIME_AUTH_BYTES = 256;
export const MAX_RUNTIME_ID_BYTES = 128;
export const MAX_RUNTIME_RESPONSE_BYTES = 128 * 1024;
export const HTTP_TIMEOUT_MS = 500;

export const ErrorCode = Object.freeze({
  CLOSED: "client_closed",
  INVALID_AUTHENTICATION: "invalid_authentication",
  INVALID_REQUEST: "invalid_request",
  INVALID_RESPONSE: "invalid_response",
  IO: "io_failure",
  NON_LOOPBACK_ADDRESS: "non_loopback_address",
  RESPONSE_TOO_LARGE: "response_too_large",
  UNEXPECTED_HEALTH_RESPONSE: "unexpected_health_response",
});

const ID_PATTERN = /^[A-Za-z0-9._:-]+$/;
const AUTH_PATTERN = ID_PATTERN;

export class TkachClientError extends Error {
  constructor(code) {
    super(code);
    this.name = "TkachClientError";
    this.code = code;
  }

  toString() {
    return `TkachClientError(${this.code})`;
  }
}

export class ClientResponse {
  constructor(statusCode, body) {
    this.statusCode = statusCode;
    this.body = body;
    Object.freeze(this);
  }

  get isSuccess() {
    return this.statusCode >= 200 && this.statusCode < 300;
  }
}

export class TkachClient {
  constructor(host = "127.0.0.1", port = 8080, bearerToken = "") {
    if (typeof host !== "string" || !isLoopback(host)) {
      throw new TkachClientError(ErrorCode.NON_LOOPBACK_ADDRESS);
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new TkachClientError(ErrorCode.INVALID_REQUEST);
    }
    this._host = host;
    this._port = port;
    this._token = validatedToken(bearerToken);
    this._closed = false;
    this._requests = new Set();
  }

  get address() {
    return Object.freeze({ host: this._host, port: this._port });
  }

  toString() {
    return `TkachClient(host=${JSON.stringify(this._host)}, port=${this._port}, bearerToken=<redacted>)`;
  }

  close() {
    this._token.fill(0);
    for (const request of this._requests) {
      request.destroy();
    }
    this._requests.clear();
    this._closed = true;
  }

  async health() {
    const response = await this._exchange("GET", "/healthz");
    if (response.statusCode !== 200 || !response.body.equals(Buffer.from('{"status":"ok"}'))) {
      throw new TkachClientError(ErrorCode.UNEXPECTED_HEALTH_RESPONSE);
    }
  }

  async run(requestId, lifecycleId, request) {
    validateIdentifier(requestId);
    validateIdentifier(lifecycleId);
    let encoded;
    try {
      let nonFinite = false;
      const serialized = JSON.stringify(
        { request_id: requestId, lifecycle_id: lifecycleId, request },
        (_key, value) => {
          if (typeof value === "number" && !Number.isFinite(value)) {
            nonFinite = true;
          }
          return value;
        },
      );
      if (nonFinite || serialized === undefined) {
        throw new Error("non-finite or undefined JSON");
      }
      encoded = Buffer.from(serialized, "utf8");
    } catch (_error) {
      throw new TkachClientError(ErrorCode.INVALID_REQUEST);
    }
    if (encoded.length > MAX_HTTP_BODY_BYTES) {
      throw new TkachClientError(ErrorCode.INVALID_REQUEST);
    }
    return this._exchange("POST", "/v1/run", encoded);
  }

  _exchange(method, path, body) {
    if (this._closed) {
      return Promise.reject(new TkachClientError(ErrorCode.CLOSED));
    }
    const headers = { Connection: "close" };
    if (body !== undefined) {
      headers.Authorization = `Bearer ${this._token.toString("ascii")}`;
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = String(body.length);
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      let request;
      const finish = (callback, value) => {
        if (settled) {
          return;
        }
        settled = true;
        this._requests.delete(request);
        callback(value);
      };
      const fail = (error) => {
        const safeError =
          error instanceof TkachClientError
            ? error
            : new TkachClientError(ErrorCode.IO);
        if (!settled) {
          request?.destroy();
        }
        finish(reject, safeError);
      };
      try {
        request = http.request(
          {
            host: this._host,
            port: this._port,
            method,
            path,
            headers,
            agent: false,
          },
          (response) => {
            let framing;
            try {
              framing = parseResponseHeaders(response);
            } catch (error) {
              fail(error);
              return;
            }
            const chunks = [];
            let received = 0;
            response.on("data", (chunk) => {
              received += chunk.length;
              if (received > framing.contentLength || received > MAX_RUNTIME_RESPONSE_BYTES) {
                fail(
                  received > MAX_RUNTIME_RESPONSE_BYTES
                    ? new TkachClientError(ErrorCode.RESPONSE_TOO_LARGE)
                    : new TkachClientError(ErrorCode.INVALID_RESPONSE),
                );
                return;
              }
              chunks.push(chunk);
            });
            response.on("end", () => {
              if (received !== framing.contentLength) {
                fail(new TkachClientError(ErrorCode.INVALID_RESPONSE));
                return;
              }
              finish(
                resolve,
                new ClientResponse(response.statusCode, Buffer.concat(chunks, received)),
              );
            });
            response.on("error", () => fail(new TkachClientError(ErrorCode.IO)));
          },
        );
        this._requests.add(request);
        request.setTimeout(HTTP_TIMEOUT_MS, () => fail(new TkachClientError(ErrorCode.IO)));
        request.on("error", () => fail(new TkachClientError(ErrorCode.IO)));
        request.end(body);
      } catch (_error) {
        fail(new TkachClientError(ErrorCode.IO));
      }
    });
  }
}

function isLoopback(host) {
  const family = net.isIP(host);
  return (family === 4 && host.split(".")[0] === "127") || (family === 6 && host === "::1");
}

function validatedToken(value) {
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value, "ascii") !== value.length ||
    value.length === 0 ||
    value.length > MAX_RUNTIME_AUTH_BYTES ||
    !AUTH_PATTERN.test(value)
  ) {
    throw new TkachClientError(ErrorCode.INVALID_AUTHENTICATION);
  }
  return Buffer.from(value, "ascii");
}

function validateIdentifier(value) {
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value, "ascii") !== value.length ||
    value.length === 0 ||
    value.length > MAX_RUNTIME_ID_BYTES ||
    !ID_PATTERN.test(value)
  ) {
    throw new TkachClientError(ErrorCode.INVALID_REQUEST);
  }
}

function parseResponseHeaders(response) {
  const rawHeaders = response.rawHeaders;
  let headerBytes = 0;
  const transferEncoding = [];
  const contentTypes = [];
  const contentLengths = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1];
    headerBytes += Buffer.byteLength(name, "utf8") + Buffer.byteLength(value, "utf8") + 4;
    switch (name.toLowerCase()) {
      case "transfer-encoding":
        transferEncoding.push(value);
        break;
      case "content-type":
        contentTypes.push(value);
        break;
      case "content-length":
        contentLengths.push(value);
        break;
      default:
        break;
    }
  }
  const statusLineBytes = Buffer.byteLength(
    `HTTP/${response.httpVersion} ${response.statusCode} ${response.statusMessage}\r\n`,
    "utf8",
  );
  if (statusLineBytes + headerBytes > MAX_HTTP_HEADER_BYTES) {
    throw new TkachClientError(ErrorCode.RESPONSE_TOO_LARGE);
  }
  if (transferEncoding.length !== 0 || contentTypes.length !== 1 || contentTypes[0] !== "application/json") {
    throw new TkachClientError(ErrorCode.INVALID_RESPONSE);
  }
  if (
    contentLengths.length !== 1 ||
    !/^[0-9]+$/.test(contentLengths[0])
  ) {
    throw new TkachClientError(ErrorCode.INVALID_RESPONSE);
  }
  const contentLength = Number(contentLengths[0]);
  if (!Number.isSafeInteger(contentLength)) {
    throw new TkachClientError(ErrorCode.RESPONSE_TOO_LARGE);
  }
  if (contentLength > MAX_RUNTIME_RESPONSE_BYTES) {
    throw new TkachClientError(ErrorCode.RESPONSE_TOO_LARGE);
  }
  return { contentLength };
}
