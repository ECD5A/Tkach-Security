import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import test from "node:test";

import {
  ErrorCode,
  MAX_HTTP_BODY_BYTES,
  MAX_RUNTIME_RESPONSE_BYTES,
  TkachClient,
  TkachClientError,
} from "./tkach_client.mjs";

async function withHttpServer(handler, callback) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await callback(server.address().port);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function withRawServer(response, callback) {
  const server = net.createServer((socket) => {
    let request = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      request = Buffer.concat([request, chunk]);
      if (request.includes(Buffer.from("\r\n\r\n"))) {
        socket.end(response);
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await callback(server.address().port);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("configuration is loopback-only and string output redacts the token", () => {
  for (const host of ["localhost", "0.0.0.0", "192.0.2.1"]) {
    assert.throws(
      () => new TkachClient(host, 8080, "secret"),
      (error) => error instanceof TkachClientError && error.code === ErrorCode.NON_LOOPBACK_ADDRESS,
    );
  }
  assert.throws(
    () => new TkachClient("127.0.0.1", 8080, "bad token"),
    (error) => error instanceof TkachClientError && error.code === ErrorCode.INVALID_AUTHENTICATION,
  );
  for (const timeoutMs of [0, -1, 120_001, 1.5]) {
    assert.throws(
      () => new TkachClient("127.0.0.1", 8080, "secret", timeoutMs),
      (error) => error instanceof TkachClientError && error.code === ErrorCode.INVALID_REQUEST,
    );
  }
  const client = new TkachClient("127.0.0.1", 8080, "secret-token");
  assert.doesNotMatch(client.toString(), /secret-token/);
  client.close();
});

test("health uses the exact public endpoint without bearer auth", async () => {
  const requests = [];
  await withHttpServer((request, response) => {
    requests.push({ method: request.method, url: request.url, headers: request.headers });
    response.writeHead(200, {
      "Content-Type": "application/json",
      "Content-Length": String(Buffer.byteLength('{"status":"ok"}')),
      Connection: "close",
    });
    response.end('{"status":"ok"}');
  }, async (port) => {
    const client = new TkachClient("127.0.0.1", port, "secret-token");
    await client.health();
    client.close();
  });
  assert.deepEqual(requests[0].url, "/healthz");
  assert.equal(requests[0].headers.authorization, undefined);
});

test("run sends one bounded request and returns transport observation", async () => {
  let received;
  await withHttpServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      received = { method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks) };
      const body = '{"Success":{"output":"bounded response"}}';
      response.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Length": String(Buffer.byteLength(body)),
        Connection: "close",
      });
      response.end(body);
    });
  }, async (port) => {
    const client = new TkachClient("127.0.0.1", port, "secret-token");
    const result = await client.run("request-1", "lifecycle-1", {
      messages: [{ role: "user", content: "hello" }],
    });
    client.close();
    assert.equal(result.statusCode, 200);
    assert.equal(result.isSuccess, true);
    assert.doesNotMatch(result.body.toString("utf8"), /secret-token/);
  });
  assert.deepEqual([received.method, received.url], ["POST", "/v1/run"]);
  assert.equal(received.headers.authorization, "Bearer secret-token");
  assert.equal(received.headers["content-type"], "application/json");
  assert.match(received.body.toString("utf8"), /"request_id":"request-1"/);
});

test("run accepts a bounded slow response without retry", async () => {
  await withHttpServer((_request, response) => {
    setTimeout(() => {
      const body = "{}";
      response.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Length": String(Buffer.byteLength(body)),
        Connection: "close",
      });
      response.end(body);
    }, 800);
  }, async (port) => {
    const client = new TkachClient("127.0.0.1", port, "secret-token");
    const result = await client.run("slow-request", "slow-lifecycle", { messages: [] });
    client.close();
    assert.equal(result.statusCode, 200);
  });
});

test("an explicit short deadline rejects a slow response", async () => {
  await withHttpServer((_request, response) => {
    setTimeout(() => response.end("{}"), 800);
  }, async (port) => {
    const client = new TkachClient("127.0.0.1", port, "secret-token", 100);
    await assert.rejects(
      client.run("short-request", "short-lifecycle", { messages: [] }),
      (error) => error.code === ErrorCode.IO,
    );
    client.close();
  });
});

test("chunked and duplicate response framing fail closed", async () => {
  await withHttpServer((_request, response) => {
    response.writeHead(200, {
      "Content-Type": "application/json",
      "Transfer-Encoding": "chunked",
      Connection: "close",
    });
    response.end("{}");
  }, async (port) => {
    const client = new TkachClient("127.0.0.1", port, "secret-token");
    await assert.rejects(client.health(), (error) => error.code === ErrorCode.INVALID_RESPONSE);
    client.close();
  });
  const duplicate = Buffer.from(
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
  );
  await withRawServer(duplicate, async (port) => {
    const client = new TkachClient("127.0.0.1", port, "secret-token");
    await assert.rejects(
      client.health(),
      (error) => [ErrorCode.INVALID_RESPONSE, ErrorCode.IO].includes(error.code),
    );
    client.close();
  });
});

test("request and response budgets are bounded", async () => {
  const oversized = Buffer.from(
    `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${MAX_RUNTIME_RESPONSE_BYTES + 1}\r\nConnection: close\r\n\r\n`,
  );
  await withRawServer(oversized, async (port) => {
    const client = new TkachClient("127.0.0.1", port, "secret-token");
    await assert.rejects(client.health(), (error) => error.code === ErrorCode.RESPONSE_TOO_LARGE);
    client.close();
  });
  const client = new TkachClient("127.0.0.1", 8080, "secret-token");
  await assert.rejects(
    client.run("request-1", "lifecycle-1", { payload: "x".repeat(MAX_HTTP_BODY_BYTES) }),
    (error) => error.code === ErrorCode.INVALID_REQUEST,
  );
  client.close();
});

test("close wipes the owned token and rejects future calls", () => {
  const client = new TkachClient("127.0.0.1", 8080, "secret-token");
  client.close();
  assert.equal(client._token.every((byte) => byte === 0), true);
  return assert.rejects(client.health(), (error) => error.code === ErrorCode.CLOSED);
});
