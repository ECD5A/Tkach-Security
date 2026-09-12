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

import { TkachClient } from "../../sdk/javascript/tkach_client.mjs";

const token = process.env.TKACH_BEARER_TOKEN;
if (!token) {
  throw new Error("TKACH_BEARER_TOKEN must be set in trusted host configuration");
}
const port = Number.parseInt(process.env.TKACH_HTTP_PORT ?? "8080", 10);
if (!Number.isInteger(port)) {
  throw new Error("TKACH_HTTP_PORT must be an integer");
}
const client = new TkachClient("127.0.0.1", port, token);
try {
  await client.health();
  const response = await client.run("example-javascript-1", "example-javascript-lifecycle", {
    messages: [{ role: "user", content: "hello from JavaScript" }],
    metadata: [],
    tool_declarations: [],
  });
  console.log(`HTTP ${response.statusCode}`);
  console.log(response.body.toString("utf8"));
} finally {
  client.close();
}
