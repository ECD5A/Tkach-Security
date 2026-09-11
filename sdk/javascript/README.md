# Tkach JavaScript / TypeScript adapter

This is a dependency-free Node.js carrier for the reviewed local HTTP
contract. `tkach_client.mjs` is the runtime; `tkach_client.d.ts` provides the
TypeScript declarations without reimplementing Tkach Core.

Install the local package while the public npm release is still deferred:

```text
npm install ./sdk/javascript
```

The package has no install or postinstall hook and ships only the runtime,
declarations, and this README.

```js
import { TkachClient } from "tkach-security-client";

const tkach = new TkachClient("127.0.0.1", 8080, "local-development-secret");
try {
  await tkach.health();
  const response = await tkach.run("request-1", "lifecycle-1", {
    messages: [{ role: "user", content: "hello" }],
  });
  console.log(response.statusCode, response.body.toString("utf8"));
} finally {
  tkach.close();
}
```

The adapter accepts numeric loopback IP addresses only, uses one bounded HTTP
request without retries, rejects chunked/ambiguous/oversized responses, and
returns transport observations. It has no policy, authority, provider,
executor, secret-broker, or public-network surface. It is not a TLS client,
process boundary, public service, or published npm package.

Run the offline contract tests with Node.js 20 or newer:

```text
node --test sdk/javascript/test_tkach_client.mjs
```
