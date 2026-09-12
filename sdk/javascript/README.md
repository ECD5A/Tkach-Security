# Tkach JavaScript / TypeScript adapter

This is a dependency-free Node.js carrier for the reviewed local HTTP
contract. `tkach_client.mjs` is the runtime; `tkach_client.d.ts` provides the
TypeScript declarations without reimplementing Tkach Core.

Install the published package from npm:

```console
npm install tkach-security-client@0.1.1
```

For repository development, the same package can be installed from the
checkout with `npm install ./sdk/javascript`.

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
process boundary, public service, or policy engine.

The next release will give each exchange a 35-second total deadline by default.
The current source also accepts a trusted integer `timeoutMs` from 1 to 120000
when a different finite budget is required; a timeout is not a retry signal and
does not prove that an effect did not happen. The published `0.1.1` package
retains its original 500ms budget.

`health()` is liveness only. `ready()` checks the unauthenticated `/readyz`
admission signal; it becomes non-ready when the runtime is shutting down or
its non-evicting replay ledger is full. It does not prove provider
connectivity or effect availability. This readiness method is part of the
current source candidate and will ship in the next coordinated adapter
release.

Run the offline contract tests with Node.js 20 or newer:

```text
node --test sdk/javascript/test_tkach_client.mjs
```
