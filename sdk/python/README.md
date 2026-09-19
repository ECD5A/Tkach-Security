# Tkach Python adapter

This is a deliberately small, standard-library-only client for the reviewed
local HTTP contract. It is not a Python reimplementation of Tkach Core.

Install the published package from PyPI:

```text
python -m pip install tkach-security-client==0.1.2
```

For source development, use `python -m pip install ./sdk/python` from the
repository root.

```python
from tkach_client import TkachClient

with TkachClient("127.0.0.1", 8080, "local-development-secret") as tkach:
    tkach.health()
    response = tkach.run(
        "request-1",
        "lifecycle-1",
        {"messages": [{"role": "user", "content": "hello"}]},
    )
    print(response.status_code, response.body)
```

The adapter accepts numeric loopback IP addresses only, uses one bounded HTTP
request without retries, rejects chunked/ambiguous/oversized responses, and
keeps policy interpretation inside the Rust runtime. It is a local carrier,
not TLS, process isolation, a public client, or an authority API.

`ClientResponse.kind` provides the shared finite result classification:
`success`, `refused`, `provider_failure`, `outcome_unknown`,
`replay_or_cancelled`, `unavailable`, `invalid_request`, `effect_failed`, or
`other`. These are observations only; the client never retries, and
`outcome_unknown` must not be used to repeat an action.

Each exchange now has a 35-second total deadline by default.
The current source also accepts a trusted finite `timeout` in seconds greater
than 0 and up to 120; a timeout is not a retry signal and does not prove that
an effect did not happen. The `0.1.2` package carries the bounded deadline and
slow-response hardening.

`health()` is liveness only. `ready()` checks the unauthenticated `/readyz`
admission signal; it becomes non-ready when the runtime is shutting down or
its non-evicting replay ledger is full. It does not prove provider
connectivity or effect availability. This readiness method is part of the
`0.1.2` adapter release.

Run the offline contract tests from this directory:

```text
python -m unittest -v
```
