# Tkach Python adapter

This is a deliberately small, standard-library-only client for the reviewed
local HTTP contract. It is not a Python reimplementation of Tkach Core.

Install the published package from PyPI:

```text
python -m pip install tkach-security-client==0.1.1
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

Run the offline contract tests from this directory:

```text
python -m unittest -v
```
