# Tkach Security
#
# Copyright 2026 ECD5A
# Licensed under the Apache License, Version 2.0.
#
# Repository: https://github.com/ECD5A/Tkach-Security
#
# See LICENSE and SECURITY.md.

"""Run one bounded request through the local Tkach HTTP contract."""

from __future__ import annotations

import os

from tkach_client import TkachClient


def main() -> None:
    token = os.environ.get("TKACH_BEARER_TOKEN")
    if not token:
        raise SystemExit("TKACH_BEARER_TOKEN must be set in trusted host configuration")
    port = int(os.environ.get("TKACH_HTTP_PORT", "8080"))
    with TkachClient(port=port, bearer_token=token) as client:
        client.health()
        response = client.run(
            "example-python-1",
            "example-python-lifecycle",
            {
                "messages": [{"role": "user", "content": "hello from Python"}],
                "metadata": [],
                "tool_declarations": [],
            },
        )
        print(f"HTTP {response.status_code}")
        print(response.body.decode("utf-8"))


if __name__ == "__main__":
    main()
