# `tkach-mcp`

`tkach-mcp` is the bounded stdio MCP adapter for the Tkach Security local
runtime. It exposes one `tkach_run` tool and delegates to an already running
loopback `tkach serve` process. Policy, authority, provider handling, and
effects remain outside the protocol adapter.

- MCP Registry name: `mcp-name: io.github.ECD5A/tkach-security`

## Local use

Start the local runtime first, then configure the MCP host to launch the
adapter with `TKACH_HTTP_ADDR` and `TKACH_BEARER_TOKEN` from trusted host
configuration. The adapter accepts no credential arguments and writes only
newline-delimited JSON-RPC to stdout.

```text
cargo install tkach-mcp --version 0.1.0
tkach-mcp --help
```

This crate is not a public package until the release owner publishes the
matching version and verifies its registry metadata.

See the repository [integration guide](https://github.com/ECD5A/Tkach-Security/blob/main/docs/INTEGRATION.md#mcp-stdio-adapter--v01),
[security policy](https://github.com/ECD5A/Tkach-Security/blob/main/SECURITY.md),
and [LICENSE](https://github.com/ECD5A/Tkach-Security/blob/main/LICENSE).
