# Tkach Security examples

These examples are intentionally small carriers around the reviewed Tkach
contracts. They do not implement policy, authority, providers, effects, or
secret handling outside the Rust boundary.

## Start the local reference runtime

From the repository root, start the deterministic local runtime with a
trusted bearer token. On Unix:

```sh
export TKACH_BEARER_TOKEN=replace-with-local-token
cargo run -p tkach-cli -- serve --demo
```

On PowerShell:

```powershell
$env:TKACH_BEARER_TOKEN = "replace-with-local-token"
cargo run -p tkach-cli -- serve --demo
```

The server remains loopback-only. Set `TKACH_HTTP_PORT` when the default port
8080 is already in use. Keep the token in trusted host configuration; never
place it in model-controlled data or commit it to a repository.

## Run an adapter example

Use the same token in a second terminal:

```sh
export TKACH_BEARER_TOKEN=replace-with-local-token
python examples/python/run.py
node examples/javascript/run.mjs
go run ./examples/go
```

The JavaScript example reads `TKACH_BEARER_TOKEN` from the environment. On
PowerShell, set it once before running all three commands:

```powershell
$env:TKACH_BEARER_TOKEN = "replace-with-local-token"
python examples/python/run.py
node examples/javascript/run.mjs
go run ./examples/go
```

The Python adapter is dependency-free at runtime. Run it from a checkout with
the local package available, or install the local package first:

```text
python -m pip install --editable sdk/python
```

Each example performs `/healthz`, sends one bounded request to `/v1/run`, and
prints only the transport observation. A successful HTTP response is not an
authorization grant and must not be treated as proof that model output is
trusted.

## Rust Core example

The Rust example is kept with its owning crate so Cargo can compile it with
the exact workspace contract:

```text
cargo run -p tkach-gateway --example quickstart --locked
```

It constructs the Core primitives, runs a deterministic provider, and releases
output only through the Gateway result.

## MCP example

Start the same local runtime, install or build `tkach-mcp`, and configure an
MCP host with trusted environment configuration:

```json
{
  "mcpServers": {
    "tkach": {
      "command": "tkach-mcp",
      "env": {
        "TKACH_HTTP_ADDR": "127.0.0.1:8080",
        "TKACH_BEARER_TOKEN": "<trusted-runtime-token>"
      }
    }
  }
}
```

The adapter uses stdio and delegates one bounded `tkach_run` tool call to the
loopback runtime. It does not expose Core policy or credentials as tool
arguments. The MCP host remains responsible for user consent and subprocess
isolation.
