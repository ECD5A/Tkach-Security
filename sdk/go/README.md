# Tkach Go adapter

This is a dependency-free Go carrier for the reviewed local HTTP contract. It
does not reimplement Tkach Core policy or create authority.

```go
client, err := tkachclient.NewClient("127.0.0.1", 8080, "local-development-secret")
if err != nil {
    return err
}
defer client.Close()
if err := client.Health(); err != nil {
    return err
}
response, err := client.Run("request-1", "lifecycle-1", map[string]any{
    "messages": []map[string]string{{"role": "user", "content": "hello"}},
})
```

The adapter accepts numeric loopback IP addresses only, bounds request and
response framing, rejects chunked/ambiguous responses, never retries, and
returns transport observations. It is not TLS, process isolation, a public
service, or a published Go module yet.

Run the offline contract tests:

```text
go test ./...
```
