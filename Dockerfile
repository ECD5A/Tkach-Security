# Tkach Security
#
# Copyright 2026 ECD5A
# Licensed under the Apache License, Version 2.0.
#
# Repository: https://github.com/ECD5A/Tkach-Security
# See LICENSE and SECURITY.md.

FROM rust:1.85.1-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --locked --release -p tkach-cli

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /nonroot \
       --shell /usr/sbin/nologin tkach

COPY --from=builder /src/target/release/tkach /usr/local/bin/tkach

LABEL org.opencontainers.image.source="https://github.com/ECD5A/Tkach-Security" \
      org.opencontainers.image.description="Loopback-only Tkach Security runtime with fail-closed defaults" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app
USER 10001:10001
ENV TKACH_HTTP_ADDR=127.0.0.1:8080

# The service deliberately stays loopback-only. On Linux, use host networking
# for a host-local deployment; otherwise the healthcheck still works inside
# the container and an explicit reviewed network boundary is required.
EXPOSE 8080
STOPSIGNAL SIGINT
HEALTHCHECK --interval=10s --timeout=2s --start-period=5s --retries=3 CMD ["tkach", "health"]

ENTRYPOINT ["tkach"]
CMD ["serve"]
