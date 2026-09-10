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

//! stdio entry point for the bounded Tkach MCP adapter.

#![forbid(unsafe_code)]

use std::env;
use std::io;
use std::net::SocketAddr;
use tkach_client::TkachClient;
use tkach_mcp::McpStdioServer;

const DEFAULT_HTTP_ADDRESS: &str = "127.0.0.1:8080";
const ADDRESS_ENV: &str = "TKACH_HTTP_ADDR";
const TOKEN_ENV: &str = "TKACH_BEARER_TOKEN";

fn main() {
    let address = env::var(ADDRESS_ENV).unwrap_or_else(|_| DEFAULT_HTTP_ADDRESS.to_owned());
    let Ok(address) = address.parse::<SocketAddr>() else {
        eprintln!("tkach-mcp: TKACH_HTTP_ADDR must be a loopback socket address");
        std::process::exit(2);
    };
    let Ok(token) = env::var(TOKEN_ENV) else {
        eprintln!("tkach-mcp: TKACH_BEARER_TOKEN is required");
        std::process::exit(2);
    };
    let Ok(client) = TkachClient::new(address, token) else {
        eprintln!("tkach-mcp: invalid loopback client configuration");
        std::process::exit(2);
    };
    let mut server = McpStdioServer::new(client);
    let stdin = io::stdin();
    let stdout = io::stdout();
    if server.serve(stdin.lock(), stdout.lock()).is_err() {
        eprintln!("tkach-mcp: stdio transport failed");
        std::process::exit(1);
    }
}
