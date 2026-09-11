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
const HELP: &str = concat!(
    "Tkach Security MCP stdio adapter ",
    env!("CARGO_PKG_VERSION"),
    "\n\nUsage:\n  tkach-mcp                 serve MCP over stdio\n  tkach-mcp --version       print the adapter version\n  tkach-mcp --help          show this guide\n\nConfiguration:\n  TKACH_HTTP_ADDR           loopback Tkach HTTP runtime (default 127.0.0.1:8080)\n  TKACH_BEARER_TOKEN        required runtime bearer proof\n"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Serve,
    Version,
    Help,
    Invalid,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Command {
    let _program = args.next();
    match (args.next(), args.next()) {
        (None, None) => Command::Serve,
        (Some(flag), None) if flag == "--version" => Command::Version,
        (Some(flag), None) if flag == "--help" || flag == "-h" => Command::Help,
        _ => Command::Invalid,
    }
}

fn main() {
    match parse_args(env::args()) {
        Command::Version => {
            println!("tkach-mcp {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Command::Help => {
            print!("{HELP}");
            return;
        }
        Command::Invalid => {
            eprintln!("tkach-mcp: unsupported argument; use --help");
            std::process::exit(2);
        }
        Command::Serve => {}
    }

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

#[cfg(test)]
mod tests {
    use super::{Command, parse_args};

    fn command(args: &[&str]) -> Command {
        parse_args(args.iter().map(|value| (*value).to_owned()))
    }

    #[test]
    fn accepts_only_documented_process_modes() {
        assert_eq!(command(&["tkach-mcp"]), Command::Serve);
        assert_eq!(command(&["tkach-mcp", "--version"]), Command::Version);
        assert_eq!(command(&["tkach-mcp", "--help"]), Command::Help);
        assert_eq!(command(&["tkach-mcp", "-h"]), Command::Help);
        assert_eq!(
            command(&["tkach-mcp", "--version", "secret"]),
            Command::Invalid
        );
        assert_eq!(command(&["tkach-mcp", "--unknown"]), Command::Invalid);
    }
}
