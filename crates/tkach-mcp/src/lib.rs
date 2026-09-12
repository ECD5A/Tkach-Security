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

//! A bounded MCP stdio adapter around the Tkach local HTTP contract.
//!
//! The adapter implements the MCP lifecycle, tools/list, tools/call, and ping
//! subset needed to expose one explicit Tkach tool. It never implements policy,
//! authority, provider orchestration, or effects. All tool execution is
//! delegated to the configured loopback HTTP client.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::Deserialize;
use serde_json::{Value, json};
use std::fmt::{Debug, Formatter};
use std::io::{Read, Write};
use thiserror::Error;
use tkach_client::{ClientError, RunRequest, TkachClient};

/// MCP protocol version implemented by this adapter.
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
/// Maximum bytes in one newline-delimited MCP message.
pub const MAX_MCP_MESSAGE_BYTES: usize = 64 * 1024;
/// Maximum serialized MCP response emitted by this adapter.
pub const MAX_MCP_RESPONSE_BYTES: usize = 132 * 1024;
/// The single model-callable tool exposed by this adapter.
pub const TKACH_TOOL_NAME: &str = "tkach_run";

const MAX_MCP_ID_BYTES: usize = 128;
const INVALID_REQUEST_CODE: i32 = -32600;
const METHOD_NOT_FOUND_CODE: i32 = -32601;
const INVALID_PARAMS_CODE: i32 = -32602;
const INTERNAL_ERROR_CODE: i32 = -32603;
const SESSION_NOT_READY_CODE: i32 = -32002;
const TOOL_DESCRIPTION: &str =
    "Run one bounded request through Tkach Security; model output remains untrusted data.";
const GENERIC_TOOL_FAILURE: &str = "Tkach runtime request failed";
const TOOL_RESPONSE_TEXT: &str = "Tkach runtime response";

/// Errors from the stdio framing or output path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum McpTransportError {
    /// The input ended in a partial line.
    #[error("MCP stdio input ended before a newline-delimited message completed")]
    PartialMessage,
    /// The output or input operation failed.
    #[error("MCP stdio I/O failed")]
    Io,
    /// The adapter could not encode its bounded response.
    #[error("MCP response could not be represented within its budget")]
    ResponseTooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionState {
    New,
    AwaitingInitialized,
    Ready,
}

/// A sequential MCP stdio server backed by one configured Tkach HTTP client.
///
/// The server emits only JSON-RPC messages on the supplied writer. Diagnostics
/// belong to the caller's stderr path; this type never writes logs to stdout.
pub struct McpStdioServer {
    client: TkachClient,
    state: SessionState,
}

impl Debug for McpStdioServer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpStdioServer")
            .field("client", &self.client)
            .field("state", &self.state)
            .finish()
    }
}

impl McpStdioServer {
    /// Construct a server around the already configured loopback client.
    #[must_use]
    pub fn new(client: TkachClient) -> Self {
        Self {
            client,
            state: SessionState::New,
        }
    }

    /// Serve newline-delimited MCP messages until clean EOF.
    ///
    /// Malformed messages receive a bounded JSON-RPC error and do not echo
    /// input. A valid tool invocation is delegated exactly once to the
    /// Tkach client; there are no retries or background tasks.
    ///
    /// # Errors
    ///
    /// Returns a static transport error for I/O or a partial final message.
    pub fn serve<R: Read, W: Write>(
        &mut self,
        mut reader: R,
        mut writer: W,
    ) -> Result<(), McpTransportError> {
        loop {
            let message = match read_message(&mut reader)? {
                ReadMessage::Eof => return Ok(()),
                ReadMessage::Oversized => {
                    let response =
                        error_response(None, INVALID_REQUEST_CODE, "invalid MCP request");
                    write_value(&mut writer, &response)?;
                    continue;
                }
                ReadMessage::Complete(message) => message,
            };
            let response = match serde_json::from_slice::<RpcRequest>(&message) {
                Ok(request) => self.dispatch(&request),
                Err(_) => Some(error_response(
                    None,
                    INVALID_REQUEST_CODE,
                    "invalid MCP request",
                )),
            };
            if let Some(response) = response {
                write_value(&mut writer, &response)?;
            }
        }
    }

    fn dispatch(&mut self, request: &RpcRequest) -> Option<Value> {
        let id = request.id.clone();
        if request.id.as_ref().is_some_and(|id| !validate_id(id)) {
            return response_for_request(
                request,
                error_response(None, INVALID_REQUEST_CODE, "invalid MCP request"),
            );
        }
        if request.jsonrpc != "2.0" || request.method.len() > MAX_MCP_ID_BYTES {
            return response_for_request(
                request,
                error_response(id, INVALID_REQUEST_CODE, "invalid MCP request"),
            );
        }
        match request.method.as_str() {
            "initialize" => self.initialize(request),
            "notifications/initialized" => self.initialized(request),
            "ping" => response_for_request(
                request,
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {}
                }),
            ),
            "tools/list" => self.list_tools(request),
            "tools/call" => self.call_tool(request),
            _ => response_for_request(
                request,
                error_response(id, METHOD_NOT_FOUND_CODE, "MCP method not found"),
            ),
        }
    }

    fn initialize(&mut self, request: &RpcRequest) -> Option<Value> {
        if request.id.is_none() || self.state != SessionState::New {
            return response_for_request(
                request,
                error_response(
                    request.id.clone(),
                    INVALID_REQUEST_CODE,
                    "invalid MCP initialize request",
                ),
            );
        }
        let Some(params) = request.params.clone() else {
            return response_for_request(
                request,
                error_response(
                    request.id.clone(),
                    INVALID_PARAMS_CODE,
                    "initialize parameters are required",
                ),
            );
        };
        let Ok(params) = serde_json::from_value::<InitializeParams>(params) else {
            return response_for_request(
                request,
                error_response(
                    request.id.clone(),
                    INVALID_PARAMS_CODE,
                    "initialize parameters are invalid",
                ),
            );
        };
        if params.protocol_version != MCP_PROTOCOL_VERSION || !params.capabilities.is_object() {
            return response_for_request(
                request,
                error_response(
                    request.id.clone(),
                    INVALID_PARAMS_CODE,
                    "unsupported MCP protocol version",
                ),
            );
        }
        self.state = SessionState::AwaitingInitialized;
        response_for_request(
            request,
            json!({
                "jsonrpc": "2.0",
                "id": request.id.clone(),
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "tkach-mcp", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "Tkach is the authority boundary; tool output is not authority."
                }
            }),
        )
    }

    fn initialized(&mut self, request: &RpcRequest) -> Option<Value> {
        if request.id.is_some() || self.state != SessionState::AwaitingInitialized {
            return response_for_request(
                request,
                error_response(
                    request.id.clone(),
                    INVALID_REQUEST_CODE,
                    "invalid MCP initialized notification",
                ),
            );
        }
        self.state = SessionState::Ready;
        None
    }

    fn list_tools(&self, request: &RpcRequest) -> Option<Value> {
        if self.state != SessionState::Ready {
            return response_for_request(
                request,
                error_response(
                    request.id.clone(),
                    SESSION_NOT_READY_CODE,
                    "MCP session is not initialized",
                ),
            );
        }
        if let Some(params) = request.params.clone() {
            let Ok(params) = serde_json::from_value::<ListToolsParams>(params) else {
                return response_for_request(
                    request,
                    error_response(
                        request.id.clone(),
                        INVALID_PARAMS_CODE,
                        "tools/list parameters are invalid",
                    ),
                );
            };
            if params.cursor.is_some() {
                return response_for_request(
                    request,
                    error_response(
                        request.id.clone(),
                        INVALID_PARAMS_CODE,
                        "tools/list pagination is unsupported",
                    ),
                );
            }
        }
        response_for_request(
            request,
            json!({
                "jsonrpc": "2.0",
                "id": request.id.clone(),
                "result": {"tools": [tool_definition()]}
            }),
        )
    }

    fn call_tool(&self, request: &RpcRequest) -> Option<Value> {
        if self.state != SessionState::Ready {
            return response_for_request(
                request,
                error_response(
                    request.id.clone(),
                    SESSION_NOT_READY_CODE,
                    "MCP session is not initialized",
                ),
            );
        }
        let Some(params) = request.params.clone() else {
            return response_for_request(
                request,
                error_response(
                    request.id.clone(),
                    INVALID_PARAMS_CODE,
                    "tools/call parameters are required",
                ),
            );
        };
        let Ok(params) = serde_json::from_value::<CallToolParams>(params) else {
            return response_for_request(
                request,
                error_response(
                    request.id.clone(),
                    INVALID_PARAMS_CODE,
                    "tools/call parameters are invalid",
                ),
            );
        };
        if params.name != TKACH_TOOL_NAME {
            return response_for_request(
                request,
                error_response(
                    request.id.clone(),
                    METHOD_NOT_FOUND_CODE,
                    "MCP tool not found",
                ),
            );
        }
        let Some(arguments) = params.arguments else {
            return response_for_request(
                request,
                error_response(
                    request.id.clone(),
                    INVALID_PARAMS_CODE,
                    "Tkach tool arguments are required",
                ),
            );
        };
        let tool_result = match make_run_request(arguments) {
            Ok(run_request) => match self.client.run(&run_request) {
                Ok(response) => tool_result_from_response(&response),
                Err(_) => tool_failure(),
            },
            Err(_) => tool_failure(),
        };
        response_for_request(
            request,
            json!({
                "jsonrpc": "2.0",
                "id": request.id.clone(),
                "result": tool_result
            }),
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
    capabilities: Value,
    #[serde(rename = "clientInfo")]
    _client_info: Value,
    #[serde(rename = "_meta", default)]
    _meta: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListToolsParams {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(rename = "_meta", default)]
    _meta: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallToolParams {
    name: String,
    #[serde(default)]
    arguments: Option<Value>,
    #[serde(rename = "_meta", default)]
    _meta: Option<Value>,
}

fn make_run_request(arguments: Value) -> Result<RunRequest, ClientError> {
    let arguments = serde_json::from_value::<ToolArguments>(arguments)
        .map_err(|_| ClientError::InvalidRequest)?;
    let request_json =
        serde_json::to_vec(&arguments.request).map_err(|_| ClientError::InvalidRequest)?;
    RunRequest::new(arguments.request_id, arguments.lifecycle_id, request_json)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolArguments {
    request_id: String,
    lifecycle_id: String,
    request: Value,
}

fn tool_definition() -> Value {
    json!({
        "name": TKACH_TOOL_NAME,
        "description": TOOL_DESCRIPTION,
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "request_id": {"type": "string", "maxLength": 128},
                "lifecycle_id": {"type": "string", "maxLength": 128},
                "request": {
                    "type": "object",
                    "description": "Strict bounded Tkach Gateway request object"
                }
            },
            "required": ["request_id", "lifecycle_id", "request"]
        }
    })
}

fn tool_result_from_response(response: &tkach_client::ClientResponse) -> Value {
    let Ok(structured) = serde_json::from_slice::<Value>(response.body()) else {
        return tool_failure();
    };
    if !structured.is_object() {
        return tool_failure();
    }
    json!({
        "content": [{"type": "text", "text": TOOL_RESPONSE_TEXT}],
        "structuredContent": structured,
        "_meta": {"tkachOutcome": response.kind().as_str()},
        "isError": !response.is_success()
    })
}

fn tool_failure() -> Value {
    json!({
        "content": [{"type": "text", "text": GENERIC_TOOL_FAILURE}],
        "isError": true
    })
}

fn response_for_request(request: &RpcRequest, response: Value) -> Option<Value> {
    if request.id.is_some() {
        Some(response)
    } else {
        None
    }
}

fn error_response(id: Option<Value>, code: i32, message: &'static str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {"code": code, "message": message}
    })
}

fn validate_id(id: &Value) -> bool {
    match id {
        Value::String(value) => !value.is_empty() && value.len() <= MAX_MCP_ID_BYTES,
        Value::Number(value) => value.to_string().len() <= MAX_MCP_ID_BYTES,
        _ => false,
    }
}

fn write_value<W: Write>(writer: &mut W, value: &Value) -> Result<(), McpTransportError> {
    let mut bytes = serde_json::to_vec(&value).map_err(|_| McpTransportError::ResponseTooLarge)?;
    if bytes.len() > MAX_MCP_RESPONSE_BYTES {
        bytes = serde_json::to_vec(&error_response(
            None,
            INTERNAL_ERROR_CODE,
            "MCP response exceeds its budget",
        ))
        .map_err(|_| McpTransportError::ResponseTooLarge)?;
    }
    writer
        .write_all(&bytes)
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush())
        .map_err(|_| McpTransportError::Io)
}

enum ReadMessage {
    Eof,
    Oversized,
    Complete(Vec<u8>),
}

fn read_message<R: Read>(reader: &mut R) -> Result<ReadMessage, McpTransportError> {
    let mut message = Vec::with_capacity(MAX_MCP_MESSAGE_BYTES.min(1024));
    let mut byte = [0_u8; 1];
    loop {
        let read = reader.read(&mut byte).map_err(|_| McpTransportError::Io)?;
        if read == 0 {
            if message.is_empty() {
                return Ok(ReadMessage::Eof);
            }
            return Err(McpTransportError::PartialMessage);
        }
        if byte[0] == b'\n' {
            return if message.len() > MAX_MCP_MESSAGE_BYTES {
                Ok(ReadMessage::Oversized)
            } else {
                if message.last() == Some(&b'\r') {
                    message.pop();
                }
                Ok(ReadMessage::Complete(message))
            };
        }
        if message.len() >= MAX_MCP_MESSAGE_BYTES {
            loop {
                let read = reader.read(&mut byte).map_err(|_| McpTransportError::Io)?;
                if read == 0 {
                    return Err(McpTransportError::PartialMessage);
                }
                if byte[0] == b'\n' {
                    return Ok(ReadMessage::Oversized);
                }
            }
        }
        message.push(byte[0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;
    use std::thread;
    use tkach_core::domain::{Destination, Identity, PolicyId, Principal, RuleId};
    use tkach_core::krosna::{Krosna, Policy};
    use tkach_core::ruslo::{FlowMatcher, FlowOperation, FlowRule, FlowSource, Ruslo};
    use tkach_core::zaslon::Zaslon;
    use tkach_gateway::{
        DeterministicProvider, FakeToolBroker, ProviderStep, RuntimeAuthenticator, RuntimeLimits,
        RuntimeService, ScriptedStep,
    };
    use tkach_http::HttpListener;

    fn service() -> RuntimeService<DeterministicProvider> {
        let client = Destination::Internal(Identity::new("client").unwrap());
        let flow = FlowRule::allow(
            RuleId::new("allow-mcp-export").unwrap(),
            FlowMatcher::any()
                .principal(Principal::Model)
                .source(FlowSource::Model)
                .destination(client.clone())
                .operation(FlowOperation::Export),
        );
        let kernel = Krosna::with_zaslon_and_ruslo(
            Policy::new(PolicyId::new("mcp-test-policy").unwrap(), Vec::new()).unwrap(),
            Zaslon::empty(),
            Ruslo::new(vec![flow]).unwrap(),
        );
        let gateway = tkach_gateway::Gateway::new(
            kernel,
            Zaslon::empty(),
            Zaslon::empty(),
            client,
            FakeToolBroker::new(),
        );
        RuntimeService::new(
            gateway,
            DeterministicProvider::new(vec![ScriptedStep {
                chunks: vec!["safe MCP response".to_owned()],
                actions: Vec::new(),
                continuation: ProviderStep::Complete,
            }]),
            RuntimeAuthenticator::new(b"runtime-secret").unwrap(),
            RuntimeLimits::default(),
        )
    }

    fn initialize() -> String {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0.1.0"}
            }
        })
        .to_string()
    }

    fn call() -> String {
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": TKACH_TOOL_NAME,
                "arguments": {
                    "request_id": "mcp-request-1",
                    "lifecycle_id": "mcp-lifecycle-1",
                    "request": {"messages": [{"role": "user", "content": "hello"}]}
                }
            }
        })
        .to_string()
    }

    #[test]
    fn lifecycle_lists_one_tool_and_delegates_one_bounded_call() {
        let listener = HttpListener::bind("127.0.0.1:0".parse().unwrap(), service()).unwrap();
        let address = listener.local_addr().unwrap();
        let client = TkachClient::new(address, "runtime-secret").unwrap();
        let input = format!(
            "{}\n{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n\
             {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n{}\n",
            initialize(),
            call()
        );
        let mut server = McpStdioServer::new(client);
        let peer = thread::spawn(move || {
            let mut output = Vec::new();
            server
                .serve(Cursor::new(input.into_bytes()), &mut output)
                .unwrap();
            output
        });
        let mut listener = listener;
        listener.serve_one().unwrap();
        let output = String::from_utf8(peer.join().unwrap()).unwrap();
        let messages: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(messages.len(), 3);
        assert_eq!(
            messages[0]["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION
        );
        assert_eq!(messages[1]["result"]["tools"][0]["name"], TKACH_TOOL_NAME);
        assert_eq!(messages[2]["result"]["isError"], false);
        assert_eq!(messages[2]["result"]["_meta"]["tkachOutcome"], "success");
        assert!(output.contains("safe MCP response"));
        assert!(!output.contains("runtime-secret"));
    }

    #[test]
    fn invalid_lifecycle_and_unknown_fields_fail_without_backend_access() {
        let input = concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"wrong","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":3,"method":"initialize","extra":true,"params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}"#,
            "\n"
        )
        .to_owned();
        let client = TkachClient::new("127.0.0.1:1".parse().unwrap(), "secret").unwrap();
        let mut server = McpStdioServer::new(client);
        let mut output = Vec::new();
        server
            .serve(Cursor::new(input.into_bytes()), &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.lines().count(), 3);
        assert!(output.contains("MCP session is not initialized"));
        assert!(output.contains("unsupported MCP protocol version"));
        assert!(!output.contains("extra"));
    }

    #[test]
    fn oversized_message_is_rejected_without_echo_and_output_stays_bounded() {
        let mut input = String::from(r#"{"jsonrpc":"2.0","method":"ping","pad":""#);
        input.push_str(&"x".repeat(MAX_MCP_MESSAGE_BYTES));
        input.push('"');
        input.push('}');
        input.push('\n');
        let client = TkachClient::new("127.0.0.1:1".parse().unwrap(), "secret").unwrap();
        let mut server = McpStdioServer::new(client);
        let mut output = Vec::new();
        server
            .serve(Cursor::new(input.into_bytes()), &mut output)
            .unwrap();
        assert!(output.len() < 256);
        assert!(!output.windows(4).any(|window| window == b"xxxx"));
    }

    #[test]
    fn oversized_message_does_not_desynchronize_the_next_message() {
        let mut input = String::from(r#"{"jsonrpc":"2.0","method":"ping","pad":""#);
        input.push_str(&"x".repeat(MAX_MCP_MESSAGE_BYTES));
        input.push_str("\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
        let client = TkachClient::new("127.0.0.1:1".parse().unwrap(), "secret").unwrap();
        let mut server = McpStdioServer::new(client);
        let mut output = Vec::new();
        server
            .serve(Cursor::new(input.into_bytes()), &mut output)
            .unwrap();
        let messages: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["error"]["code"], INVALID_REQUEST_CODE);
        assert_eq!(messages[1]["id"], 1);
        assert_eq!(messages[1]["result"], json!({}));
    }

    #[test]
    fn partial_message_is_a_terminal_transport_error() {
        let client = TkachClient::new("127.0.0.1:1".parse().unwrap(), "secret").unwrap();
        let mut server = McpStdioServer::new(client);
        let mut output = Vec::new();
        assert_eq!(
            server
                .serve(Cursor::new(br#"{"jsonrpc":"2.0"}"#.to_vec()), &mut output)
                .unwrap_err(),
            McpTransportError::PartialMessage
        );
        assert!(output.is_empty());
    }

    #[test]
    fn tool_failure_is_static_and_does_not_echo_arguments() {
        let input = format!(
            "{}\n{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"{}\",\"arguments\":{{\"request_id\":\"secret-request-id\",\"lifecycle_id\":\"secret-life\",\"request\":{{\"messages\":[]}}}}}}}}\n",
            initialize(),
            TKACH_TOOL_NAME
        );
        let client = TkachClient::new("127.0.0.1:1".parse().unwrap(), "runtime-secret").unwrap();
        let mut server = McpStdioServer::new(client);
        let mut output = Vec::new();
        server
            .serve(Cursor::new(input.into_bytes()), &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(GENERIC_TOOL_FAILURE));
        assert!(!output.contains("secret-request-id"));
        assert!(!output.contains("secret-life"));
        assert!(!output.contains("runtime-secret"));
    }

    #[test]
    fn identifiers_are_bounded_and_only_string_or_number() {
        assert!(validate_id(&json!(1)));
        assert!(validate_id(&json!("request")));
        assert!(!validate_id(&Value::Null));
        assert!(!validate_id(&json!([])));
        assert!(!validate_id(&json!("x".repeat(MAX_MCP_ID_BYTES + 1))));
    }

    #[test]
    fn invalid_identifier_is_not_echoed_in_error_response() {
        let input = concat!(
            r#"{"jsonrpc":"2.0","id":["secret-id"],"method":"ping"}"#,
            "\n"
        );
        let client = TkachClient::new("127.0.0.1:1".parse().unwrap(), "secret").unwrap();
        let mut server = McpStdioServer::new(client);
        let mut output = Vec::new();
        server
            .serve(Cursor::new(input.as_bytes()), &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(r#""id":null"#));
        assert!(!output.contains("secret-id"));
    }
}
