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

export declare const MAX_HTTP_BODY_BYTES: number;
export declare const MAX_HTTP_HEADER_BYTES: number;
export declare const MAX_RUNTIME_AUTH_BYTES: number;
export declare const MAX_RUNTIME_ID_BYTES: number;
export declare const MAX_RUNTIME_RESPONSE_BYTES: number;
export declare const HTTP_TIMEOUT_MS: number;

export declare const ErrorCode: {
  readonly CLOSED: "client_closed";
  readonly INVALID_AUTHENTICATION: "invalid_authentication";
  readonly INVALID_REQUEST: "invalid_request";
  readonly INVALID_RESPONSE: "invalid_response";
  readonly IO: "io_failure";
  readonly NON_LOOPBACK_ADDRESS: "non_loopback_address";
  readonly RESPONSE_TOO_LARGE: "response_too_large";
  readonly UNEXPECTED_HEALTH_RESPONSE: "unexpected_health_response";
};

export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode];

export declare class TkachClientError extends Error {
  readonly code: ErrorCodeValue;
  constructor(code: ErrorCodeValue);
}

export declare class ClientResponse {
  readonly statusCode: number;
  readonly body: Uint8Array;
  readonly isSuccess: boolean;
  constructor(statusCode: number, body: Uint8Array);
}

export declare class TkachClient {
  constructor(host?: string, port?: number, bearerToken?: string);
  readonly address: { readonly host: string; readonly port: number };
  close(): void;
  health(): Promise<void>;
  run(requestId: string, lifecycleId: string, request: unknown): Promise<ClientResponse>;
}
