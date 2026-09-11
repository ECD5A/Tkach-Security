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

// Package tkachclient is a thin, bounded carrier for the Tkach loopback HTTP
// contract. It does not reimplement Tkach Core policy or create authority.
package tkachclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	// MaxHTTPBodyBytes mirrors the published v0.1 HTTP request budget.
	MaxHTTPBodyBytes = 64*1024 - 256 - 256
	// MaxHTTPHeaderBytes is the published v0.1 HTTP header budget.
	MaxHTTPHeaderBytes = 16 * 1024
	// MaxRuntimeAuthBytes is the published v0.1 bearer proof budget.
	MaxRuntimeAuthBytes = 256
	// MaxRuntimeIDBytes is the published v0.1 identity budget.
	MaxRuntimeIDBytes = 128
	// MaxRuntimeResponseBytes is the published v0.1 response budget.
	MaxRuntimeResponseBytes = 128 * 1024
	clientTimeout           = 500 * time.Millisecond
)

// ErrorCode is a stable, payload-free client failure category.
type ErrorCode string

const (
	ErrorClosed                   ErrorCode = "client_closed"
	ErrorInvalidAuthentication    ErrorCode = "invalid_authentication"
	ErrorInvalidRequest           ErrorCode = "invalid_request"
	ErrorInvalidResponse          ErrorCode = "invalid_response"
	ErrorIO                       ErrorCode = "io_failure"
	ErrorNonLoopbackAddress       ErrorCode = "non_loopback_address"
	ErrorResponseTooLarge         ErrorCode = "response_too_large"
	ErrorUnexpectedHealthResponse ErrorCode = "unexpected_health_response"
)

// Error never includes request, response, endpoint, or token material.
type Error struct {
	Code ErrorCode
}

func (e *Error) Error() string { return string(e.Code) }

// Response is a bounded transport observation. Its body has no policy meaning
// by itself.
type Response struct {
	StatusCode int
	Body       []byte
}

// IsSuccess reports only the HTTP status class; it does not grant authority.
func (r Response) IsSuccess() bool { return r.StatusCode >= 200 && r.StatusCode < 300 }

// Client is a loopback-only Tkach HTTP client. Requests are sent once.
type Client struct {
	host      string
	port      int
	token     []byte
	http      *http.Client
	transport *http.Transport
	mu        sync.RWMutex
	closed    bool
}

// NewClient validates a numeric loopback endpoint and a runtime-compatible
// bearer token. DNS names and public-network addresses are rejected.
func NewClient(host string, port int, bearerToken string) (*Client, error) {
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, &Error{Code: ErrorNonLoopbackAddress}
	}
	if port < 1 || port > 65535 || !validToken(bearerToken) {
		if port < 1 || port > 65535 {
			return nil, &Error{Code: ErrorInvalidRequest}
		}
		return nil, &Error{Code: ErrorInvalidAuthentication}
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		MaxConnsPerHost:   1,
	}
	return &Client{
		host:      host,
		port:      port,
		token:     []byte(bearerToken),
		transport: transport,
		http:      &http.Client{Transport: transport, Timeout: clientTimeout},
	}, nil
}

// String is intentionally redacted and safe for logs.
func (c *Client) String() string {
	if c == nil {
		return "TkachClient(<nil>)"
	}
	return fmt.Sprintf("TkachClient(host=%q, port=%d, bearerToken=<redacted>)", c.host, c.port)
}

// Close wipes the client's owned token and closes transport idle state.
func (c *Client) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	for index := range c.token {
		c.token[index] = 0
	}
	c.closed = true
	c.mu.Unlock()
	c.transport.CloseIdleConnections()
}

// Health requires the exact unauthenticated /healthz liveness response.
func (c *Client) Health() error {
	response, err := c.exchange(http.MethodGet, "/healthz", nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal(response.Body, []byte(`{"status":"ok"}`)) {
		return &Error{Code: ErrorUnexpectedHealthResponse}
	}
	return nil
}

// Run sends one bounded request and returns transport observations only.
func (c *Client) Run(requestID, lifecycleID string, request any) (Response, error) {
	if err := validateIdentifier(requestID); err != nil {
		return Response{}, err
	}
	if err := validateIdentifier(lifecycleID); err != nil {
		return Response{}, err
	}
	body, err := json.Marshal(struct {
		RequestID   string `json:"request_id"`
		LifecycleID string `json:"lifecycle_id"`
		Request     any    `json:"request"`
	}{requestID, lifecycleID, request})
	if err != nil || len(body) > MaxHTTPBodyBytes {
		return Response{}, &Error{Code: ErrorInvalidRequest}
	}
	return c.exchange(http.MethodPost, "/v1/run", body)
}

func (c *Client) exchange(method, path string, body []byte) (Response, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return Response{}, &Error{Code: ErrorClosed}
	}
	token := append([]byte(nil), c.token...)
	host := c.host
	port := c.port
	httpClient := c.http
	c.mu.RUnlock()
	defer zero(token)

	url := "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + path
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return Response{}, &Error{Code: ErrorInvalidRequest}
	}
	request.GetBody = nil
	request.Header.Set("Connection", "close")
	if body != nil {
		request.Header.Set("Authorization", "Bearer "+string(token))
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = int64(len(body))
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return Response{}, &Error{Code: ErrorIO}
	}
	defer response.Body.Close()
	contentLength, err := parseResponseHeaders(response)
	if err != nil {
		return Response{}, err
	}
	body, err = io.ReadAll(io.LimitReader(response.Body, int64(MaxRuntimeResponseBytes)+1))
	if err != nil {
		return Response{}, &Error{Code: ErrorIO}
	}
	if len(body) > MaxRuntimeResponseBytes || int64(len(body)) > contentLength {
		return Response{}, &Error{Code: ErrorResponseTooLarge}
	}
	if int64(len(body)) != contentLength {
		return Response{}, &Error{Code: ErrorInvalidResponse}
	}
	return Response{StatusCode: response.StatusCode, Body: body}, nil
}

func parseResponseHeaders(response *http.Response) (int64, error) {
	headerBytes := len("HTTP/1.1 ") + len(response.Status)
	for name, values := range response.Header {
		for _, value := range values {
			headerBytes += len(name) + len(value) + 4
		}
	}
	if response.ContentLength >= 0 {
		headerBytes += len("Content-Length") + len(strconv.FormatInt(response.ContentLength, 10)) + 4
	}
	for _, transferEncoding := range response.TransferEncoding {
		headerBytes += len("Transfer-Encoding") + len(transferEncoding) + 4
	}
	if headerBytes > MaxHTTPHeaderBytes {
		return 0, &Error{Code: ErrorResponseTooLarge}
	}
	if len(response.TransferEncoding) != 0 {
		return 0, &Error{Code: ErrorInvalidResponse}
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 || contentTypes[0] != "application/json" {
		return 0, &Error{Code: ErrorInvalidResponse}
	}
	if response.ContentLength < 0 {
		return 0, &Error{Code: ErrorInvalidResponse}
	}
	if response.ContentLength > MaxRuntimeResponseBytes {
		return 0, &Error{Code: ErrorResponseTooLarge}
	}
	return response.ContentLength, nil
}

func validToken(value string) bool {
	if len(value) == 0 || len(value) > MaxRuntimeAuthBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		if !validTokenByte(value[index]) {
			return false
		}
	}
	return true
}

func validTokenByte(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9' || value == '.' || value == '_' || value == ':' || value == '-'
}

func validateIdentifier(value string) error {
	if len(value) == 0 || len(value) > MaxRuntimeIDBytes {
		return &Error{Code: ErrorInvalidRequest}
	}
	for index := 0; index < len(value); index++ {
		if !validTokenByte(value[index]) {
			return &Error{Code: ErrorInvalidRequest}
		}
	}
	return nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
