package tkachclient

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestConfigurationIsLoopbackOnlyAndRedacted(t *testing.T) {
	for _, host := range []string{"localhost", "0.0.0.0", "192.0.2.1"} {
		if _, err := NewClient(host, 8080, "secret"); codeOf(err) != ErrorNonLoopbackAddress {
			t.Fatalf("host %q: got %v", host, err)
		}
	}
	if _, err := NewClient("127.0.0.1", 8080, "bad token"); codeOf(err) != ErrorInvalidAuthentication {
		t.Fatalf("invalid token: got %v", err)
	}
	client, err := NewClient("127.0.0.1", 8080, "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(client.String(), "secret-token") {
		t.Fatal("client string leaked token")
	}
	client.Close()
}

func TestHealthUsesExactPublicEndpoint(t *testing.T) {
	var seenAuth string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seenAuth = request.Header.Get("Authorization")
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Connection", "close")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()
	host, port := splitServerAddress(t, server)
	client, err := NewClient(host, port, "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Health(); err != nil {
		t.Fatal(err)
	}
	if seenAuth != "" {
		t.Fatalf("health sent bearer auth: %q", seenAuth)
	}
}

func TestRunSendsBoundedRequestAndReturnsObservation(t *testing.T) {
	var seen *http.Request
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen = request
		body = make([]byte, request.ContentLength)
		_, _ = request.Body.Read(body)
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Connection", "close")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"Success":{"output":"bounded response"}}`))
	}))
	defer server.Close()
	host, port := splitServerAddress(t, server)
	client, err := NewClient(host, port, "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.Run("request-1", "lifecycle-1", map[string]any{
		"messages": []map[string]string{{"role": "user", "content": "hello"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !response.IsSuccess() {
		t.Fatalf("unexpected response: %#v", response)
	}
	if seen == nil || seen.URL.Path != "/v1/run" || seen.Header.Get("Authorization") != "Bearer secret-token" {
		t.Fatalf("unexpected request: %#v", seen)
	}
	if !strings.Contains(string(body), `"request_id":"request-1"`) {
		t.Fatalf("request id missing: %s", body)
	}
}

func TestRequestAndResponseBoundsFailClosed(t *testing.T) {
	client, err := NewClient("127.0.0.1", 1, "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Run("request-1", "lifecycle-1", map[string]string{"payload": strings.Repeat("x", MaxHTTPBodyBytes)}); codeOf(err) != ErrorInvalidRequest {
		t.Fatalf("oversized request: got %v", err)
	}
}

func TestResponseFramingAndTransportFailuresFailClosed(t *testing.T) {
	client, err := NewClient("127.0.0.1", 8080, "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var calls atomic.Int32
	client.http.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode:       http.StatusOK,
			Status:           "200 OK",
			Header:           http.Header{"Content-Type": []string{"application/json"}},
			TransferEncoding: []string{"chunked"},
			ContentLength:    2,
			Body:             io.NopCloser(strings.NewReader("{}")),
		}, nil
	})
	if err := client.Health(); codeOf(err) != ErrorInvalidResponse {
		t.Fatalf("chunked response: got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpected retry count: %d", calls.Load())
	}

	for _, response := range []*http.Response{
		{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Header:        http.Header{"Content-Type": []string{"application/json", "application/json"}},
			ContentLength: 2,
			Body:          io.NopCloser(strings.NewReader("{}")),
		},
		{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Header:        http.Header{"Content-Type": []string{"application/json"}},
			ContentLength: MaxRuntimeResponseBytes + 1,
			Body:          io.NopCloser(strings.NewReader("")),
		},
		{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Header:        http.Header{"Content-Type": []string{"application/json", strings.Repeat("x", MaxHTTPHeaderBytes)}},
			ContentLength: 2,
			Body:          io.NopCloser(strings.NewReader("{}")),
		},
	} {
		client.http.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return response, nil
		})
		if err := client.Health(); codeOf(err) != ErrorInvalidResponse && codeOf(err) != ErrorResponseTooLarge {
			t.Fatalf("malformed response: got %v", err)
		}
	}
}

func TestCloseWipesTokenAndRejectsCalls(t *testing.T) {
	client, err := NewClient("127.0.0.1", 8080, "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if !allZero(client.token) {
		t.Fatal("token was not wiped")
	}
	if err := client.Health(); codeOf(err) != ErrorClosed {
		t.Fatalf("closed client: got %v", err)
	}
}

func splitServerAddress(t *testing.T, server *httptest.Server) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatal(err)
	}
	return host, port
}

func codeOf(err error) ErrorCode {
	if err == nil {
		return ""
	}
	if value, ok := err.(*Error); ok {
		return value.Code
	}
	return ""
}

func allZero(value []byte) bool {
	for _, byteValue := range value {
		if byteValue != 0 {
			return false
		}
	}
	return true
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
