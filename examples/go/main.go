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

package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/ECD5A/Tkach-Security/sdk/go/tkachclient"
)

func main() {
	token := os.Getenv("TKACH_BEARER_TOKEN")
	if token == "" {
		fail("TKACH_BEARER_TOKEN must be set in trusted host configuration")
	}
	port := 8080
	if value := os.Getenv("TKACH_HTTP_PORT"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			fail("TKACH_HTTP_PORT must be an integer")
		}
		port = parsed
	}
	client, err := tkachclient.NewClient("127.0.0.1", port, token)
	if err != nil {
		fail(err.Error())
	}
	defer client.Close()
	if err := client.Health(); err != nil {
		fail(err.Error())
	}
	response, err := client.Run("example-go-1", "example-go-lifecycle", map[string]any{
		"messages":          []map[string]string{{"role": "user", "content": "hello from Go"}},
		"metadata":          []any{},
		"tool_declarations": []any{},
	})
	if err != nil {
		fail(err.Error())
	}
	fmt.Printf("HTTP %d\n%s\n", response.StatusCode, response.Body)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
