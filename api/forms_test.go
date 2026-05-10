package api

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestOauth_FormScope verifies that formScope reads RFC 6749 §3.3 / §4.4.2
// "scope" (singular) first, falls back to the legacy "scopes" (plural)
// parameter, and prefers the RFC name when both are present.
func TestOauth_FormScope(t *testing.T) {

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "both empty returns empty",
			body: "",
			want: "",
		},
		{
			name: "only scope (singular, RFC) returns its value",
			body: url.Values{"scope": {"ping pong"}}.Encode(),
			want: "ping pong",
		},
		{
			name: "only scopes (plural, legacy) returns its value",
			body: url.Values{"scopes": {"ping pong"}}.Encode(),
			want: "ping pong",
		},
		{
			name: "both set; RFC scope wins",
			body: url.Values{"scope": {"ping"}, "scopes": {"pong"}}.Encode(),
			want: "ping",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/token", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := req.ParseForm(); err != nil {
				t.Fatalf("ParseForm failed: %v", err)
			}

			got := formScope(req)
			if got != tt.want {
				t.Errorf("formScope() = %q, want %q", got, tt.want)
			}
		})
	}
}
