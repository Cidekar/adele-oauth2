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

// TestOauth_HasFormField verifies that hasFormField reports presence of
// arbitrary form fields and, for the formFieldScope sentinel, treats
// either "scope" (RFC) or "scopes" (legacy) as satisfying the gate.
func TestOauth_HasFormField(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		field string
		want  bool
	}{
		{
			name:  "sentinel: only scope set returns true",
			body:  url.Values{"scope": {"read"}}.Encode(),
			field: formFieldScope,
			want:  true,
		},
		{
			name:  "sentinel: only scopes set returns true",
			body:  url.Values{"scopes": {"read"}}.Encode(),
			field: formFieldScope,
			want:  true,
		},
		{
			name:  "sentinel: neither set returns false",
			body:  "",
			field: formFieldScope,
			want:  false,
		},
		{
			name:  "sentinel: both set returns true",
			body:  url.Values{"scope": {"read"}, "scopes": {"read"}}.Encode(),
			field: formFieldScope,
			want:  true,
		},
		{
			name:  "non-sentinel: field set returns true",
			body:  url.Values{"client_id": {"1"}}.Encode(),
			field: "client_id",
			want:  true,
		},
		{
			name:  "non-sentinel: field absent returns false",
			body:  "",
			field: "client_id",
			want:  false,
		},
		{
			name:  "non-sentinel: empty value still has-presence",
			body:  url.Values{"client_id": {""}}.Encode(),
			field: "client_id",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/token", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := req.ParseForm(); err != nil {
				t.Fatalf("ParseForm failed: %v", err)
			}

			got := hasFormField(req, tt.field)
			if got != tt.want {
				t.Errorf("hasFormField(%q) = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}

// TestOauth_FormFieldNonEmpty verifies that formFieldNonEmpty requires
// a non-empty (non-whitespace) value, and that for the formFieldScope
// sentinel either "scope" or "scopes" can satisfy the gate (with the
// formScope precedence: "scope" preferred, "scopes" as fallback).
func TestOauth_FormFieldNonEmpty(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		field string
		want  bool
	}{
		{
			name:  "sentinel: scope=value returns true",
			body:  url.Values{"scope": {"read"}}.Encode(),
			field: formFieldScope,
			want:  true,
		},
		{
			name:  "sentinel: scopes=value returns true (legacy)",
			body:  url.Values{"scopes": {"read"}}.Encode(),
			field: formFieldScope,
			want:  true,
		},
		{
			name:  "sentinel: scope empty + scopes=value falls back to scopes",
			body:  url.Values{"scope": {""}, "scopes": {"read"}}.Encode(),
			field: formFieldScope,
			want:  true,
		},
		{
			name:  "sentinel: both empty returns false",
			body:  url.Values{"scope": {""}, "scopes": {""}}.Encode(),
			field: formFieldScope,
			want:  false,
		},
		{
			name:  "sentinel: both whitespace returns false",
			body:  url.Values{"scope": {"   "}, "scopes": {" "}}.Encode(),
			field: formFieldScope,
			want:  false,
		},
		{
			name:  "sentinel: neither set returns false",
			body:  "",
			field: formFieldScope,
			want:  false,
		},
		{
			name:  "non-sentinel: field=value returns true",
			body:  url.Values{"client_id": {"42"}}.Encode(),
			field: "client_id",
			want:  true,
		},
		{
			name:  "non-sentinel: field=whitespace returns false",
			body:  url.Values{"client_id": {"   "}}.Encode(),
			field: "client_id",
			want:  false,
		},
		{
			name:  "non-sentinel: field absent returns false",
			body:  "",
			field: "client_id",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/token", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := req.ParseForm(); err != nil {
				t.Fatalf("ParseForm failed: %v", err)
			}

			got := formFieldNonEmpty(req, tt.field)
			if got != tt.want {
				t.Errorf("formFieldNonEmpty(%q) = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}
