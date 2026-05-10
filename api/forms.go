package api

import (
	"net/http"
	"strings"
)

// formScope returns the requested scope string from the OAuth request form.
// RFC 6749 §3.3 / §4.4.2 specify the parameter name as "scope" (singular)
// containing a space-delimited list. Earlier versions of this package read
// only "scopes"; the legacy plural is accepted as a fallback so existing
// clients continue to work. Prefer "scope" in new clients.
func formScope(r *http.Request) string {
	if v := r.Form.Get("scope"); v != "" {
		return v
	}
	return r.Form.Get("scopes")
}

// formFieldScope is a sentinel used in required-field lists to mean
// "the OAuth scope parameter, by either RFC-6749 name". Gate loops
// must special-case this sentinel and accept either "scope" (RFC) or
// "scopes" (legacy) as satisfying the requirement.
const formFieldScope = "scope|scopes"

// hasFormField reports whether the named form field is present on r.
// The sentinel formFieldScope matches when either "scope" or "scopes"
// is present, supporting RFC 6749 §3.3 / §4.4.2 and our legacy plural.
func hasFormField(r *http.Request, name string) bool {
	if name == formFieldScope {
		return r.Form.Has("scope") || r.Form.Has("scopes")
	}
	return r.Form.Has(name)
}

// formFieldNonEmpty reports whether the named form field has a non-empty
// value on r (whitespace-only values are treated as empty, matching the
// existing TrimSpace gate semantics). The sentinel formFieldScope is
// satisfied if either "scope" or "scopes" carries a non-empty value
// (formScope handles the precedence).
func formFieldNonEmpty(r *http.Request, name string) bool {
	if name == formFieldScope {
		return strings.TrimSpace(formScope(r)) != ""
	}
	return strings.TrimSpace(r.Form.Get(name)) != ""
}
