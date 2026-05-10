package api

import "net/http"

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
