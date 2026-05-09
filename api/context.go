package api

// contextKey is the unexported context key type for adele-oauth2 values.
// Using a private struct (not a string) prevents key collisions with other
// packages that use the same string literal.
type contextKey struct{ name string }

func (k contextKey) String() string { return "adele-oauth2:" + k.name }

var (
	// ContextKeyAccessToken is the plaintext bearer token, populated by
	// BearerTokenHandler after successful token validation. Promoted to a
	// typed key for type-safe consumer access; the legacy string key
	// "accessToken" is still set for one major release for backward compat.
	ContextKeyAccessToken = contextKey{name: "access-token"}

	// ContextKeyClientID is the integer ID of the authenticated oauth_clients
	// row, populated by BearerTokenHandler after successful token validation.
	ContextKeyClientID = contextKey{name: "client-id"}

	// ContextKeyClientName is the human-readable name of the authenticated
	// oauth_clients row (oauth_clients.name), populated by BearerTokenHandler
	// after successful token validation. Consumers use this for per-client
	// audit logging, multi-tenant routing, or vendor attribution on outbound
	// calls.
	ContextKeyClientName = contextKey{name: "client-name"}
)
