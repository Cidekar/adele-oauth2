package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"slices"
	"strings"
)

func (o *Service) AuthenticationTokenMiddleware() func(next http.Handler) http.Handler {
	return BearerTokenHandler(o.Config.UnguardedRoutes, o.Config.GuardedRouteGroups, o.ErrorLog, o)
}

func (o *Service) AuthenticationCheckForScopes() func(next http.Handler) http.Handler {
	return ScopeHandler(o.Config.UnguardedRoutes, o.Config.GuardedRouteGroups, o.ErrorLog, o)
}

// authenticate the bearer token attached to a HTTP request is a valid token by getting it by the plain text value from the db and checking that is not expired. Valid tokens are added to the context of the request as an access token for use by other middleware deeper in the stack. The middleware is designed for use in the global stack, so it is going to get loaded on every request, as a result the  the guarded route groups are first checked and quickly passed to the next middleware if the path is not in a guarded group.
func BearerTokenHandler(unguardedRoute []string, GuardedRouteGroups []string, ErrorLogger *log.Logger, o *Service) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {

			if len(GuardedRouteGroups) == 0 {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			if !isProtectedBaseRoute(r.URL.Path, GuardedRouteGroups) {
				next.ServeHTTP(w, r)
				return
			}

			unguarded := false
			for _, route := range unguardedRoute {
				if r.URL.Path == route {
					unguarded = true
					break
				}
			}

			if unguarded {
				next.ServeHTTP(w, r)
				return
			}

			ok, token, err := o.AuthenticateToken(r)
			if err != nil || !ok {
				// Browser-friendly UX path: an UNAUTHENTICATED non-JSON caller
				// (e.g. a user navigating to a guarded URL in a browser) is
				// redirected to the site root instead of receiving a raw JSON
				// 401 payload. JSON callers (Accept: application/json) get the
				// standard ErrInvalidClient envelope. Authenticated requests
				// fall through to context stamping below regardless of Accept.
				if r.Header.Get("Accept") != "application/json" {
					http.Redirect(w, r, "/", http.StatusSeeOther)
					return
				}
				if writeErr := writeJSON(w, StatusCodes[ErrInvalidClient], Descriptions[ErrInvalidClient]); writeErr != nil {
					ErrorLogger.Println(writeErr)
				}
				return
			}

			ctx := r.Context()
			if client, err := o.GetClient(token.ClientID); err == nil && client != nil {
				ctx = context.WithValue(ctx, ContextKeyClientID, client.ID)
				ctx = context.WithValue(ctx, ContextKeyClientName, client.Name)
			}
			ctx = context.WithValue(ctx, ContextKeyAccessToken, token.PlainText)
			// Backward-compat: the legacy bare-string key "accessToken" is
			// stamped alongside the typed ContextKeyAccessToken for one major
			// release. ScopeHandler (this package) and external consumers
			// historically read r.Context().Value("accessToken").(string);
			// removing the legacy stamping silently breaks every caller that
			// has not yet migrated. The typed ContextKeyAccessToken is the
			// canonical reader path and should be preferred for new code.
			// Remove this line one major release after all known consumers
			// have migrated to the typed key.
			ctx = context.WithValue(ctx, "accessToken", token.PlainText)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}

// write a JSON response to the client
func writeJSON(w http.ResponseWriter, status int, data interface{}) error {
	out, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(out)
	if err != nil {
		return err
	}
	return nil
}

// check if the path is part of a protected route group set in the configuration
func isProtectedBaseRoute(path string, groups []string) bool {
	for _, route := range groups {
		if strings.Contains(path, route) {
			return true
		}
	}
	return false
}

// look up the scopes assigned to the current route and confirm the access token passed in the http request has the same scopes assigned to the token.
func ScopeHandler(UnguardedRoutes []string, GuardedRouteGroups []string, ErrorLogger *log.Logger, o *Service) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {

			if !isProtectedBaseRoute(r.URL.Path, GuardedRouteGroups) {
				next.ServeHTTP(w, r)
				return
			}

			for _, route := range UnguardedRoutes {
				if r.URL.Path == route {
					next.ServeHTTP(w, r)
					return
				}
			}

			tid, ok := r.Context().Value("accessToken").(string)
			if !ok {
				err := writeJSON(w, StatusCodes[ErrAccessDenied], Descriptions[ErrAccessDenied])
				if err != nil {
					ErrorLogger.Println(err)
					return
				}
				return
			}

			token, err := o.GetByToken(tid)
			if err != nil {
				err := writeJSON(w, StatusCodes[ErrAccessDenied], Descriptions[ErrAccessDenied])
				if err != nil {
					ErrorLogger.Println(err)
					return
				}
				return
			}

			muxRouteScope := o.Mux.GetScopes(r.URL.Path)
			if len(muxRouteScope.Scope) != 0 {
				for _, s := range muxRouteScope.Scope {
					if !slices.Contains(strings.Split(token.Scopes, " "), strings.TrimSpace(s)) {
						err := writeJSON(w, StatusCodes[ErrAccessDenied], Descriptions[ErrAccessDenied])
						if err != nil {
							ErrorLogger.Println(err)
							return
						}
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
