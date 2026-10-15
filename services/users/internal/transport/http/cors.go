package http

import (
	"net/http"
	"strings"
)

// WithFrontendCORS permits credentialed requests only from the configured origin.
func WithFrontendCORS(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		requestOrigin := r.Header.Get("Origin")
		if requestOrigin == "" {
			next.ServeHTTP(w, r)
			return
		}
		if origin == "" || origin == "*" || requestOrigin != origin {
			problem(w, 403, "invalid_origin")
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition, Location, X-Next-Cursor")
		if r.Method == "OPTIONS" && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")
			switch r.Header.Get("Access-Control-Request-Method") {
			case "GET", "POST", "PATCH", "PUT", "DELETE":
			default:
				problem(w, 403, "invalid_cors_method")
				return
			}
			for _, h := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
				switch strings.ToLower(strings.TrimSpace(h)) {
				case "", "content-type", "idempotency-key":
				default:
					problem(w, 403, "invalid_cors_header")
					return
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Idempotency-Key")
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}
