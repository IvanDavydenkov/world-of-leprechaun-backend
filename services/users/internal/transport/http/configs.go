package http

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"leprechaun/users/internal/application"
	"leprechaun/users/internal/domain"
	"mime"
	"net/http"
	"net/url"
)

func (a *Auth) RegisterConfigRoutes(mux *http.ServeMux, gateway application.ConfigGateway) {
	a.configGateway = gateway
	a.registerOwnConfigs(mux)
	for _, pattern := range []string{
		"POST /admin/vpn-servers",
		"GET /admin/vpn-servers",
		"GET /admin/vpn-servers/{server_id}",
		"PATCH /admin/vpn-servers/{server_id}",
		"POST /admin/users/{user_id}/configs",
		"DELETE /admin/users/{user_id}/configs/{config_id}",
		"POST /admin/users/{user_id}/configs/bulk-delete",
		"DELETE /admin/users/{user_id}/configs",
		"GET /admin/users/{user_id}/config-operations/{operation_id}",
	} {
		mux.HandleFunc(pattern, noStore(func(w http.ResponseWriter, r *http.Request) {
			actor, err := a.current(r)
			if err != nil {
				authError(w, err)
				return
			}
			if actor.Role != domain.RoleAdmin {
				problem(w, 403, "admin_required")
				return
			}
			if r.Method != "GET" && r.Header.Get("Origin") != a.origin {
				problem(w, 403, "invalid_origin")
				return
			}
			if gateway == nil {
				problem(w, 503, "vpn_unavailable")
				return
			}
			if r.Method == http.MethodPost || r.Method == http.MethodPatch {
				media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil || media != "application/json" {
					problem(w, 400, "invalid_content_type")
					return
				}
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32*1024))
			if err != nil {
				problem(w, 400, "invalid_body")
				return
			}
			response, err := gateway.Forward(r.Context(), actor.ID, r.Method, r.URL.EscapedPath(), r.Header.Get("Idempotency-Key"), body)
			if err != nil {
				problem(w, 503, "vpn_unavailable")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if response.Location != "" {
				w.Header().Set("Location", response.Location)
			}
			w.WriteHeader(response.Status)
			_, _ = w.Write(response.Body)
		}))
	}
}

// Internal directory is not browser-authenticated: only a trusted peer service
// may resolve stored identities. Roles are derived from current configuration.
func (a *Auth) RegisterInternal(mux *http.ServeMux, token string) {
	expected := sha256.Sum256([]byte(token))
	mux.HandleFunc("GET /internal/users/{user_id}", noStore(func(w http.ResponseWriter, r *http.Request) {
		actual := sha256.Sum256([]byte(r.Header.Get("X-Service-Token")))
		if len(token) < 32 || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
			problem(w, 401, "service_auth_required")
			return
		}
		id, err := url.PathUnescape(r.PathValue("user_id"))
		if err != nil {
			problem(w, 400, "invalid_id")
			return
		}
		user, err := a.directory.Resolve(r.Context(), id)
		if err != nil {
			authError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			ID   string      `json:"id"`
			Role domain.Role `json:"role"`
		}{user.ID, user.Role})
	}))
}
