package http

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"leprechaun/vpn-configs/internal/application"
	"mime"
	"net/http"
	"net/url"
)

type ServerAPI struct {
	registry *application.ServerRegistry
	secret   string
}

func NewServerAPI(registry *application.ServerRegistry, secret string) *ServerAPI {
	return &ServerAPI{registry, secret}
}
func (a *ServerAPI) Register(mux *http.ServeMux) {
	for _, route := range []string{"POST /admin/vpn-servers", "GET /admin/vpn-servers", "GET /admin/vpn-servers/{server_id}", "PATCH /admin/vpn-servers/{server_id}"} {
		mux.HandleFunc(route, a.handle)
	}
}
func decodeServerBody(w http.ResponseWriter, r *http.Request, target any) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return application.ErrInvalid
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32*1024))
	if err != nil {
		return application.ErrInvalid
	}
	// Null and duplicate fields are rejected instead of silently preserving values.
	tokens := json.NewDecoder(bytes.NewReader(body))
	token, err := tokens.Token()
	if err != nil || token != json.Delim('{') {
		return application.ErrInvalid
	}
	seen := map[string]bool{}
	for tokens.More() {
		key, err := tokens.Token()
		if err != nil {
			return application.ErrInvalid
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return application.ErrInvalid
		}
		seen[name] = true
		var value json.RawMessage
		if tokens.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return application.ErrInvalid
		}
	}
	if _, err = tokens.Token(); err != nil {
		return application.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return application.ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return application.ErrInvalid
	}
	return nil
}
func (a *ServerAPI) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	expected := sha256.Sum256([]byte(a.secret))
	actual := sha256.Sum256([]byte(r.Header.Get("X-Service-Token")))
	if len(a.secret) < 32 || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
		apiError(w, 401, "service_auth_required")
		return
	}
	actor := r.Header.Get("X-Actor-ID")
	if err := a.registry.Authorize(r.Context(), actor); err != nil {
		serverError(w, err)
		return
	}
	var result any
	var err error
	status := 200
	switch r.Method {
	case "POST":
		var input application.ServerFields
		if decodeServerBody(w, r, &input) != nil {
			apiError(w, 400, "invalid_request")
			return
		}
		result, err = a.registry.Create(r.Context(), actor, input)
		status = 201
	case "PATCH":
		var input application.ServerPatch
		if decodeServerBody(w, r, &input) != nil {
			apiError(w, 400, "invalid_request")
			return
		}
		result, err = a.registry.Patch(r.Context(), actor, r.PathValue("server_id"), input)
	case "GET":
		if r.PathValue("server_id") == "" {
			result, err = a.registry.List(r.Context(), actor)
		} else {
			result, err = a.registry.Get(r.Context(), actor, r.PathValue("server_id"))
		}
	}
	if err != nil {
		serverError(w, err)
		return
	}
	if status == 201 {
		item := result.(application.ServerView)
		w.Header().Set("Location", "/admin/vpn-servers/"+url.PathEscape(item.ID))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
}
func serverError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, application.ErrForbidden):
		apiError(w, 403, "admin_required")
	case errors.Is(err, application.ErrNotFound):
		apiError(w, 404, "not_found")
	case errors.Is(err, application.ErrConflict):
		apiError(w, 409, "revision_conflict")
	case errors.Is(err, application.ErrInvalid):
		apiError(w, 400, "invalid_request")
	default:
		apiError(w, 503, "dependency_unavailable")
	}
}
