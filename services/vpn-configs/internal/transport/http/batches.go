package http

import (
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

type BatchAPI struct {
	manager *application.Manager
	secret  string
}

func NewBatchAPI(manager *application.Manager, secret string) *BatchAPI {
	return &BatchAPI{manager: manager, secret: secret}
}
func (a *BatchAPI) Register(mux *http.ServeMux) {
	a.registerOwnConfigs(mux)
	for _, route := range []string{"POST /admin/users/{user_id}/configs", "DELETE /admin/users/{user_id}/configs/{config_id}", "POST /admin/users/{user_id}/configs/bulk-delete", "DELETE /admin/users/{user_id}/configs", "GET /admin/users/{user_id}/config-operations/{operation_id}"} {
		mux.HandleFunc(route, a.handle)
	}
	mux.HandleFunc("POST /admin/users/config-summaries", a.handle)
}
func apiError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
func (a *BatchAPI) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	expected := sha256.Sum256([]byte(a.secret))
	actual := sha256.Sum256([]byte(r.Header.Get("X-Service-Token")))
	if len(a.secret) < 32 || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
		apiError(w, 401, "service_auth_required")
		return
	}
	actor, owner := r.Header.Get("X-Actor-ID"), r.PathValue("user_id")
	if err := a.manager.AuthorizeAdmin(r.Context(), actor); err != nil {
		if errors.Is(err, application.ErrForbidden) || errors.Is(err, application.ErrNotFound) {
			apiError(w, 403, "admin_required")
		} else {
			apiError(w, 503, "identity_unavailable")
		}
		return
	}
	if r.Pattern == "POST /admin/users/config-summaries" {
		var input struct {
			UserIDs []string `json:"user_ids"`
		}
		if decodeBody(w, r, &input) != nil {
			apiError(w, 400, "invalid_request")
			return
		}
		result, err := a.manager.ConfigSummaries(r.Context(), actor, input.UserIDs)
		if err != nil {
			if errors.Is(err, application.ErrInvalid) {
				apiError(w, 400, "invalid_request")
			} else {
				apiError(w, 503, "dependency_unavailable")
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
		return
	}
	var result application.BatchResult
	var err error
	if r.Method == http.MethodGet {
		result, err = a.manager.BatchStatus(r.Context(), actor, owner, r.PathValue("operation_id"))
	} else {
		request := application.BatchRequest{}
		switch {
		case r.Method == http.MethodPost && r.Pattern == "POST /admin/users/{user_id}/configs":
			request.Scope = "create"
			var body struct {
				Count int `json:"count"`
			}
			err = decodeBody(w, r, &body)
			request.Count = body.Count
		case r.Method == http.MethodPost:
			request.Scope = "selected"
			var body struct {
				IDs []string `json:"config_ids"`
			}
			err = decodeBody(w, r, &body)
			request.ConfigIDs = body.IDs
		case r.PathValue("config_id") != "":
			request.Scope = "single"
			request.ConfigIDs = []string{r.PathValue("config_id")}
			err = emptyBody(r)
		default:
			request.Scope = "all"
			err = emptyBody(r)
		}
		if err == nil {
			result, err = a.manager.SubmitBatch(r.Context(), actor, owner, r.Header.Get("Idempotency-Key"), request)
		}
	}
	if err != nil {
		switch {
		case errors.Is(err, application.ErrInvalid):
			apiError(w, 400, "invalid_request")
		case errors.Is(err, application.ErrForbidden):
			apiError(w, 403, "admin_required")
		case errors.Is(err, application.ErrNotFound):
			apiError(w, 404, "not_found")
		case errors.Is(err, application.ErrConflict):
			apiError(w, 409, "operation_conflict")
		default:
			apiError(w, 503, "dependency_unavailable")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.Header().Set("Location", "/admin/users/"+url.PathEscape(owner)+"/config-operations/"+url.PathEscape(result.ID))
		w.WriteHeader(http.StatusAccepted)
	}
	_ = json.NewEncoder(w).Encode(result)
}
func decodeBody(w http.ResponseWriter, r *http.Request, target any) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return application.ErrInvalid
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024))
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
func emptyBody(r *http.Request) error {
	content, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil || len(content) > 0 {
		return application.ErrInvalid
	}
	return nil
}
