package http

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"leprechaun/vpn-configs/internal/application"
	"mime"
	"net/http"
)

func (a *BatchAPI) registerOwnConfigs(mux *http.ServeMux) {
	for _, pattern := range []string{"GET /me/configs", "GET /me/configs/{config_id}/download"} {
		mux.HandleFunc(pattern, a.ownConfigs)
	}
}
func (a *BatchAPI) ownConfigs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	expected := sha256.Sum256([]byte(a.secret))
	actual := sha256.Sum256([]byte(r.Header.Get("X-Service-Token")))
	if len(a.secret) < 32 || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
		apiError(w, 401, "service_auth_required")
		return
	}
	owner := r.Header.Get("X-Actor-ID")
	var result any
	var file []byte
	var err error
	if r.Pattern == "GET /me/configs" {
		result, err = a.manager.OwnConfigs(r.Context(), owner)
	} else {
		file, err = a.manager.OwnDownload(r.Context(), owner, r.PathValue("config_id"))
	}
	if err != nil {
		if errors.Is(err, application.ErrNotFound) || errors.Is(err, application.ErrForbidden) {
			apiError(w, 404, "not_found")
		} else {
			apiError(w, 503, "dependency_unavailable")
		}
		return
	}
	if r.Pattern == "GET /me/configs" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "config-" + r.PathValue("config_id") + ".conf"}))
	_, _ = w.Write(file)
}
