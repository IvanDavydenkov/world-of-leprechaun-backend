package http

import (
	"net/http"
	"net/url"
)

func (a *Auth) registerOwnConfigs(mux *http.ServeMux) {
	for _, pattern := range []string{"GET /me/configs", "GET /me/configs/{config_id}/download"} {
		mux.HandleFunc(pattern, noStore(a.ownConfigs))
	}
}
func (a *Auth) ownConfigs(w http.ResponseWriter, r *http.Request) {
	actor, err := a.current(r)
	if err != nil {
		authError(w, err)
		return
	}
	if a.configGateway == nil {
		problem(w, 503, "vpn_unavailable")
		return
	}
	path := "/me/configs"
	if r.Pattern != "GET /me/configs" {
		path += "/" + url.PathEscape(r.PathValue("config_id")) + "/download"
	}
	response, err := a.configGateway.Forward(r.Context(), actor.ID, http.MethodGet, path, "", nil)
	if err != nil {
		problem(w, 503, "vpn_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if response.Status == 200 && r.Pattern != "GET /me/configs" {
		if response.ContentType != "application/octet-stream" || response.Disposition == "" {
			problem(w, 503, "invalid_vpn_response")
			return
		}
		w.Header().Set("Content-Type", response.ContentType)
		w.Header().Set("Content-Disposition", response.Disposition)
	}
	w.WriteHeader(response.Status)
	_, _ = w.Write(response.Body)
}
