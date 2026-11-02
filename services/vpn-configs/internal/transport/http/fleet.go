package http

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/domain"
	"net/http"
	"net/url"
	"strconv"
)

type FleetAPI struct {
	fleet  *application.Fleet
	secret string
}

func NewFleetAPI(f *application.Fleet, secret string) *FleetAPI { return &FleetAPI{f, secret} }
func (a *FleetAPI) Register(mux *http.ServeMux) {
	for _, route := range []string{"GET /admin/vpn-routing", "POST /admin/vpn-servers/{server_id}/prepare", "POST /admin/vpn-switches", "POST /admin/vpn-revocations", "GET /admin/vpn-server-operations", "GET /admin/vpn-server-operations/{operation_id}", "GET /admin/vpn-server-operations/{operation_id}/items", "POST /admin/vpn-server-operations/{operation_id}/resume", "POST /admin/vpn-server-operations/{operation_id}/retry"} {
		mux.HandleFunc(route, a.handle)
	}
}
func (a *FleetAPI) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	expected := sha256.Sum256([]byte(a.secret))
	actual := sha256.Sum256([]byte(r.Header.Get("X-Service-Token")))
	if len(a.secret) < 32 || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
		apiError(w, 401, "service_auth_required")
		return
	}
	actor := r.Header.Get("X-Actor-ID")
	if err := a.fleet.Access.RequireAdmin(r.Context(), actor); err != nil {
		serverError(w, err)
		return
	}
	var result any
	var err error
	if r.Method == "GET" {
		switch r.Pattern {
		case "GET /admin/vpn-routing":
			result, err = a.fleet.Routing(r.Context(), actor)
		case "GET /admin/vpn-server-operations":
			var list []domain.FleetOperation
			list, err = a.fleet.Operations(r.Context(), actor)
			if err == nil {
				result, err = operationPage(r, list)
			}
		case "GET /admin/vpn-server-operations/{operation_id}/items":
			var o domain.FleetOperation
			o, err = a.fleet.Status(r.Context(), actor, r.PathValue("operation_id"))
			if err == nil {
				result, err = itemPage(r, o.Items)
			}
		default:
			result, err = a.fleet.Status(r.Context(), actor, r.PathValue("operation_id"))
		}
	} else {
		key := r.Header.Get("Idempotency-Key")
		switch r.Pattern {
		case "POST /admin/vpn-servers/{server_id}/prepare":
			var in struct {
				Revision int64 `json:"expected_revision"`
			}
			err = decodeServerBody(w, r, &in)
			if err == nil {
				result, err = a.fleet.SubmitPrepare(r.Context(), actor, r.PathValue("server_id"), key, in.Revision)
			}
		case "POST /admin/vpn-switches":
			var in struct {
				Target   string `json:"target_server_id"`
				Revision int64  `json:"expected_routing_revision"`
			}
			err = decodeServerBody(w, r, &in)
			if err == nil {
				result, err = a.fleet.SubmitSwitch(r.Context(), actor, key, in.Target, in.Revision)
			}
		case "POST /admin/vpn-revocations":
			var in application.RevokeRequest
			err = decodeServerBody(w, r, &in)
			if err == nil {
				result, err = a.fleet.SubmitRevoke(r.Context(), actor, key, in)
			}
		case "POST /admin/vpn-server-operations/{operation_id}/resume":
			var in struct {
				Revision  int64            `json:"expected_revision"`
				Selection domain.Selection `json:"selection"`
			}
			err = decodeServerBody(w, r, &in)
			if err == nil {
				result, err = a.fleet.Command(r.Context(), actor, r.PathValue("operation_id"), key, "resume", in.Revision, in.Selection)
			}
		default:
			var in struct{}
			err = decodeServerBody(w, r, &in)
			if err == nil {
				result, err = a.fleet.Command(r.Context(), actor, r.PathValue("operation_id"), key, "retry", 0, domain.Selection{})
			}
		}
	}
	if err != nil {
		serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "GET" {
		o := result.(domain.FleetOperation)
		w.Header().Set("Location", "/admin/vpn-server-operations/"+url.PathEscape(o.ID))
		w.WriteHeader(202)
	}
	_ = json.NewEncoder(w).Encode(result)
}
func pageParams(r *http.Request, defaultLimit int) (int, string, error) {
	limit := defaultLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			return 0, "", application.ErrInvalid
		}
	}
	after := ""
	if raw := r.URL.Query().Get("after"); raw != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || !application.ValidID(string(decoded)) {
			return 0, "", application.ErrInvalid
		}
		after = string(decoded)
	}
	return limit, after, nil
}
func operationPage(r *http.Request, items []domain.FleetOperation) (any, error) {
	limit, after, err := pageParams(r, 20)
	if err != nil {
		return nil, err
	}
	start := 0
	if after != "" {
		start = -1
		for i, item := range items {
			if item.ID == after {
				start = i + 1
				break
			}
		}
		if start < 0 {
			return nil, application.ErrInvalid
		}
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	var next *string
	if end < len(items) {
		value := base64.RawURLEncoding.EncodeToString([]byte(items[end-1].ID))
		next = &value
	}
	return struct {
		Items []domain.FleetOperation `json:"items"`
		Next  *string                 `json:"next_cursor"`
	}{append([]domain.FleetOperation{}, items[start:end]...), next}, nil
}
func itemPage(r *http.Request, items []domain.FleetItem) (any, error) {
	limit, after, err := pageParams(r, 50)
	if err != nil {
		return nil, err
	}
	start := 0
	if after != "" {
		start = -1
		for i, item := range items {
			if item.ID == after {
				start = i + 1
				break
			}
		}
		if start < 0 {
			return nil, application.ErrInvalid
		}
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	var next *string
	if end < len(items) {
		value := base64.RawURLEncoding.EncodeToString([]byte(items[end-1].ID))
		next = &value
	}
	return struct {
		Items []domain.FleetItem `json:"items"`
		Next  *string            `json:"next_cursor"`
	}{append([]domain.FleetItem{}, items[start:end]...), next}, nil
}
