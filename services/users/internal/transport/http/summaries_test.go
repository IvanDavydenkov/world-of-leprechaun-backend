package http

import (
	"context"
	"encoding/json"
	"errors"
	"leprechaun/users/internal/application"
	"leprechaun/users/internal/domain"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type summaryDirectory struct{ authDirectory }

func (d *summaryDirectory) List(context.Context, string, string, int) ([]domain.User, error) {
	return []domain.User{{ID: "user", DisplayName: "Name", Role: domain.RoleUser}}, nil
}

type summaryGateway struct{ fail bool }

func (g *summaryGateway) Forward(_ context.Context, actor, method, path, key string, body []byte) (application.ConfigResponse, error) {
	if g.fail {
		return application.ConfigResponse{}, errors.New("offline")
	}
	if actor != "user" || method != "POST" || path != "/admin/users/config-summaries" {
		return application.ConfigResponse{}, errors.New("bad request")
	}
	return application.ConfigResponse{Status: 200, Body: []byte(`{"user":{"availability":"available","counts":{"total":1,"active":1,"disabled":0,"pending":0},"configs":[{"id":"cfg","name":"Phone","status":"active","version":1}],"traffic":{"freshness":"unavailable","coverage":"unknown"}}}`)}, nil
}
func TestAdminUsersIncludesVPNAndReportsUnavailable(t *testing.T) {
	a, store, _, _, _ := setupAuth(t)
	a.directory = &summaryDirectory{authDirectory{role: domain.RoleAdmin}}
	g := &summaryGateway{}
	a.configGateway = g
	store.SaveSession(context.Background(), HashCredential("test-session"), "user", time.Now().Add(time.Hour))
	router := NewRouter(func(context.Context) error { return nil }, a.Register)
	for _, fail := range []bool{false, true} {
		g.fail = fail
		r := httptest.NewRequest("GET", "/admin/users?limit=50", nil)
		r.AddCookie(&http.Cookie{Name: "leprechaun_session", Value: "test-session"})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		var result []struct {
			VPN application.ConfigSummary `json:"vpn"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result) != 1 {
			t.Fatal(w.Body.String())
		}
		if fail {
			if result[0].VPN.Availability != "unavailable" || result[0].VPN.Counts != nil {
				t.Fatal(w.Body.String())
			}
		} else {
			if result[0].VPN.Counts.Active != 1 || result[0].VPN.Configs[0].ID != "cfg" {
				t.Fatal(w.Body.String())
			}
		}
	}
}
