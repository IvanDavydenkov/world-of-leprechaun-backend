package http

import (
	"context"
	"leprechaun/users/internal/application"
	"leprechaun/users/internal/domain"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type ownGateway struct{ actor, path string }

func (g *ownGateway) Forward(_ context.Context, actor, method, path, key string, body []byte) (application.ConfigResponse, error) {
	g.actor = actor
	g.path = path
	if path == "/me/configs" {
		return application.ConfigResponse{Status: 200, Body: []byte("[]")}, nil
	}
	return application.ConfigResponse{Status: 200, Body: []byte("private-config"), ContentType: "application/octet-stream", Disposition: `attachment; filename=config-own.conf`}, nil
}
func TestOwnRoutesUseSessionIdentity(t *testing.T) {
	a, store, _, directory, _ := setupAuth(t)
	g := &ownGateway{}
	router := NewRouter(func(context.Context) error { return nil }, a.Register, func(mux *http.ServeMux) { a.RegisterConfigRoutes(mux, g) })
	store.SaveSession(context.Background(), HashCredential("session"), "user", time.Now().Add(time.Hour))
	for _, role := range []domain.Role{domain.RoleUser, domain.RoleAdmin} {
		directory.role = role
		for _, path := range []string{"/me/configs?user_id=other", "/me/configs/own/download?owner_id=other"} {
			req := httptest.NewRequest("GET", path, nil)
			req.Header.Set("X-Actor-ID", "other")
			req.Header.Set("X-Service-Token", "forged")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != 401 {
				t.Fatal(w.Code)
			}
			req.AddCookie(&http.Cookie{Name: "leprechaun_session", Value: "session"})
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != 200 || g.actor != "user" {
				t.Fatal(w.Code, g.actor)
			}
			if path != "/me/configs?user_id=other" && (w.Body.String() != "private-config" || w.Header().Get("Content-Disposition") == "" || w.Header().Get("Cache-Control") != "no-store") {
				t.Fatal("file response incorrect")
			}
		}
	}
}
