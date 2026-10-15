package http

import (
	"context"
	"leprechaun/users/internal/domain"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServerRoutesRequireAdminSessionAndOrigin(t *testing.T) {
	a, store, _, directory, _ := setupAuth(t)
	g := &gatewayStub{}
	router := NewRouter(func(context.Context) error { return nil }, a.Register, func(mux *http.ServeMux) { a.RegisterConfigRoutes(mux, g) })
	store.SaveSession(context.Background(), HashCredential("session"), "user", time.Now().Add(time.Hour))
	for _, tc := range []struct{ method, path string }{{"POST", "/admin/vpn-servers"}, {"GET", "/admin/vpn-servers"}, {"GET", "/admin/vpn-servers/id"}, {"PATCH", "/admin/vpn-servers/id"}} {
		call := func(session bool, role domain.Role, origin string) *httptest.ResponseRecorder {
			directory.role = role
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", origin)
			r.Header.Set("X-Actor-ID", "forged")
			if session {
				r.AddCookie(&http.Cookie{Name: "leprechaun_session", Value: "session"})
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			return w
		}
		if w := call(false, domain.RoleAdmin, a.origin); w.Code != 401 {
			t.Fatal(w.Code)
		}
		if w := call(true, domain.RoleUser, a.origin); w.Code != 403 {
			t.Fatal(w.Code)
		}
		if tc.method != "GET" {
			if w := call(true, domain.RoleAdmin, "https://evil.example"); w.Code != 403 {
				t.Fatal(w.Code)
			}
		}
		if w := call(true, domain.RoleAdmin, a.origin); w.Code != 202 || g.actor != "user" || g.path != tc.path {
			t.Fatal(w.Code, g.actor, g.path)
		}
	}
}
