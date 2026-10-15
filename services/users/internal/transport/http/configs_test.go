package http

import (
	"context"
	"leprechaun/users/internal/application"
	"leprechaun/users/internal/domain"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type gatewayStub struct {
	calls            int
	actor, path, key string
}

func (g *gatewayStub) Forward(_ context.Context, actor, method, path, key string, body []byte) (application.ConfigResponse, error) {
	g.calls++
	g.actor = actor
	g.path = path
	g.key = key
	return application.ConfigResponse{Status: 202, Body: []byte("{\"operation_id\":\"op\"}"), Location: "/admin/users/target/config-operations/op"}, nil
}
func TestConfigGatewayRequiresCurrentAdminAndOrigin(t *testing.T) {
	auth, _, _, directory, _ := setupAuth(t)
	gateway := &gatewayStub{}
	router := NewRouter(func(context.Context) error { return nil }, auth.Register, func(mux *http.ServeMux) { auth.RegisterConfigRoutes(mux, gateway) })
	request := func(cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://localhost:8080/admin/users/target/configs", strings.NewReader("{\"count\":2}"))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("Idempotency-Key", "unique")
		r.Header.Set("X-Actor-ID", "forged")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if response := request(nil, "http://localhost:8080"); response.Code != 401 {
		t.Fatal(response.Code)
	}
	state, cookie, _ := beginLogin(t, router)
	login := callback(router, state, cookie)
	var session *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == auth.sessionCookie {
			session = c
		}
	}
	directory.role = domain.RoleUser
	if response := request(session, "http://localhost:8080"); response.Code != 403 {
		t.Fatal(response.Code)
	}
	directory.role = domain.RoleAdmin
	if response := request(session, "https://attacker.example"); response.Code != 403 {
		t.Fatal(response.Code)
	}
	if gateway.calls != 0 {
		t.Fatal("untrusted request reached VPN")
	}
	response := request(session, "http://localhost:8080")
	if response.Code != 202 || gateway.calls != 1 || gateway.actor != "user" || gateway.key != "unique" || response.Header().Get("Location") == "" {
		t.Fatalf("%d %+v", response.Code, gateway)
	}
	directory.role = domain.RoleUser
	if response := request(session, "http://localhost:8080"); response.Code != 403 || gateway.calls != 1 {
		t.Fatal("old session retained admin")
	}
}
func TestInternalDirectoryRequiresServiceSecret(t *testing.T) {
	auth, _, _, _, _ := setupAuth(t)
	token := strings.Repeat("s", 40)
	router := NewRouter(func(context.Context) error { return nil }, func(mux *http.ServeMux) { auth.RegisterInternal(mux, token) })
	for _, tc := range []struct {
		token  string
		status int
	}{{"", 401}, {"wrong", 401}, {token, 200}} {
		request := httptest.NewRequest("GET", "http://localhost:8080/internal/users/user", nil)
		request.Header.Set("X-Service-Token", tc.token)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != tc.status {
			t.Fatal(response.Code)
		}
		if strings.Contains(response.Body.String(), "yandex_id") {
			t.Fatal("internal directory returned excess identity data")
		}
	}
}
