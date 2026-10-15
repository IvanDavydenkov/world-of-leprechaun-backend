package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCredentialedFrontendCORS(t *testing.T) {
	called := 0
	handler := WithFrontendCORS("https://worldofleprechauns.ru", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++; w.WriteHeader(200) }))
	for _, tc := range []struct {
		origin, method, headers string
		status                  int
	}{{"https://worldofleprechauns.ru", "PATCH", "content-type, idempotency-key", 204}, {"https://evil.example", "GET", "", 403}, {"https://worldofleprechauns.ru", "PATCH", "x-service-token", 403}, {"https://worldofleprechauns.ru", "TRACE", "", 403}} {
		r := httptest.NewRequest("OPTIONS", "/admin/vpn-servers", nil)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Access-Control-Request-Method", tc.method)
		r.Header.Set("Access-Control-Request-Headers", tc.headers)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal(w.Code)
		}
		if tc.status == 204 && (w.Header().Get("Access-Control-Allow-Origin") != tc.origin || w.Header().Get("Access-Control-Allow-Credentials") != "true") {
			t.Fatal("missing CORS headers")
		}
	}
	if called != 0 {
		t.Fatal("preflight reached business handler")
	}
	r := httptest.NewRequest("GET", "/me", nil)
	r.Header.Set("Origin", "https://worldofleprechauns.ru")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 || called != 1 {
		t.Fatal(w.Code)
	}
}
func TestFrontendRedirectAllowlist(t *testing.T) {
	a, _, _, _, _ := setupAuth(t)
	a.SetFrontendOrigin("https://worldofleprechauns.ru")
	for _, target := range []string{"https://evil.example/", "//evil.example/", "javascript:alert(1)", "/\\evil.example"} {
		if a.SetFrontendRedirects(target, "") == nil {
			t.Fatal("unsafe redirect", target)
		}
	}
	if err := a.SetFrontendRedirects("https://worldofleprechauns.ru/", "https://worldofleprechauns.ru/"); err != nil {
		t.Fatal(err)
	}
}

func TestJSONLogoutDoesNotRedirect(t *testing.T) {
	a, _, _, _, router := setupAuth(t)
	r := httptest.NewRequest("POST", "/auth/logout", nil)
	r.Header.Set("Origin", a.origin)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != 204 || w.Header().Get("Location") != "" {
		t.Fatal(w.Code)
	}
	if cookies := w.Result().Cookies(); len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Fatal("session cookie was not cleared")
	}
}
