package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestConfiguredFrontendLogoutOrigin(t *testing.T) {
	auth, store, _, _, router := setupAuth(t)
	if err := auth.SetFrontendOrigin("http://localhost:5173"); err != nil {
		t.Fatal(err)
	}
	token := "local-test-session"
	hash := HashCredential(token)
	store.sessions[hash] = authEntry{"user", time.Now().Add(time.Hour)}
	for _, origin := range []string{"", "http://localhost:8080", "http://127.0.0.1:5173", "https://evil.example"} {
		request := httptest.NewRequest("POST", "/auth/logout", nil)
		request.Header.Set("Origin", origin)
		request.AddCookie(&http.Cookie{Name: auth.sessionCookie, Value: token})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("unexpected status for %q: %d", origin, response.Code)
		}
		if _, ok := store.sessions[hash]; !ok {
			t.Fatal("untrusted request removed session")
		}
	}
	request := httptest.NewRequest("POST", "/auth/logout", nil)
	request.Header.Set("Origin", "http://localhost:5173")
	request.AddCookie(&http.Cookie{Name: auth.sessionCookie, Value: token})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatal(response.Code)
	}
	if _, ok := store.sessions[hash]; ok {
		t.Fatal("session not revoked")
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Fatal("session cookie not cleared")
	}
}

func TestFrontendOriginValidation(t *testing.T) {
	for _, origin := range []string{"*", "null", "http://worldofleprechaun.ru", "https://example.com/path", "https://example.com/", "https://name@example.com", "https://example.com?x=1", "https://example.com#x"} {
		auth, _, _, _, _ := setupAuth(t)
		if err := auth.SetFrontendOrigin(origin); err == nil {
			t.Errorf("accepted invalid origin %q", origin)
		}
	}
	auth, _, _, _, _ := setupAuth(t)
	if err := auth.SetFrontendOrigin("https://worldofleprechaun.ru"); err != nil {
		t.Fatal(err)
	}
	if auth.origin != "https://worldofleprechaun.ru" {
		t.Fatal("production origin not applied")
	}
}
