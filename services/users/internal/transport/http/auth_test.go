package http

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"leprechaun/users/internal/application"
	"leprechaun/users/internal/domain"
)

type authEntry struct {
	value  string
	expiry time.Time
}
type authStore struct{ states, sessions map[string]authEntry }

func (s *authStore) SaveState(_ context.Context, hash, verifier string, expiry time.Time) error {
	s.states[hash] = authEntry{verifier, expiry}
	return nil
}
func (s *authStore) ConsumeState(_ context.Context, hash string, now time.Time) (string, error) {
	entry, ok := s.states[hash]
	if !ok || !entry.expiry.After(now) {
		return "", application.ErrUnauthenticated
	}
	delete(s.states, hash)
	return entry.value, nil
}
func (s *authStore) SaveSession(_ context.Context, hash, id string, expiry time.Time) error {
	s.sessions[hash] = authEntry{id, expiry}
	return nil
}
func (s *authStore) SessionUser(_ context.Context, hash string, now time.Time) (string, error) {
	entry, ok := s.sessions[hash]
	if !ok || !entry.expiry.After(now) {
		return "", application.ErrUnauthenticated
	}
	return entry.value, nil
}
func (s *authStore) DeleteSession(_ context.Context, hash string) error {
	delete(s.sessions, hash)
	return nil
}

type signInStub struct {
	calls    int
	verifier string
}

func (s *signInStub) SignIn(_ context.Context, code, verifier string) (domain.User, error) {
	s.calls++
	s.verifier = verifier
	return domain.User{ID: "user", YandexID: "123", Role: domain.RoleAdmin}, nil
}

type authDirectory struct{ role domain.Role }

func (d *authDirectory) Resolve(context.Context, string) (domain.User, error) {
	return domain.User{ID: "user", YandexID: "123", Role: d.role}, nil
}
func (d *authDirectory) List(context.Context, string, string, int) ([]domain.User, error) {
	return []domain.User{}, nil
}

func setupAuth(t *testing.T) (*Auth, *authStore, *signInStub, *authDirectory, http.Handler) {
	t.Helper()
	store := &authStore{states: map[string]authEntry{}, sessions: map[string]authEntry{}}
	signIn := &signInStub{}
	directory := &authDirectory{role: domain.RoleAdmin}
	auth, err := NewAuth(signIn, directory, store, func(state, challenge string) string {
		return "https://oauth.yandex.ru/authorize?" + url.Values{"state": {state}, "code_challenge": {challenge}}.Encode()
	}, "http://localhost:8080/auth/yandex/callback")
	if err != nil {
		t.Fatal(err)
	}
	return auth, store, signIn, directory, NewRouter(func(context.Context) error { return nil }, auth.Register)
}
func beginLogin(t *testing.T, router http.Handler) (string, *http.Cookie, string) {
	t.Helper()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest("GET", "http://localhost:8080/auth/yandex/login", nil))
	if response.Code != 302 {
		t.Fatal(response.Code)
	}
	location, _ := url.Parse(response.Header().Get("Location"))
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("state cookie missing")
	}
	return location.Query().Get("state"), cookies[0], location.Query().Get("code_challenge")
}
func callback(router http.Handler, state string, cookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest("GET", "http://localhost:8080/auth/yandex/callback?code=code&state="+url.QueryEscape(state), nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}
func TestLoginPKCESessionAndCurrentRole(t *testing.T) {
	auth, store, signIn, directory, router := setupAuth(t)
	state, stateCookie, challenge := beginLogin(t, router)
	verifier := store.states[HashCredential(state)].value
	sum := sha256.Sum256([]byte(verifier))
	if challenge != base64.RawURLEncoding.EncodeToString(sum[:]) || len(verifier) < 43 {
		t.Fatal("PKCE missing")
	}
	response := callback(router, state, stateCookie)
	if response.Code != 303 || signIn.calls != 1 || signIn.verifier != verifier {
		t.Fatal("login failed")
	}
	var sessionCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == auth.sessionCookie {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("invalid session cookie")
	}
	if _, exists := store.sessions[sessionCookie.Value]; exists {
		t.Fatal("raw session token persisted")
	}
	if _, exists := store.sessions[HashCredential(sessionCookie.Value)]; !exists {
		t.Fatal("hashed session missing")
	}
	request := httptest.NewRequest("GET", "http://localhost:8080/me", nil)
	request.AddCookie(sessionCookie)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	var profile map[string]string
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &profile) != nil || profile["yandex_id"] != "123" || profile["role"] != "admin" {
		t.Fatal(response.Body.String())
	}
	// Administrative privileges are resolved again on every request.
	directory.role = domain.RoleUser
	request = httptest.NewRequest("GET", "http://localhost:8080/admin/users?role=admin", nil)
	request.AddCookie(sessionCookie)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != 403 {
		t.Fatal("stale admin privileges preserved")
	}
	// Consumed OAuth states cannot be replayed.
	if response = callback(router, state, stateCookie); response.Code != 400 || signIn.calls != 1 {
		t.Fatal("callback replay accepted")
	}
	auth.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	request = httptest.NewRequest("GET", "http://localhost:8080/me", nil)
	request.AddCookie(sessionCookie)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatal("expired session accepted")
	}
}
func TestInvalidStateNeverExchangesCode(t *testing.T) {
	auth, _, signIn, _, router := setupAuth(t)
	state, cookie, _ := beginLogin(t, router)
	if response := callback(router, state, nil); response.Code != 400 {
		t.Fatal("missing browser binding accepted")
	}
	bad := *cookie
	bad.Value = "wrong"
	if response := callback(router, state, &bad); response.Code != 400 {
		t.Fatal("wrong browser accepted")
	}
	auth.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if response := callback(router, state, cookie); response.Code != 400 {
		t.Fatal("expired state accepted")
	}
	if signIn.calls != 0 {
		t.Fatal("provider called for invalid state")
	}
}
func TestLogoutOriginAndRevocation(t *testing.T) {
	auth, _, _, _, router := setupAuth(t)
	state, cookie, _ := beginLogin(t, router)
	login := callback(router, state, cookie)
	var session *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == auth.sessionCookie {
			session = c
		}
	}
	request := httptest.NewRequest("POST", "http://localhost:8080/auth/logout", nil)
	request.AddCookie(session)
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != 403 {
		t.Fatal("cross-origin logout accepted")
	}
	request.Header.Set("Origin", "http://localhost:8080")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != 303 {
		t.Fatal(response.Code)
	}
	request = httptest.NewRequest("GET", "http://localhost:8080/me", nil)
	request.AddCookie(session)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatal("logged-out session still works")
	}
}
func TestRedirectSecurity(t *testing.T) {
	for _, redirect := range []string{"http://public.example/auth/yandex/callback", "https://user:password@example.org/auth/yandex/callback", "https://example.org/wrong", "https://example.org/auth/yandex/callback?token=x"} {
		if _, err := NewAuth(nil, nil, nil, nil, redirect); err == nil {
			t.Fatal("unsafe redirect accepted", redirect)
		}
	}
	auth, err := NewAuth(nil, nil, nil, nil, "https://example.org/auth/yandex/callback")
	if err != nil || !auth.secure || !strings.HasPrefix(auth.sessionCookie, "__Host-") {
		t.Fatal("secure cookie mode missing")
	}
}
