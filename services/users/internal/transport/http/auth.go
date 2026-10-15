package http

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"leprechaun/users/internal/application"
	"leprechaun/users/internal/domain"
)

type SignInUseCase interface {
	SignIn(context.Context, string, string) (domain.User, error)
}
type UserDirectory interface {
	Resolve(context.Context, string) (domain.User, error)
	List(context.Context, string, string, int) ([]domain.User, error)
}

type Auth struct {
	signIn                     SignInUseCase
	directory                  UserDirectory
	sessions                   application.SessionStore
	authorizationURL           func(string, string) string
	secure                     bool
	origin                     string
	sessionCookie, stateCookie string
	now                        func() time.Time
	configGateway              application.ConfigGateway
}

func NewAuth(signIn SignInUseCase, directory UserDirectory, sessions application.SessionStore, authorize func(string, string) string, redirectURL string) (*Auth, error) {
	redirect, err := url.Parse(redirectURL)
	if err != nil || redirect.User != nil || redirect.Host == "" || redirect.RawQuery != "" || redirect.Fragment != "" || redirect.Path != "/auth/yandex/callback" {
		return nil, errors.New("YANDEX_REDIRECT_URL must have path /auth/yandex/callback without credentials, query or fragment")
	}
	local := redirect.Hostname() == "localhost" || redirect.Hostname() == "127.0.0.1" || redirect.Hostname() == "::1"
	if redirect.Scheme != "https" && !(redirect.Scheme == "http" && local) {
		return nil, errors.New("OAuth requires HTTPS except on localhost")
	}
	auth := &Auth{signIn: signIn, directory: directory, sessions: sessions, authorizationURL: authorize, secure: redirect.Scheme == "https", origin: redirect.Scheme + "://" + redirect.Host, now: time.Now, sessionCookie: "leprechaun_session", stateCookie: "leprechaun_oauth_state"}
	if auth.secure {
		auth.sessionCookie = "__Host-leprechaun_session"
		auth.stateCookie = "__Host-leprechaun_oauth_state"
	}
	return auth, nil
}

func HashCredential(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func randomCredential() string { return rand.Text() + rand.Text() }
func (a *Auth) cookie(w http.ResponseWriter, name, value string, seconds int) {
	cookie := &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode, MaxAge: seconds}
	if seconds < 0 {
		cookie.Expires = time.Unix(1, 0)
	} else {
		cookie.Expires = a.now().Add(time.Duration(seconds) * time.Second)
	}
	http.SetCookie(w, cookie)
}
func (a *Auth) Register(mux *http.ServeMux) {
	routes := []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"GET /{$}", a.index}, {"GET /auth/yandex/login", a.login}, {"GET /auth/yandex/callback", a.callback},
		{"GET /me", a.me}, {"POST /auth/logout", a.logout}, {"GET /admin/users", a.users},
	}
	for _, route := range routes {
		mux.HandleFunc(route.pattern, noStore(route.handler))
	}
}
func noStore(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next(w, r)
	}
}
func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
func (a *Auth) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	_, _ = w.Write([]byte("<!doctype html><html lang=\"ru\"><meta charset=\"utf-8\"><title>Проверка входа</title><h1>Word of Leprechaun</h1><p><a href=\"/auth/yandex/login\">Войти через Яндекс</a></p><p><a href=\"/me\">Мой профиль (JSON)</a></p><form action=\"/auth/logout\" method=\"post\"><button>Выйти</button></form></html>"))
}
func (a *Auth) login(w http.ResponseWriter, r *http.Request) {
	state, verifier := randomCredential(), randomCredential()
	if err := a.sessions.SaveState(r.Context(), HashCredential(state), verifier, a.now().Add(10*time.Minute)); err != nil {
		problem(w, 503, "auth_storage_unavailable")
		return
	}
	challenge := sha256.Sum256([]byte(verifier))
	a.cookie(w, a.stateCookie, state, 600)
	http.Redirect(w, r, a.authorizationURL(state, base64.RawURLEncoding.EncodeToString(challenge[:])), http.StatusFound)
}
func (a *Auth) callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(a.stateCookie)
	state := r.URL.Query().Get("state")
	a.cookie(w, a.stateCookie, "", -1)
	if err != nil || len(state) < 32 || len(state) > 256 || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		problem(w, 400, "invalid_oauth_state")
		return
	}
	verifier, err := a.sessions.ConsumeState(r.Context(), HashCredential(state), a.now())
	if err != nil {
		if errors.Is(err, application.ErrUnauthenticated) {
			problem(w, 400, "invalid_oauth_state")
		} else {
			problem(w, 503, "auth_storage_unavailable")
		}
		return
	}
	if r.URL.Query().Get("error") != "" || r.URL.Query().Get("code") == "" {
		problem(w, 400, "yandex_login_cancelled")
		return
	}
	user, err := a.signIn.SignIn(r.Context(), r.URL.Query().Get("code"), verifier)
	if err != nil {
		problem(w, 502, "yandex_login_failed")
		return
	}
	token := randomCredential()
	if err = a.sessions.SaveSession(r.Context(), HashCredential(token), user.ID, a.now().Add(24*time.Hour)); err != nil {
		problem(w, 503, "auth_storage_unavailable")
		return
	}
	if old, err := r.Cookie(a.sessionCookie); err == nil {
		if err = a.sessions.DeleteSession(r.Context(), HashCredential(old.Value)); err != nil {
			problem(w, 503, "auth_storage_unavailable")
			return
		}
	}
	a.cookie(w, a.sessionCookie, token, 24*60*60)
	http.Redirect(w, r, "/me", http.StatusSeeOther)
}
func (a *Auth) current(r *http.Request) (domain.User, error) {
	cookie, err := r.Cookie(a.sessionCookie)
	if err != nil || len(cookie.Value) > 256 {
		return domain.User{}, application.ErrUnauthenticated
	}
	id, err := a.sessions.SessionUser(r.Context(), HashCredential(cookie.Value), a.now())
	if err != nil {
		return domain.User{}, err
	}
	// Role is recomputed on every request, so old sessions cannot preserve admin.
	return a.directory.Resolve(r.Context(), id)
}
func authError(w http.ResponseWriter, err error) {
	if errors.Is(err, application.ErrUnauthenticated) || errors.Is(err, application.ErrNotFound) || errors.Is(err, application.ErrForbidden) {
		problem(w, 401, "authentication_required")
	} else {
		problem(w, 503, "auth_storage_unavailable")
	}
}
func (a *Auth) me(w http.ResponseWriter, r *http.Request) {
	user, err := a.current(r)
	if err != nil {
		authError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		ID          string      `json:"id"`
		YandexID    string      `json:"yandex_id"`
		DisplayName string      `json:"display_name"`
		Role        domain.Role `json:"role"`
	}{user.ID, user.YandexID, user.DisplayName, user.Role})
}
func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != a.origin {
		problem(w, 403, "invalid_origin")
		return
	}
	if cookie, err := r.Cookie(a.sessionCookie); err == nil {
		if err = a.sessions.DeleteSession(r.Context(), HashCredential(cookie.Value)); err != nil {
			problem(w, 503, "auth_storage_unavailable")
			return
		}
	}
	a.cookie(w, a.sessionCookie, "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *Auth) users(w http.ResponseWriter, r *http.Request) {
	actor, err := a.current(r)
	if err != nil {
		authError(w, err)
		return
	}
	if actor.Role != domain.RoleAdmin {
		problem(w, 403, "admin_required")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			problem(w, 400, "invalid_limit")
			return
		}
	}
	users, err := a.directory.List(r.Context(), actor.ID, r.URL.Query().Get("after"), limit)
	if err != nil {
		if errors.Is(err, application.ErrForbidden) {
			problem(w, 403, "admin_required")
		} else {
			problem(w, 503, "auth_storage_unavailable")
		}
		return
	}
	type entry struct {
		ID          string                    `json:"id"`
		DisplayName string                    `json:"display_name"`
		Role        domain.Role               `json:"role"`
		YandexID    string                    `json:"yandex_id"`
		CreatedAt   time.Time                 `json:"created_at"`
		VPN         application.ConfigSummary `json:"vpn"`
	}
	summaries := a.configSummaries(r.Context(), actor.ID, users)
	result := make([]entry, 0, len(users))
	for _, user := range users {
		summary, ok := summaries[user.ID]
		if !ok {
			summary = application.ConfigSummary{Availability: "unavailable"}
		}
		result = append(result, entry{user.ID, user.DisplayName, user.Role, user.YandexID, user.CreatedAt, summary})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// SetFrontendOrigin configures the single trusted browser origin for logout.
// Empty preserves the OAuth callback origin for backwards compatibility.
func (a *Auth) SetFrontendOrigin(origin string) error {
	if origin == "" {
		return nil
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || origin != parsed.Scheme+"://"+parsed.Host {
		return errors.New("FRONTEND_ORIGIN must be an origin without path, credentials, query or fragment")
	}
	local := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1"
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && local) {
		return errors.New("FRONTEND_ORIGIN requires HTTPS except on localhost")
	}
	a.origin = origin
	return nil
}
