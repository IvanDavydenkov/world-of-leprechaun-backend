package yandex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCodeExchangeAndIdentity(t *testing.T) {
	verifier := strings.Repeat("v", 43)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			id, secret, ok := r.BasicAuth()
			if !ok || id != "client" || secret != "secret" || r.Method != http.MethodPost {
				t.Error("invalid token authentication")
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("code_verifier") != verifier || r.Form.Get("code") != "code" || r.Form.Get("grant_type") != "authorization_code" {
				t.Error("invalid token form")
			}
			_, _ = w.Write([]byte("{\"access_token\":\"oauth-secret\"}"))
		case "/info":
			if r.Header.Get("Authorization") != "OAuth oauth-secret" || r.URL.Query().Get("oauth_token") != "" {
				t.Error("token must only be in header")
			}
			_, _ = w.Write([]byte("{\"id\":\"123\",\"display_name\":\"Name\"}"))
		}
	}))
	defer server.Close()
	provider := New("client", "secret", "http://localhost:8080/auth/yandex/callback")
	provider.tokenURL = server.URL + "/token"
	provider.infoURL = server.URL + "/info"
	identity, err := provider.ExchangeCode(context.Background(), "code", verifier)
	if err != nil || identity.Subject != "123" || identity.DisplayName != "Name" {
		t.Fatalf("%+v %v", identity, err)
	}
	parsed, _ := url.Parse(provider.AuthorizationURL("state", "challenge"))
	if parsed.Query().Get("state") != "state" || parsed.Query().Get("code_challenge_method") != "S256" || parsed.Query().Get("code_challenge") != "challenge" {
		t.Fatal("invalid authorize URL")
	}
}

func TestProviderErrorsAreSanitized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte("client_secret=secret"))
	}))
	defer server.Close()
	provider := New("client", "secret", "http://localhost:8080/auth/yandex/callback")
	provider.tokenURL = server.URL
	if _, err := provider.ExchangeCode(context.Background(), "code", strings.Repeat("v", 43)); err != ErrProvider {
		t.Fatal(err)
	}
}
