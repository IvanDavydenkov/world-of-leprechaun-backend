package usersclient

import (
	"context"
	"errors"
	"leprechaun/vpn-configs/internal/application"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCurrentRoleIsCheckedOnEveryCall(t *testing.T) {
	token := strings.Repeat("s", 40)
	role := "admin"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Service-Token") != token {
			t.Error("service token missing")
		}
		_, _ = w.Write([]byte("{\"id\":\"owner\",\"role\":\"" + role + "\"}"))
	}))
	defer server.Close()
	client, err := New(server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.RequireAdmin(context.Background(), "owner"); err != nil {
		t.Fatal(err)
	}
	role = "user"
	if err = client.RequireAdmin(context.Background(), "owner"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
	if err = client.RequireUser(context.Background(), "owner"); err != nil {
		t.Fatal(err)
	}
}
func TestClientRejectsUnsafeConfiguration(t *testing.T) {
	if _, err := New("http://public.example", strings.Repeat("s", 40)); err == nil {
		t.Fatal("plaintext public service URL accepted")
	}
	if _, err := New("http://127.0.0.1:8080", "short"); err == nil {
		t.Fatal("short service token accepted")
	}
}
