package http

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/ssh"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/domain"
	"leprechaun/vpn-configs/internal/infrastructure/vault"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type serverTestRepo struct {
	mu    sync.Mutex
	items map[string]domain.VPNServer
}

func (r *serverTestRepo) Create(_ context.Context, s domain.VPNServer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[s.ID] = s
	return nil
}
func (r *serverTestRepo) Get(_ context.Context, id string) (domain.VPNServer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.items[id]
	if !ok {
		return s, application.ErrNotFound
	}
	return s, nil
}
func (r *serverTestRepo) List(context.Context) ([]domain.VPNServer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	items := []domain.VPNServer{}
	for _, s := range r.items {
		items = append(items, s)
	}
	return items, nil
}
func (r *serverTestRepo) Update(_ context.Context, s domain.VPNServer, revision int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.items[s.ID].Revision != revision {
		return false, nil
	}
	r.items[s.ID] = s
	return true, nil
}
func TestServerRegistryHTTPAndEncryptedPassword(t *testing.T) {
	repo := &serverTestRepo{items: map[string]domain.VPNServer{}}
	secrets, _ := vault.New(nil, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	registry := application.NewServerRegistry(repo, secrets, apiAccess{}, func() string { return "server1" }, time.Now)
	token := strings.Repeat("s", 40)
	router := NewRouter(func(context.Context) error { return nil }, NewServerAPI(registry, token).Register)
	call := func(method, path, body, secret, actor string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Service-Token", secret)
		r.Header.Set("X-Actor-ID", actor)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	for _, route := range []struct{ method, path string }{{"POST", "/admin/vpn-servers"}, {"GET", "/admin/vpn-servers"}, {"GET", "/admin/vpn-servers/server1"}, {"PATCH", "/admin/vpn-servers/server1"}} {
		if w := call(route.method, route.path, "{}", "", "admin"); w.Code != 401 {
			t.Fatal(w.Code)
		}
		if w := call(route.method, route.path, "{}", token, "owner"); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(public)
	input := application.ServerFields{Name: "Main", SSHAddress: "vpn.example:22", SSHUsername: "root", Password: "private-password", SSHHostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), PublicEndpoint: "vpn.example:39977", Container: "amnezia-awg2", Interface: "awg0"}
	body, _ := json.Marshal(input)
	w := call("POST", "/admin/vpn-servers", string(body), token, "admin")
	if w.Code != 201 || w.Header().Get("Location") != "/admin/vpn-servers/server1" {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private-password") || strings.Contains(w.Body.String(), "ciphertext") {
		t.Fatal("secret in response")
	}
	var created application.ServerView
	if json.Unmarshal(w.Body.Bytes(), &created) != nil || !created.PasswordSet || created.Revision != 1 {
		t.Fatal(w.Body.String())
	}
	saved, _ := repo.Get(context.Background(), "server1")
	if strings.Contains(string(saved.PasswordCiphertext), "private-password") {
		t.Fatal("plaintext stored")
	}
	plain, err := secrets.DecryptServerPassword("server1", saved.PasswordCiphertext)
	if err != nil || plain != "private-password" {
		t.Fatal("cannot decrypt")
	}
	w = call("PATCH", "/admin/vpn-servers/server1", `{"expected_revision":1,"name":"Renamed"}`, token, "admin")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := repo.Get(context.Background(), "server1")
	if string(after.PasswordCiphertext) != string(saved.PasswordCiphertext) || after.Revision != 2 {
		t.Fatal("omitted password changed")
	}
	for _, bad := range []string{`{"expected_revision":2}`, `{"expected_revision":2,"password":""}`, `{"expected_revision":2,"name":null}`, `{"expected_revision":2,"name":"A","name":"B"}`, `{"expected_revision":2,"unknown":true}`, `{"expected_revision":2,"ssh_address":"bad"}`, `{"expected_revision":2,"ssh_host_key":"ssh-ed25519 invalid"}`} {
		if w := call("PATCH", "/admin/vpn-servers/server1", bad, token, "admin"); w.Code != 400 {
			t.Fatal(bad, w.Code)
		}
	}
	if w := call("PATCH", "/admin/vpn-servers/server1", `{"expected_revision":1,"name":"stale"}`, token, "admin"); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if w := call("GET", "/admin/vpn-servers/missing", "", token, "admin"); w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, path := range []string{"/admin/vpn-servers", "/admin/vpn-servers/server1"} {
		w := call("GET", path, "", token, "admin")
		if w.Code != 200 || strings.Contains(w.Body.String(), "private-password") || strings.Contains(w.Body.String(), "ciphertext") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w = call("PATCH", "/admin/vpn-servers/server1", `{"expected_revision":2,"password":"rotated-password"}`, token, "admin")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	rotated, _ := repo.Get(context.Background(), "server1")
	plain, err = secrets.DecryptServerPassword("server1", rotated.PasswordCiphertext)
	if err != nil || plain != "rotated-password" {
		t.Fatal("rotation failed")
	}
}
