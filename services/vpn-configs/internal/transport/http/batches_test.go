package http

import (
	"context"
	"encoding/json"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/domain"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

type apiStore struct{ account domain.Account }

func (s *apiStore) Load(_ context.Context, owner string) (domain.Account, error) {
	data, _ := json.Marshal(s.account)
	var account domain.Account
	_ = json.Unmarshal(data, &account)
	account.OwnerID = owner
	return account, nil
}
func (s *apiStore) Save(_ context.Context, account domain.Account, revision int64) (bool, error) {
	if s.account.Revision != revision {
		return false, nil
	}
	account.Revision = revision + 1
	s.account = account
	return true, nil
}

type apiAccess struct{}

func (apiAccess) RequireAdmin(_ context.Context, id string) error {
	if id != "admin" {
		return application.ErrForbidden
	}
	return nil
}
func (apiAccess) RequireUser(_ context.Context, id string) error {
	if id != "owner" {
		return application.ErrNotFound
	}
	return nil
}

type apiHost struct{}

func (apiHost) Create(context.Context, string, string, string) (application.Provisioned, error) {
	return application.Provisioned{RemoteID: "peer", File: []byte("config")}, nil
}
func (apiHost) Revoke(context.Context, string, string) error { return nil }

type apiFiles struct{}

func (apiFiles) Put(context.Context, string, string, string, []byte) error { return nil }
func (apiFiles) Get(context.Context, string, string, string) ([]byte, error) {
	return []byte("config"), nil
}
func TestInternalBatchHTTPValidationAndStatus(t *testing.T) {
	store := &apiStore{}
	i := 0
	manager := application.NewManager(store, apiAccess{}, apiHost{}, apiFiles{}, func() string { i++; return strconv.Itoa(i) }, time.Now)
	token := strings.Repeat("s", 40)
	api := NewBatchAPI(manager, token)
	router := NewRouter(func(context.Context) error { return nil }, api.Register)
	call := func(method, path, body, secret, actor, key string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, "http://vpn"+path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Service-Token", secret)
		request.Header.Set("X-Actor-ID", actor)
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	path := "/admin/users/owner/configs"
	if response := call("POST", path, "{\"count\":2}", "", "admin", "key"); response.Code != 401 {
		t.Fatal(response.Code)
	}
	if response := call("POST", path, "not-json", token, "user", "key"); response.Code != 403 {
		t.Fatal(response.Code)
	}
	for _, body := range []string{"null", "{}", "{\"count\":0}", "{\"count\":21}", "{\"count\":1.1}", "{\"count\":\"2\"}", "{\"count\":1,\"role\":\"admin\"}", "{\"count\":1} {}"} {
		if response := call("POST", path, body, token, "admin", "key"); response.Code != 400 {
			t.Fatalf("%s: %d", body, response.Code)
		}
	}
	if len(store.account.Batches) != 0 {
		t.Fatal("invalid request mutated state")
	}
	response := call("POST", path, "{\"count\":2}", token, "admin", "key")
	if response.Code != 202 || response.Header().Get("Location") == "" {
		t.Fatal(response.Code)
	}
	var accepted application.BatchResult
	if json.Unmarshal(response.Body.Bytes(), &accepted) != nil {
		t.Fatal("invalid result")
	}
	again := call("POST", path, "{\"count\":2}", token, "admin", "key")
	var repeated application.BatchResult
	_ = json.Unmarshal(again.Body.Bytes(), &repeated)
	if repeated.ID != accepted.ID || len(store.account.Configs) != 2 {
		t.Fatal("HTTP retry duplicated batch")
	}
	if response = call("POST", path, "{\"count\":3}", token, "admin", "key"); response.Code != 409 {
		t.Fatal(response.Code)
	}
	for i := 0; i < 2; i++ {
		if _, err := manager.ProcessNext(context.Background(), "owner"); err != nil {
			t.Fatal(err)
		}
	}
	response = call("GET", "/admin/users/owner/config-operations/"+accepted.ID, "", token, "admin", "")
	var completed application.BatchResult
	_ = json.Unmarshal(response.Body.Bytes(), &completed)
	if response.Code != 200 || completed.Status != "succeeded" {
		t.Fatal(response.Body.String())
	}
	if response = call("POST", path+"/bulk-delete", "{\"config_ids\":[\"missing\"]}", token, "admin", "delete"); response.Code != 404 {
		t.Fatal(response.Code)
	}
	if response = call("DELETE", path, "{}", token, "admin", "all"); response.Code != 400 {
		t.Fatal(response.Code)
	}
	response = call("DELETE", path, "", token, "admin", "all")
	if response.Code != 202 {
		t.Fatal(response.Body.String())
	}
}
