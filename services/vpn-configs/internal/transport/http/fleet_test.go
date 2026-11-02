package http

import (
	"context"
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/v2/bson"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/domain"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type httpFleetStore struct{ state domain.FleetControl }

func (s *httpFleetStore) LoadFleet(context.Context) (domain.FleetControl, error) {
	data, _ := bson.Marshal(s.state)
	var out domain.FleetControl
	bson.Unmarshal(data, &out)
	return out, nil
}
func (s *httpFleetStore) SaveFleet(_ context.Context, state domain.FleetControl, revision int64) (bool, error) {
	if s.state.Revision != revision {
		return false, nil
	}
	state.Revision++
	s.state = state
	return true, nil
}

type httpFleetCatalog struct{ apiStore }

func (*httpFleetCatalog) OwnersAfter(context.Context, string, int64) ([]string, error) {
	return []string{}, nil
}

type httpFleetGuard struct{ mu sync.Mutex }

func (g *httpFleetGuard) With(ctx context.Context, fn func(context.Context) error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return fn(ctx)
}
func TestFleetHTTPAuthorizationStrictBodiesAndPolling(t *testing.T) {
	revision := int64(1)
	repo := &serverTestRepo{items: map[string]domain.VPNServer{"target": {ID: "target", Revision: 1, PreparationStatus: "ready", PreparedRevision: &revision}}}
	counter := 0
	fleet := &application.Fleet{Store: &httpFleetStore{state: domain.FleetControl{SchemaReady: true}}, Accounts: &httpFleetCatalog{}, Servers: repo, Access: apiAccess{}, Guard: &httpFleetGuard{}, NewID: func() string { counter++; return fmt.Sprintf("op%d", counter) }, Now: time.Now}
	secret := strings.Repeat("s", 40)
	router := NewRouter(func(context.Context) error { return nil }, NewFleetAPI(fleet, secret).Register)
	call := func(method, path, body, token, actor, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Service-Token", token)
		r.Header.Set("X-Actor-ID", actor)
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/admin/vpn-routing", "/admin/vpn-server-operations", "/admin/vpn-server-operations/missing"} {
		if w := call("GET", path, "", "", "admin", ""); w.Code != 401 {
			t.Fatal(w.Code)
		}
		if w := call("GET", path, "", secret, "owner", ""); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	if w := call("POST", "/admin/vpn-switches", `{"target_server_id":"target","expected_routing_revision":0,"revoke_old":true}`, secret, "admin", "key"); w.Code != 400 {
		t.Fatal(w.Code)
	}
	response := call("POST", "/admin/vpn-switches", `{"target_server_id":"target","expected_routing_revision":0}`, secret, "admin", "key")
	if response.Code != 202 || response.Header().Get("Location") == "" {
		t.Fatal(response.Code, response.Body.String())
	}
	var op domain.FleetOperation
	json.Unmarshal(response.Body.Bytes(), &op)
	fleet.Process(context.Background())
	response = call("GET", "/admin/vpn-server-operations/"+op.ID, "", secret, "admin", "")
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"status":"succeeded"`) {
		t.Fatal(response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), `"Key"`) || strings.Contains(response.Body.String(), `"Items"`) {
		t.Fatal("internal operation state leaked")
	}
	for _, path := range []string{"/admin/vpn-server-operations?limit=1", "/admin/vpn-server-operations/" + op.ID + "/items?limit=50"} {
		w := call("GET", path, "", secret, "admin", "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"next_cursor":null`) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for _, query := range []string{"limit=0", "after=invalid!", "limit=101"} {
		if w := call("GET", "/admin/vpn-server-operations?"+query, "", secret, "admin", ""); w.Code != 400 {
			t.Fatal(query, w.Code)
		}
	}
	if w := call("POST", "/admin/vpn-server-operations/"+op.ID+"/retry", "{}", secret, "admin", "retry"); w.Code != 409 {
		t.Fatal(w.Code)
	}
}
