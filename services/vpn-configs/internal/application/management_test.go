package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"leprechaun/vpn-configs/internal/domain"
)

type memoryStates struct {
	mu       sync.Mutex
	accounts map[string]domain.Account
}

func copyState(a domain.Account) domain.Account {
	data, _ := json.Marshal(a)
	var b domain.Account
	_ = json.Unmarshal(data, &b)
	return b
}
func (s *memoryStates) Load(_ context.Context, owner string) (domain.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[owner]
	if !ok {
		return domain.Account{OwnerID: owner}, nil
	}
	return copyState(a), nil
}
func (s *memoryStates) Save(_ context.Context, a domain.Account, revision int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accounts[a.OwnerID].Revision != revision {
		return false, nil
	}
	a.Revision = revision + 1
	s.accounts[a.OwnerID] = copyState(a)
	return true, nil
}

type accessStub struct{}

func (accessStub) RequireAdmin(_ context.Context, actor string) error {
	if actor != "admin" {
		return ErrForbidden
	}
	return nil
}
func (accessStub) RequireUser(_ context.Context, owner string) error {
	if owner != "user" {
		return ErrNotFound
	}
	return nil
}

type provisionerStub struct {
	created        map[string]string
	revoked        map[string]bool
	failCreate     bool
	failRevoke     bool
	failGeneration string
	creates        int
}

func (h *provisionerStub) Create(_ context.Context, id, owner, name string) (Provisioned, error) {
	if h.failCreate {
		return Provisioned{}, errors.New("password: must never be persisted")
	}
	if remote, ok := h.created[id]; ok {
		return Provisioned{RemoteID: remote, File: []byte("config-" + id)}, nil
	}
	h.creates++
	h.created[id] = "remote-" + id
	return Provisioned{RemoteID: h.created[id], File: []byte("config-" + id)}, nil
}
func (h *provisionerStub) Revoke(_ context.Context, id, remote string) error {
	if h.failRevoke || h.failGeneration == id {
		return errors.New("private-key: must never be persisted")
	}
	h.revoked[id] = true
	return nil
}
func setupManager() (*Manager, *memoryStates, *provisionerStub) {
	states := &memoryStates{accounts: map[string]domain.Account{}}
	host := &provisionerStub{created: map[string]string{}, revoked: map[string]bool{}}
	var i atomic.Int64
	manager := NewManager(states, accessStub{}, host, &fileVaultStub{files: map[string][]byte{}}, func() string { return fmt.Sprint(i.Add(1)) }, time.Now)
	return manager, states, host
}

func advanceRetries(m *Manager) {
	now := m.now().Add(time.Minute)
	m.now = func() time.Time { return now }
}

func TestManagementAuthorizationAndIdempotency(t *testing.T) {
	m, states, host := setupManager()
	ctx := context.Background()
	if _, err := m.Submit(ctx, "user", "user", "req", domain.CreateConfig, "", "VPN"); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if len(states.accounts) != 0 || host.creates != 0 {
		t.Fatal("unauthorized side effect")
	}
	if _, err := m.Submit(ctx, "admin", "missing", "req", domain.CreateConfig, "", "VPN"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	first, err := m.Submit(ctx, "admin", "user", "req", domain.CreateConfig, "", "VPN")
	if err != nil {
		t.Fatal(err)
	}
	again, err := m.Submit(ctx, "admin", "user", "req", domain.CreateConfig, "", "VPN")
	if err != nil || first.ConfigID != again.ConfigID {
		t.Fatalf("%+v %v", again, err)
	}
	if _, err := m.Submit(ctx, "admin", "user", "req", domain.CreateConfig, "", "Other"); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	a, _ := states.Load(ctx, "user")
	if len(a.Active()) != 0 {
		t.Fatal("pending config visible")
	}
	if _, err := m.ProcessNext(ctx, "user"); err != nil {
		t.Fatal(err)
	}
	a, _ = states.Load(ctx, "user")
	if len(a.Active()) != 1 || host.creates != 1 {
		t.Fatal("config not activated")
	}
}

func TestRevokeAllIncludesPendingCreationAndBlocksNewIssuance(t *testing.T) {
	m, states, host := setupManager()
	ctx := context.Background()
	created, err := m.Submit(ctx, "admin", "user", "create", domain.CreateConfig, "", "VPN")
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Submit(ctx, "admin", "user", "all", domain.RevokeAllConfigs, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Submit(ctx, "admin", "user", "blocked", domain.CreateConfig, "", "VPN2"); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err = m.ProcessNext(ctx, "user"); err != nil {
		t.Fatal(err)
	}
	a, _ := states.Load(ctx, "user")
	if len(a.Active()) != 0 {
		t.Fatal("late creation resurrected config")
	}
	host.failRevoke = true
	if _, err = m.ProcessNext(ctx, "user"); err == nil {
		t.Fatal("host failure reported as success")
	}
	op, err := m.Status(ctx, "admin", "user", "all")
	if err != nil || op.CompletedAt != nil || op.ErrorCode != "host_operation_unconfirmed" {
		t.Fatalf("%+v %v", op, err)
	}
	host.failRevoke = false
	advanceRetries(m)
	// Recreate application service to simulate restart; intent lives in the store.
	restarted := NewManager(states, accessStub{}, host, &fileVaultStub{files: map[string][]byte{}}, func() string { return "after" }, time.Now)
	advanceRetries(restarted)
	if _, err = restarted.ProcessNext(ctx, "user"); err != nil {
		t.Fatal(err)
	}
	if !host.revoked[created.Generation] {
		t.Fatal("VPN access not revoked")
	}
	a, _ = states.Load(ctx, "user")
	if a.Draining() || len(a.Active()) != 0 {
		t.Fatal("drain incomplete")
	}
	if _, err = restarted.Submit(ctx, "admin", "user", "after", domain.CreateConfig, "", "New"); err != nil {
		t.Fatal(err)
	}
}

func TestSingleRevokeHidesBeforeRemoteConfirmation(t *testing.T) {
	m, states, host := setupManager()
	ctx := context.Background()
	op, err := m.Submit(ctx, "admin", "user", "create", domain.CreateConfig, "", "VPN")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.ProcessNext(ctx, "user"); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Submit(ctx, "admin", "user", "delete", domain.RevokeConfig, op.ConfigID, ""); err != nil {
		t.Fatal(err)
	}
	a, _ := states.Load(ctx, "user")
	if len(a.Active()) != 0 {
		t.Fatal("revoking config downloadable")
	}
	host.failRevoke = true
	_, _ = m.ProcessNext(ctx, "user")
	pending, _ := m.Status(ctx, "admin", "user", "delete")
	if pending.CompletedAt != nil {
		t.Fatal("unconfirmed revocation completed")
	}
	host.failRevoke = false
	advanceRetries(m)
	if _, err = m.ProcessNext(ctx, "user"); err != nil {
		t.Fatal(err)
	}
}
