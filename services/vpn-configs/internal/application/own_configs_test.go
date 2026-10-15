package application

import (
	"context"
	"leprechaun/vpn-configs/internal/domain"
	"testing"
	"time"
)

type ownAccess struct{}

func (ownAccess) RequireAdmin(context.Context, string) error { return ErrForbidden }
func (ownAccess) RequireUser(_ context.Context, id string) error {
	if id == "alice" || id == "bob" || id == "admin" {
		return nil
	}
	return ErrNotFound
}
func TestOwnConfigsIsolationAndCurrentGeneration(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	store := &memoryStates{accounts: map[string]domain.Account{}}
	files := &fileVaultStub{files: map[string][]byte{}}
	m := NewManager(store, ownAccess{}, nil, files, nil, time.Now)
	for _, owner := range []string{"alice", "bob", "admin"} {
		id := owner + "-config"
		store.accounts[owner] = domain.Account{OwnerID: owner, Configs: []domain.ManagedConfig{{ID: id, Desired: true, Provisioned: true, Version: 2, Generation: "new"}, {ID: "deleted", DeletedAt: &now}, {ID: "pending", Desired: true}}}
		files.Put(ctx, owner, id, "old", []byte("old"))
		files.Put(ctx, owner, id, "new", []byte(owner))
	}
	for _, owner := range []string{"alice", "bob", "admin"} {
		list, err := m.OwnConfigs(ctx, owner)
		if err != nil || len(list) != 1 || list[0].ID != owner+"-config" || !list[0].DownloadAvailable {
			t.Fatalf("%s: %+v %v", owner, list, err)
		}
		file, err := m.OwnDownload(ctx, owner, owner+"-config")
		if err != nil || string(file) != owner {
			t.Fatal("wrong generation", err)
		}
		foreign := "alice-config"
		if owner == "alice" {
			foreign = "bob-config"
		}
		if _, err = m.OwnDownload(ctx, owner, foreign); err != ErrNotFound {
			t.Fatal("foreign download allowed", err)
		}
		for _, id := range []string{"deleted", "pending", "missing", "../bob-config"} {
			if _, err = m.OwnDownload(ctx, owner, id); err != ErrNotFound {
				t.Fatal(id, err)
			}
		}
	}
	a := store.accounts["alice"]
	a.Configs[0].Desired = false
	store.accounts["alice"] = a
	if _, err := m.OwnDownload(ctx, "alice", "alice-config"); err != ErrNotFound {
		t.Fatal("revocation must block download", err)
	}
	store.accounts["bob"] = domain.Account{OwnerID: "bob"}
	list, err := m.OwnConfigs(ctx, "bob")
	if err != nil || list == nil || len(list) != 0 {
		t.Fatal("empty list", err)
	}
}
