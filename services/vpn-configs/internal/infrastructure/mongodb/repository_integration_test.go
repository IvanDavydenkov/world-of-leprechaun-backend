package mongodb

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/domain"
	"leprechaun/vpn-configs/internal/infrastructure/vault"
	"os"
	"testing"
	"time"
)

func TestRepositoryIntegration(t *testing.T) {
	uri := os.Getenv("MONGO_TEST_URI")
	if uri == "" {
		t.Skip("set MONGO_TEST_URI to a disposable MongoDB with database creation permissions")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database := fmt.Sprintf("leprechaun_test_vpn_configs_%d", time.Now().UnixNano())
	client, repository, err := Open(ctx, uri, database)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if err := client.Database(database).Drop(cleanup); err != nil {
			t.Error(err)
		}
		if err := client.Disconnect(cleanup); err != nil {
			t.Error(err)
		}
	}()
	saved, err := repository.Save(ctx, domain.Account{OwnerID: "alice", Configs: []domain.ManagedConfig{{ID: "config", Generation: "generation", RemoteID: "remote", Name: "VPN", CreatedAt: time.Now().UTC(), Desired: true, Provisioned: true, Version: 1}}}, 0)
	if err != nil || !saved {
		t.Fatal(err)
	}
	configs, err := repository.ListByOwner(ctx, "alice")
	if err != nil || len(configs) != 1 {
		t.Fatalf("configs=%v err=%v", configs, err)
	}
	configs, err = repository.ListByOwner(ctx, "bob")
	if err != nil || len(configs) != 0 || configs == nil {
		t.Fatalf("expected empty list: %v %v", configs, err)
	}
	_, err = repository.FindByOwner(ctx, "bob", "config")
	if !errors.Is(err, application.ErrNotFound) {
		t.Fatalf("foreign config: %v", err)
	}
	config, err := repository.FindByOwner(ctx, "alice", "config")
	if err != nil || config.RemoteID != "remote" {
		t.Fatalf("config=%+v err=%v", config, err)
	}
	state, err := repository.Load(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if saved, err = repository.Save(ctx, state, 0); err != nil || saved {
		t.Fatalf("stale writer accepted: %v %v", saved, err)
	}
	files, err := vault.New(NewFileStore(client.Database(database)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err = files.Put(ctx, "alice", "config", "generation", []byte("secret-config")); err != nil {
		t.Fatal(err)
	}
	file, err := files.Get(ctx, "alice", "config", "generation")
	if err != nil || string(file) != "secret-config" {
		t.Fatal("file roundtrip failed", err)
	}

}
