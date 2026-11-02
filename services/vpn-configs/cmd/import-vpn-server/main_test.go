package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"leprechaun/vpn-configs/internal/domain"
	"leprechaun/vpn-configs/internal/infrastructure/mongodb"
	"leprechaun/vpn-configs/internal/infrastructure/vault"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLegacyCLIIsOfflineIdempotentAndPreservesFiles(t *testing.T) {
	uri := os.Getenv("MONGO_TEST_URI")
	if uri == "" {
		t.Skip("set MONGO_TEST_URI for disposable database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database := fmt.Sprintf("leprechaun_test_import_%d", time.Now().UnixNano())
	client, accounts, err := mongodb.Open(ctx, uri, database)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		client.Database(database).Drop(cleanup)
		client.Disconnect(cleanup)
	}()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(pub)
	known := filepath.Join(t.TempDir(), "known_hosts")
	os.WriteFile(known, append([]byte("vpn.example "), ssh.MarshalAuthorizedKey(key)...), 0600)
	encryptionKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for name, value := range map[string]string{"MONGO_URI": uri, "MONGO_DATABASE": database, "VPN_HOST_ADDRESS": "vpn.example:22", "VPN_PUBLIC_ENDPOINT": "vpn.example:48892", "VPN_HOST_USERNAME": "root", "VPN_HOST_PASSWORD": "test-password", "VPN_KNOWN_HOSTS_FILE": known, "VPN_CONFIG_ENCRYPTION_KEY": encryptionKey} {
		t.Setenv(name, value)
	}
	_, err = accounts.Save(ctx, domain.Account{OwnerID: "owner", Configs: []domain.ManagedConfig{{ID: "stable-id", Name: "Phone", Generation: "old-generation", RemoteID: "original-peer", Desired: true, Provisioned: true, Version: 7}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := vault.New(mongodb.NewFileStore(client.Database(database)), encryptionKey)
	files.Put(ctx, "owner", "stable-id", "old-generation", []byte("original-private-file"))
	oldArgs := os.Args
	oldFlags := flag.CommandLine
	defer func() { os.Args = oldArgs; flag.CommandLine = oldFlags }()
	invoke := func(args ...string) {
		t.Helper()
		os.Args = append([]string{"import-vpn-server"}, args...)
		flag.CommandLine = flag.NewFlagSet("import-vpn-server", flag.ContinueOnError)
		if e := run(); e != nil {
			t.Fatal(e)
		}
	}
	invoke("-create-server")
	servers, _ := mongodb.NewServerRepository(client.Database(database)).List(ctx)
	if len(servers) != 0 {
		t.Fatal("dry run mutated registry")
	}
	invoke("-create-server", "-apply", "-confirm-workers-stopped")
	invoke("-create-server", "-apply", "-confirm-workers-stopped")
	servers, _ = mongodb.NewServerRepository(client.Database(database)).List(ctx)
	a, err := accounts.Load(ctx, "owner")
	if err != nil || len(servers) != 1 || a.Configs[0].ID != "stable-id" || a.Configs[0].Version != 7 || len(a.Configs[0].Issuances) != 1 || a.Configs[0].Issuances[0].RemoteID != "original-peer" {
		t.Fatal("migration changed config identity", err)
	}
	file, err := files.Get(ctx, "owner", "stable-id", "old-generation")
	if err != nil || string(file) != "original-private-file" {
		t.Fatal("migration changed file", err)
	}
}
