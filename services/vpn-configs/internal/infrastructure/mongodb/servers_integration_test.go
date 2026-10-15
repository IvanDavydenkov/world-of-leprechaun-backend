package mongodb

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"go.mongodb.org/mongo-driver/v2/bson"
	"golang.org/x/crypto/ssh"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/infrastructure/vault"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestServerRegistryMongoPersistenceAndCAS(t *testing.T) {
	uri := os.Getenv("MONGO_TEST_URI")
	if uri == "" {
		t.Skip("set MONGO_TEST_URI for disposable test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dbName := fmt.Sprintf("leprechaun_test_servers_%d", time.Now().UnixNano())
	client, _, err := Open(ctx, uri, dbName)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		client.Database(dbName).Drop(cleanup)
		client.Disconnect(cleanup)
	}()
	db := client.Database(dbName)
	repo := NewServerRepository(db)
	secrets, _ := vault.New(nil, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	registry := application.NewServerRegistry(repo, secrets, integrationAccess{}, func() string { return "server1" }, time.Now)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(pub)
	created, err := registry.Create(ctx, "admin", application.ServerFields{Name: "Test", SSHAddress: "vpn.example:22", SSHUsername: "root", Password: "integration-password", SSHHostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), PublicEndpoint: "vpn.example:39977", Container: "amnezia-awg2", Interface: "awg0"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.Collection("vpn_servers").FindOne(ctx, bson.M{"_id": created.ID}).Raw()
	if err != nil || strings.Contains(string(raw), "integration-password") {
		t.Fatal("plaintext persisted", err)
	}
	restarted := application.NewServerRegistry(NewServerRepository(db), secrets, integrationAccess{}, nil, time.Now)
	read, err := restarted.Get(ctx, "admin", created.ID)
	if err != nil || !read.PasswordSet || read.Revision != 1 {
		t.Fatal("restart failed", err)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := "Updated"
			_, e := restarted.Patch(ctx, "admin", created.ID, application.ServerPatch{ExpectedRevision: 1, Name: &name})
			if e == nil {
				winners.Add(1)
			} else if e != application.ErrConflict {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("CAS allowed multiple updates", winners.Load())
	}
	stored, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := secrets.DecryptServerPassword(created.ID, stored.PasswordCiphertext)
	if err != nil || plain != "integration-password" {
		t.Fatal("password not preserved", err)
	}
}
