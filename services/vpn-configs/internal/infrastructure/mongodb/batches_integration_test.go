package mongodb

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/infrastructure/vault"
	"os"
	"testing"
	"time"
)

type integrationAccess struct{}

func (integrationAccess) RequireAdmin(context.Context, string) error { return nil }
func (integrationAccess) RequireUser(context.Context, string) error  { return nil }

type integrationHost struct {
	creates int
	files   map[string]application.Provisioned
}

func (h *integrationHost) Create(_ context.Context, generation, owner, name string) (application.Provisioned, error) {
	if result, ok := h.files[generation]; ok {
		return result, nil
	}
	h.creates++
	result := application.Provisioned{RemoteID: "peer-" + generation, File: []byte("private-file-" + generation)}
	h.files[generation] = result
	return result, nil
}
func (h *integrationHost) Revoke(context.Context, string, string) error { return nil }
func TestBatchSurvivesManagerRestartWithEncryptedFiles(t *testing.T) {
	uri := os.Getenv("MONGO_TEST_URI")
	if uri == "" {
		t.Skip("set MONGO_TEST_URI for disposable test databases")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database := fmt.Sprintf("leprechaun_test_batch_%d", time.Now().UnixNano())
	client, store, err := Open(ctx, uri, database)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := client.Database(database).Drop(cleanup); err != nil {
			t.Error(err)
		}
		_ = client.Disconnect(cleanup)
	}()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	files, err := vault.New(NewFileStore(client.Database(database)), base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	host := &integrationHost{files: map[string]application.Provisioned{}}
	manager := application.NewManager(store, integrationAccess{}, host, files, rand.Text, time.Now)
	batch, err := manager.SubmitBatch(ctx, "admin", "owner", "batch-key", application.BatchRequest{Scope: "create", Count: 3})
	if err != nil {
		t.Fatal(err)
	}
	// Construct new application/repository objects, retaining only MongoDB and the host.
	store = NewManagedRepository(client.Database(database))
	manager = application.NewManager(store, integrationAccess{}, host, files, rand.Text, time.Now)
	for i := 0; i < 3; i++ {
		if worked, err := manager.ProcessNext(ctx, "owner"); err != nil || !worked {
			t.Fatal(worked, err)
		}
	}
	result, err := manager.BatchStatus(ctx, "admin", "owner", batch.ID)
	if err != nil || result.Status != "succeeded" || host.creates != 3 {
		t.Fatalf("%+v %v", result, err)
	}
	repeated, err := manager.SubmitBatch(ctx, "admin", "owner", "batch-key", application.BatchRequest{Scope: "create", Count: 3})
	if err != nil || repeated.ID != batch.ID {
		t.Fatal("restart duplicated batch")
	}
	state, err := store.Load(ctx, "owner")
	if err != nil || len(state.Configs) != 3 {
		t.Fatal("wrong persisted configuration count", err)
	}
	reader := application.New(store, files)
	for _, config := range state.Configs {
		content, err := reader.Download(ctx, "owner", config.ID)
		if err != nil || string(content) != "private-file-"+config.Generation {
			t.Fatal("encrypted file unavailable", err)
		}
	}
	deletion, err := manager.SubmitBatch(ctx, "admin", "owner", "delete-key", application.BatchRequest{Scope: "all"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := manager.ProcessNext(ctx, "owner"); err != nil {
			t.Fatal(err)
		}
	}
	result, err = manager.BatchStatus(ctx, "admin", "owner", deletion.ID)
	if err != nil || result.Status != "succeeded" {
		t.Fatal("delete not durable", err)
	}
	state, _ = store.Load(ctx, "owner")
	if len(state.Configs) != 3 || len(state.Active()) != 0 {
		t.Fatal("soft deletion removed metadata or left active configs")
	}
}
