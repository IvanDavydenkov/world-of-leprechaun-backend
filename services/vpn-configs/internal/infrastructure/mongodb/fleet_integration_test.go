package mongodb

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"go.mongodb.org/mongo-driver/v2/bson"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/domain"
	"leprechaun/vpn-configs/internal/infrastructure/vault"
	"os"
	"testing"
	"time"
)

type integrationFleetHost struct {
	peers            map[string]application.Provisioned
	creates, revokes int
}
type integrationServerHost struct {
	all    *integrationFleetHost
	server string
}

func (h integrationServerHost) Create(_ context.Context, generation, owner, name string) (application.Provisioned, error) {
	key := h.server + "/" + generation
	if p, ok := h.all.peers[key]; ok {
		return p, nil
	}
	p := application.Provisioned{RemoteID: key, File: []byte("private-vpn-file:" + key)}
	h.all.peers[key] = p
	h.all.creates++
	return p, nil
}
func (h integrationServerHost) Revoke(_ context.Context, generation, remote string) error {
	delete(h.all.peers, h.server+"/"+generation)
	h.all.revokes++
	return nil
}
func (h *integrationFleetHost) ForServer(_ context.Context, s domain.VPNServer) (application.Provisioner, error) {
	return integrationServerHost{h, s.ID}, nil
}
func (h *integrationFleetHost) Verify(_ context.Context, s domain.VPNServer, generation, remote string) error {
	if _, ok := h.peers[s.ID+"/"+generation]; !ok {
		return application.ErrNotFound
	}
	return nil
}
func (h *integrationFleetHost) Prepare(context.Context, domain.VPNServer, domain.Selection, func(string, string)) (application.Prepared, error) {
	return application.Prepared{}, nil
}
func TestFleetMongoLifecyclePersistenceAndLeaseFencing(t *testing.T) {
	uri := os.Getenv("MONGO_TEST_URI")
	if uri == "" {
		t.Skip("set MONGO_TEST_URI for disposable MongoDB test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	database := fmt.Sprintf("leprechaun_test_fleet_%d", time.Now().UnixNano())
	client, accounts, err := Open(ctx, uri, database)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		client.Database(database).Drop(cleanup)
		client.Disconnect(cleanup)
	}()
	db := client.Database(database)
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	files, _ := vault.New(NewFileStore(db), key)
	servers := NewServerRepository(db)
	revision := int64(1)
	for _, id := range []string{"a", "b"} {
		servers.Create(ctx, domain.VPNServer{ID: id, Revision: 1, PreparationStatus: "ready", PreparedRevision: &revision})
	}
	host := &integrationFleetHost{peers: map[string]application.Provisioned{}}
	fleet := &application.Fleet{Store: NewFleetStore(db), Accounts: accounts, Servers: servers, Access: integrationAccess{}, Files: files, Host: host, Guard: NewCoordinator(db), NewID: rand.Text, Now: time.Now}
	if err = fleet.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	drain := func() {
		t.Helper()
		for n := 0; n < 100; n++ {
			worked, e := fleet.Process(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if !worked {
				return
			}
		}
		t.Fatal("worker stuck")
	}
	switchTo := func(target, key string) domain.FleetOperation {
		t.Helper()
		state, _ := fleet.Store.LoadFleet(ctx)
		o, e := fleet.SubmitSwitch(ctx, "admin", key, target, state.Routing.Revision)
		if e != nil {
			t.Fatal(e)
		}
		drain()
		o, e = fleet.Status(ctx, "admin", o.ID)
		if e != nil || o.Status != "succeeded" {
			t.Fatal(o.Status, e)
		}
		return o
	}
	switchTo("a", "first-default")
	manager := application.NewManager(accounts, integrationAccess{}, nil, files, rand.Text, time.Now)
	manager.UseFleet(fleet)
	batch, err := manager.SubmitBatch(ctx, "admin", "owner", "create", application.BatchRequest{Scope: "create", Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 5; n++ {
		worked, e := manager.ProcessNext(ctx, "owner")
		if e != nil {
			t.Fatal(e)
		}
		if !worked {
			break
		}
	}
	batch, err = manager.BatchStatus(ctx, "admin", "owner", batch.ID)
	if err != nil || batch.Status != "succeeded" {
		t.Fatal(batch.Status, err)
	}
	toB := switchTo("b", "to-b")
	fleet.Store = NewFleetStore(db)
	repeated, err := fleet.SubmitSwitch(ctx, "admin", "to-b", "b", 1)
	if err != nil || repeated.ID != toB.ID {
		t.Fatal("persisted idempotency lost", err)
	}
	switchTo("a", "back-a")
	if host.creates != 4 || host.revokes != 0 {
		t.Fatal("switch returned wrong peer count", host.creates, host.revokes)
	}
	list, err := manager.OwnConfigs(ctx, "owner")
	if err != nil || len(list) != 2 {
		t.Fatal(err)
	}
	if _, err = manager.OwnDownload(ctx, "other", list[0].ID); err != application.ErrNotFound {
		t.Fatal("foreign download allowed", err)
	}
	first := NewCoordinator(db)
	second := NewCoordinator(db)
	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- first.With(ctx, func(locked context.Context) error {
			close(entered)
			<-release
			a, e := accounts.Load(locked, "owner")
			if e != nil {
				return e
			}
			_, e = accounts.Save(locked, a, a.Revision)
			return e
		})
	}()
	<-entered
	if err = second.With(ctx, func(context.Context) error { return nil }); application.ErrorCode(err) != "server_busy" {
		t.Fatal("distributed lease not exclusive", err)
	}
	db.Collection("vpn_locks").UpdateOne(ctx, bson.M{"_id": "mutations"}, bson.M{"$set": bson.M{"until": time.Now().Add(-time.Minute)}})
	if err = second.With(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal("expired lease not recovered", err)
	}
	close(release)
	if err = <-result; application.ErrorCode(err) != "server_busy" {
		t.Fatal("stale owner allowed to persist", err)
	}
}
