package application

import (
	"context"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/v2/bson"
	"leprechaun/vpn-configs/internal/domain"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fleetMemory struct {
	mu    sync.Mutex
	state domain.FleetControl
}

func (m *fleetMemory) LoadFleet(context.Context) (domain.FleetControl, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, _ := bson.Marshal(m.state)
	var s domain.FleetControl
	bson.Unmarshal(data, &s)
	return s, nil
}
func (m *fleetMemory) SaveFleet(_ context.Context, s domain.FleetControl, revision int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Revision != revision {
		return false, nil
	}
	s.Revision++
	data, _ := bson.Marshal(s)
	bson.Unmarshal(data, &m.state)
	return true, nil
}

type fleetAccounts struct{ *memoryStates }

func (m fleetAccounts) OwnersAfter(_ context.Context, after string, limit int64) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := []string{}
	for id := range m.accounts {
		if id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > int(limit) {
		ids = ids[:limit]
	}
	return ids, nil
}

type fleetServers map[string]domain.VPNServer

func (m fleetServers) Create(_ context.Context, s domain.VPNServer) error { m[s.ID] = s; return nil }
func (m fleetServers) Get(_ context.Context, id string) (domain.VPNServer, error) {
	s, ok := m[id]
	if !ok {
		return s, ErrNotFound
	}
	return s, nil
}
func (m fleetServers) List(context.Context) ([]domain.VPNServer, error) {
	out := []domain.VPNServer{}
	for _, s := range m {
		out = append(out, s)
	}
	return out, nil
}
func (m fleetServers) Update(_ context.Context, s domain.VPNServer, r int64) (bool, error) {
	if m[s.ID].Revision != r {
		return false, nil
	}
	m[s.ID] = s
	return true, nil
}

type memoryCoordinator struct{ mu sync.Mutex }
type memoryCoordinatorKey struct{}

func (g *memoryCoordinator) With(ctx context.Context, fn func(context.Context) error) error {
	if ctx.Value(memoryCoordinatorKey{}) == g {
		return fn(ctx)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return fn(context.WithValue(ctx, memoryCoordinatorKey{}, g))
}

type fleetAccess struct{}

func (fleetAccess) RequireAdmin(_ context.Context, id string) error {
	if id != "admin" {
		return ErrForbidden
	}
	return nil
}
func (fleetAccess) RequireUser(_ context.Context, id string) error {
	if id == "" {
		return ErrNotFound
	}
	return nil
}

type fleetHostStub struct {
	peers            map[string]Provisioned
	creates, revokes int
	failName         string
	missingJournal   bool
	needsInput       bool
}
type serverHostStub struct {
	host *fleetHostStub
	id   string
}

func (h serverHostStub) Create(_ context.Context, generation, owner, name string) (Provisioned, error) {
	if name == h.host.failName {
		return Provisioned{}, errors.New("unreachable")
	}
	key := h.id + "/" + generation
	if v, ok := h.host.peers[key]; ok {
		return v, nil
	}
	h.host.creates++
	v := Provisioned{RemoteID: key, File: []byte("file:" + key)}
	h.host.peers[key] = v
	return v, nil
}
func (h serverHostStub) Revoke(_ context.Context, generation, remote string) error {
	delete(h.host.peers, h.id+"/"+generation)
	h.host.revokes++
	return nil
}
func (h *fleetHostStub) ForServer(_ context.Context, s domain.VPNServer) (Provisioner, error) {
	return serverHostStub{h, s.ID}, nil
}
func (h *fleetHostStub) Verify(_ context.Context, s domain.VPNServer, generation, remote string) error {
	if h.missingJournal {
		return Fault("helper_journal_missing", ErrUnavailable)
	}
	if _, ok := h.peers[s.ID+"/"+generation]; !ok {
		return Fault("binding_missing_on_host", ErrUnavailable)
	}
	return nil
}
func (h *fleetHostStub) Prepare(_ context.Context, s domain.VPNServer, selection domain.Selection, progress func(string, string)) (Prepared, error) {
	for _, step := range []string{"verify_host_key", "authenticate", "inspect_ubuntu", "inspect_docker", "discover_awg"} {
		progress(step, "succeeded")
	}
	if h.needsInput && selection.CandidateID == "" {
		return Prepared{Discovery: &domain.Discovery{Candidates: []domain.Candidate{{ID: "candidate", Container: "amnezia-awg2", Interface: "awg0", Ports: []int{48892}}}, Required: []string{"candidate_id", "udp_port"}}}, nil
	}
	progress("install_helper", "succeeded")
	progress("verify_helper", "succeeded")
	return Prepared{HostKey: s.SSHHostKey, Fingerprint: s.SSHHostFingerprint, Endpoint: "vpn.example:48892", Container: "amnezia-awg2", Interface: "awg0", HelperVersion: "2.0.0", HelperHash: "hash"}, nil
}
func setupFleet(t *testing.T) (*Fleet, *fleetHostStub, *fileVaultStub) {
	t.Helper()
	revision := int64(1)
	servers := fleetServers{}
	for _, id := range []string{"a", "b", "c"} {
		servers[id] = domain.VPNServer{ID: id, Name: id, Revision: 1, PreparationStatus: "ready", PreparedRevision: &revision}
	}
	accounts := fleetAccounts{&memoryStates{accounts: map[string]domain.Account{}}}
	store := &fleetMemory{state: domain.FleetControl{SchemaReady: true, Routing: domain.Routing{DefaultServerID: "a", Revision: 1}}}
	host := &fleetHostStub{peers: map[string]Provisioned{}}
	files := &fileVaultStub{files: map[string][]byte{}}
	var seq atomic.Int64
	f := &Fleet{Store: store, Accounts: accounts, Servers: servers, Access: fleetAccess{}, Host: host, Files: files, Guard: &memoryCoordinator{}, NewID: func() string { return fmt.Sprintf("id%08d", seq.Add(1)) }, Now: time.Now}
	ctx := context.Background()
	a := domain.Account{OwnerID: "user", Revision: 1}
	for i, name := range []string{"one", "two"} {
		id := fmt.Sprintf("cfg%d", i+1)
		g := "original-" + id
		p, _ := serverHostStub{host, "a"}.Create(ctx, g, "user", name)
		files.Put(ctx, "user", id, g, p.File)
		a.Configs = append(a.Configs, domain.ManagedConfig{ID: id, Name: name, ServerID: "a", Generation: g, RemoteID: p.RemoteID, Desired: true, Provisioned: true, Version: 1, Issuances: []domain.Issuance{{ServerID: "a", Generation: g, RemoteID: p.RemoteID, State: "active"}}})
	}
	accounts.accounts["user"] = a
	return f, host, files
}
func drainFleet(t *testing.T, f *Fleet) {
	t.Helper()
	for n := 0; n < 100; n++ {
		worked, err := f.Process(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			return
		}
	}
	t.Fatal("fleet worker did not drain")
}
func switchFleet(t *testing.T, f *Fleet, key, target string) domain.FleetOperation {
	t.Helper()
	s, _ := f.Store.LoadFleet(context.Background())
	o, err := f.SubmitSwitch(context.Background(), "admin", key, target, s.Routing.Revision)
	if err != nil {
		t.Fatal(err)
	}
	drainFleet(t, f)
	o, err = f.Status(context.Background(), "admin", o.ID)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func TestFleetSwitchReturnReuseAndExplicitRevocation(t *testing.T) {
	f, host, _ := setupFleet(t)
	ctx := context.Background()
	original := host.creates
	toB := switchFleet(t, f, "to-b", "b")
	if toB.Status != "succeeded" || host.creates != original+2 || host.revokes != 0 {
		t.Fatal(toB.Status, host.creates, host.revokes)
	}
	back := switchFleet(t, f, "back-a", "a")
	if back.Status != "succeeded" || host.creates != original+2 || host.revokes != 0 {
		t.Fatal("return recreated or revoked", host.creates, host.revokes)
	}
	for _, item := range back.Items {
		if item.Action == nil || *item.Action != "reused" {
			t.Fatal("not reused")
		}
	}
	o, err := f.SubmitRevoke(ctx, "admin", "revoke-b", RevokeRequest{Scope: "server", ServerID: "b", All: true})
	if err != nil {
		t.Fatal(err)
	}
	drainFleet(t, f)
	o, _ = f.Status(ctx, "admin", o.ID)
	if o.Status != "succeeded" || host.revokes != 2 {
		t.Fatal(o.Status, host.revokes)
	}
	switchFleet(t, f, "b-again", "b")
	if host.creates != original+4 {
		t.Fatal("revoked bindings must be reissued")
	}
	if _, err = f.SubmitRevoke(ctx, "admin", "bad-revoke", RevokeRequest{Scope: "server", ServerID: "b", All: true}); ErrorCode(err) != "server_in_use" {
		t.Fatal(err)
	}
	manager := NewManager(f.Accounts, f.Access, nil, f.Files, f.NewID, time.Now)
	manager.UseFleet(f)
	batch, err := manager.SubmitBatch(ctx, "admin", "user", "delete-all", BatchRequest{Scope: "all"})
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 10; n++ {
		worked, e := manager.ProcessNext(ctx, "user")
		if e != nil {
			t.Fatal(e)
		}
		if !worked {
			break
		}
	}
	batch, err = manager.BatchStatus(ctx, "admin", "user", batch.ID)
	if err != nil || batch.Status != "succeeded" || len(host.peers) != 0 {
		t.Fatal("all-server deletion incomplete", batch.Status, len(host.peers), err)
	}
	a, _ := f.Accounts.Load(ctx, "user")
	oldGeneration := a.Configs[0].Generation
	op, e := manager.Submit(ctx, "admin", "user", "reactivate-after-global-delete", domain.ReactivateConfig, a.Configs[0].ID, "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = manager.ProcessNext(ctx, "user"); e != nil {
		t.Fatal(e)
	}
	a, _ = f.Accounts.Load(ctx, "user")
	if a.Configs[0].Generation == oldGeneration || a.Configs[0].Generation != op.Generation || a.Configs[0].ServerID != "b" || len(host.peers) != 1 {
		t.Fatal("reactivation restored old generation")
	}
}
func TestFleetPartialAndSupersededRetry(t *testing.T) {
	f, h, _ := setupFleet(t)
	ctx := context.Background()
	h.failName = "two"
	o := switchFleet(t, f, "partial-b", "b")
	if o.Status != "partial" || o.Counts.Succeeded != 1 || o.Counts.Failed != 1 {
		t.Fatal(o)
	}
	s, _ := f.Store.LoadFleet(ctx)
	if s.Routing.DefaultServerID != "b" {
		t.Fatal("default rolled back")
	}
	again, err := f.SubmitSwitch(ctx, "admin", "partial-b", "b", 1)
	if err != nil || again.ID != o.ID {
		t.Fatal("lost response duplicated operation", err)
	}
	switchFleet(t, f, "return-a", "a")
	if _, err = f.Command(ctx, "admin", o.ID, "retry-old", "retry", 0, domain.Selection{}); ErrorCode(err) != "switch_superseded" {
		t.Fatal(err)
	}
	if h.revokes != 0 {
		t.Fatal("implicit revocation")
	}
}
func TestFleetRestartsReuseReservedGenerationAfterVaultFailure(t *testing.T) {
	f, h, files := setupFleet(t)
	files.fail = true
	o := switchFleet(t, f, "storage-error", "b")
	if o.Status != "failed" {
		t.Fatal(o.Status)
	}
	created := h.creates
	files.fail = false
	restarted := *f
	if _, err := restarted.Command(context.Background(), "admin", o.ID, "retry-storage", "retry", 0, domain.Selection{}); err != nil {
		t.Fatal(err)
	}
	drainFleet(t, &restarted)
	o, _ = restarted.Status(context.Background(), "admin", o.ID)
	if o.Status != "succeeded" || h.creates != created || h.revokes != 0 {
		t.Fatal("restart duplicated peers", o.Status, h.creates, created)
	}
}
func TestFleetMissingJournalNeverSilentlyReissues(t *testing.T) {
	f, h, _ := setupFleet(t)
	switchFleet(t, f, "b", "b")
	h.missingJournal = true
	created := h.creates
	o := switchFleet(t, f, "back", "a")
	if o.Status != "failed" || h.creates != created || h.revokes != 0 {
		t.Fatal("missing journal hidden")
	}
	a, _ := f.Accounts.Load(context.Background(), "user")
	for _, c := range a.Configs {
		if c.ServerID != "b" {
			t.Fatal("failed target selected")
		}
	}
}
func TestFleetPrepareResumeAndLegacyImport(t *testing.T) {
	f, h, _ := setupFleet(t)
	ctx := context.Background()
	h.needsInput = true
	o, err := f.SubmitPrepare(ctx, "admin", "c", "prepare", 1)
	if err != nil {
		t.Fatal(err)
	}
	drainFleet(t, f)
	o, _ = f.Status(ctx, "admin", o.ID)
	if o.Status != "needs_input" {
		t.Fatal(o.Status)
	}
	if _, err = f.Command(ctx, "admin", o.ID, "resume", "resume", 1, domain.Selection{CandidateID: "candidate", UDPPort: 48892}); err != nil {
		t.Fatal(err)
	}
	drainFleet(t, f)
	server, _ := f.Servers.Get(ctx, "c")
	if !ready(server) {
		t.Fatal("server not ready")
	}
	a, _ := f.Accounts.Load(ctx, "user")
	for i := range a.Configs {
		a.Configs[i].ServerID = ""
		a.Configs[i].Issuances = nil
	}
	f.Accounts.Save(ctx, a, a.Revision)
	s, _ := f.Store.LoadFleet(ctx)
	s.SchemaReady = false
	f.Store.SaveFleet(ctx, s, s.Revision)
	before := h.creates
	report, err := f.ImportLegacy(ctx, "a", false)
	if err != nil || report.Configs != 2 || report.Applied {
		t.Fatal(report, err)
	}
	report, err = f.ImportLegacy(ctx, "a", true)
	if err != nil || !report.Applied || h.creates != before {
		t.Fatal(report, err)
	}
	report, err = f.ImportLegacy(ctx, "a", true)
	if err != nil || report.Configs != 0 {
		t.Fatal("import not idempotent", err)
	}
}
func TestFleetConcurrentSwitchAndDeletionDuringSwitch(t *testing.T) {
	f, _, _ := setupFleet(t)
	ctx := context.Background()
	var success atomic.Int32
	var wg sync.WaitGroup
	for _, target := range []string{"b", "c"} {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.SubmitSwitch(ctx, "admin", target, target, 1); err == nil {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatal("multiple routing transitions")
	}
	manager := NewManager(f.Accounts, f.Access, nil, f.Files, f.NewID, time.Now)
	manager.UseFleet(f)
	_, err := manager.SubmitBatch(ctx, "admin", "user", "delete-first", BatchRequest{Scope: "single", ConfigIDs: []string{"cfg1"}})
	if err != nil {
		t.Fatal(err)
	}
	drainFleet(t, f)
	a, _ := f.Accounts.Load(ctx, "user")
	if a.Configs[0].Desired {
		t.Fatal("switch resurrected deleted config")
	}
}

func TestFleetThirdServerAndPinnedNewIssuance(t *testing.T) {
	f, h, _ := setupFleet(t)
	switchFleet(t, f, "to-b", "b")
	switchFleet(t, f, "to-c", "c")
	if h.creates != 6 || h.revokes != 0 {
		t.Fatal("third server affected old peers")
	}
	m := NewManager(f.Accounts, f.Access, nil, f.Files, f.NewID, time.Now)
	m.UseFleet(f)
	ctx := context.Background()
	batch, err := m.SubmitBatch(ctx, "admin", "user", "new-on-c", BatchRequest{Scope: "create", Count: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.ProcessNext(ctx, "user")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := f.Accounts.Load(ctx, "user")
	for _, c := range a.Configs {
		if c.ID == batch.Items[0].ConfigID && c.ServerID != "c" {
			t.Fatal("new issuance used old env/default")
		}
	}
}

func TestFleetOldServerRevocationPlanCannotRevokeNewGeneration(t *testing.T) {
	f, h, files := setupFleet(t)
	ctx := context.Background()
	a, _ := f.Accounts.Load(ctx, "user")
	old := a.Configs[0].Generation
	a.Configs[0].Issuances[0].State = "revoked"
	delete(h.peers, "a/"+old)
	fresh, _ := serverHostStub{h, "a"}.Create(ctx, "newer-generation", "user", "one")
	files.Put(ctx, "user", a.Configs[0].ID, "newer-generation", fresh.File)
	a.Configs[0].Issuances = append(a.Configs[0].Issuances, domain.Issuance{ServerID: "a", Generation: "newer-generation", RemoteID: fresh.RemoteID, State: "active"})
	f.Accounts.Save(ctx, a, a.Revision)
	item := domain.FleetItem{OwnerID: "user", ConfigID: a.Configs[0].ID, GenerationIDs: []string{old}}
	o := domain.FleetOperation{Server: ptr("a"), Scope: "server"}
	if err := f.revokeItem(ctx, &o, &item); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.peers["a/newer-generation"]; !ok {
		t.Fatal("old retry revoked a new generation")
	}
}
