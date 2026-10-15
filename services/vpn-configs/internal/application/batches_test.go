package application

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func drainBatch(t *testing.T, m *Manager) {
	t.Helper()
	for i := 0; i < 100; i++ {
		worked, err := m.ProcessNext(context.Background(), "user")
		if !worked {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("worker did not drain")
}
func TestBatchCreatesExactlyNewConfigsAndConcurrentRetries(t *testing.T) {
	m, store, host := setupManager()
	ctx := context.Background()
	first, err := m.SubmitBatch(ctx, "admin", "user", "existing", BatchRequest{Scope: "create", Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	drainBatch(t, m)
	var wg sync.WaitGroup
	results := make(chan BatchResult, 12)
	failures := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := m.SubmitBatch(ctx, "admin", "user", "new", BatchRequest{Scope: "create", Count: 3})
			if err != nil {
				failures <- err
			} else {
				results <- result
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	id := ""
	for result := range results {
		if id == "" {
			id = result.ID
		}
		if result.ID != id || result.ID == first.ID {
			t.Fatal("duplicate batch identities")
		}
	}
	state, _ := store.Load(ctx, "user")
	if len(state.Configs) != 5 || len(state.Batches) != 2 {
		t.Fatalf("configs=%d batches=%d", len(state.Configs), len(state.Batches))
	}
	drainBatch(t, m)
	state, _ = store.Load(ctx, "user")
	if len(state.Active()) != 5 || host.creates != 5 {
		t.Fatal("wrong number of peers")
	}
	if _, err = m.SubmitBatch(ctx, "admin", "user", "new", BatchRequest{Scope: "create", Count: 4}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}
func TestBatchPartialCreationAndExplicitRetry(t *testing.T) {
	m, _, host := setupManager()
	ctx := context.Background()
	result, err := m.SubmitBatch(ctx, "admin", "user", "key", BatchRequest{Scope: "create", Count: 3})
	if err != nil {
		t.Fatal(err)
	}
	host.failCreate = true
	if _, err = m.ProcessNext(ctx, "user"); err == nil {
		t.Fatal("expected host failure")
	}
	host.failCreate = false
	drainBatch(t, m)
	result, err = m.BatchStatus(ctx, "admin", "user", result.ID)
	if err != nil || result.Status != "partial" || result.Succeeded != 2 || result.Failed != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	again, err := m.SubmitBatch(ctx, "admin", "user", "key", BatchRequest{Scope: "create", Count: 3})
	if err != nil || again.ID != result.ID {
		t.Fatal("retry replaced batch")
	}
	// Restarted application uses the same durable identities.
	restarted := NewManager(m.store, m.access, m.host, m.files, m.newID, time.Now)
	drainBatch(t, restarted)
	result, err = restarted.BatchStatus(ctx, "admin", "user", result.ID)
	if err != nil || result.Status != "succeeded" || host.creates != 3 {
		t.Fatalf("%+v creates=%d err=%v", result, host.creates, err)
	}
}
func TestSelectedDeleteValidatesWholeSetBeforeMutation(t *testing.T) {
	m, store, _ := setupManager()
	ctx := context.Background()
	_, err := m.SubmitBatch(ctx, "admin", "user", "create", BatchRequest{Scope: "create", Count: 3})
	if err != nil {
		t.Fatal(err)
	}
	drainBatch(t, m)
	state, _ := store.Load(ctx, "user")
	id := state.Configs[0].ID
	_, err = m.SubmitBatch(ctx, "admin", "user", "bad", BatchRequest{Scope: "selected", ConfigIDs: []string{id, "missing"}})
	if !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	state, _ = store.Load(ctx, "user")
	if len(state.Active()) != 3 || len(state.Batches) != 1 {
		t.Fatal("partial mutation before validation")
	}
	result, err := m.SubmitBatch(ctx, "admin", "user", "selected", BatchRequest{Scope: "selected", ConfigIDs: []string{id, state.Configs[1].ID}})
	if err != nil {
		t.Fatal(err)
	}
	drainBatch(t, m)
	result, _ = m.BatchStatus(ctx, "admin", "user", result.ID)
	state, _ = store.Load(ctx, "user")
	if result.Succeeded != 2 || len(state.Active()) != 1 || len(state.Configs) != 3 {
		t.Fatal("selected revocation failed")
	}
	result, err = m.SubmitBatch(ctx, "admin", "user", "deleted", BatchRequest{Scope: "single", ConfigIDs: []string{id}})
	if err != nil || result.Status != "succeeded" {
		t.Fatalf("already deleted: %+v %v", result, err)
	}
}
func TestDeleteAllCoversQueuedCreationsAndBlocksNewOnes(t *testing.T) {
	m, store, host := setupManager()
	ctx := context.Background()
	_, err := m.SubmitBatch(ctx, "admin", "user", "create", BatchRequest{Scope: "create", Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	deletion, err := m.SubmitBatch(ctx, "admin", "user", "all", BatchRequest{Scope: "all"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.SubmitBatch(ctx, "admin", "user", "blocked", BatchRequest{Scope: "create", Count: 1}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	drainBatch(t, m)
	state, _ := store.Load(ctx, "user")
	result, _ := m.BatchStatus(ctx, "admin", "user", deletion.ID)
	if result.Status != "succeeded" || state.Draining() || len(state.Active()) != 0 || len(host.revoked) != 2 {
		t.Fatalf("%+v", result)
	}
	for _, config := range state.Configs {
		if config.DeletedAt == nil {
			t.Fatal("record not soft deleted")
		}
	}
	if _, err = m.SubmitBatch(ctx, "admin", "user", "later", BatchRequest{Scope: "create", Count: 1}); err != nil {
		t.Fatal(err)
	}
}
func TestBatchValidationAndEmptyDelete(t *testing.T) {
	m, store, _ := setupManager()
	ctx := context.Background()
	for _, count := range []int{-1, 0, 21} {
		if _, err := m.SubmitBatch(ctx, "admin", "user", "bad", BatchRequest{Scope: "create", Count: count}); !errors.Is(err, ErrInvalid) {
			t.Fatal(count, err)
		}
	}
	if _, err := m.SubmitBatch(ctx, "user", "user", "bad", BatchRequest{Scope: "create", Count: 1}); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if _, err := m.SubmitBatch(ctx, "admin", "missing", "bad", BatchRequest{Scope: "create", Count: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	result, err := m.SubmitBatch(ctx, "admin", "user", "empty", BatchRequest{Scope: "all"})
	if err != nil || result.Status != "succeeded" || result.Requested != 0 {
		t.Fatalf("%+v %v", result, err)
	}
	if _, err = m.SubmitBatch(ctx, "admin", "user", "max", BatchRequest{Scope: "create", Count: 20}); err != nil {
		t.Fatal(err)
	}
	state, _ := store.Load(ctx, "user")
	if len(state.Configs) != 20 {
		t.Fatal("upper bound rejected")
	}
}
func TestExpiredClaimRecoveredAfterRestart(t *testing.T) {
	m, store, host := setupManager()
	ctx := context.Background()
	batch, err := m.SubmitBatch(ctx, "admin", "user", "one", BatchRequest{Scope: "create", Count: 1})
	if err != nil {
		t.Fatal(err)
	}
	state, _ := store.Load(ctx, "user")
	expiry := time.Now().Add(-time.Minute)
	state.Operations[0].AttemptID = "dead"
	state.Operations[0].ProcessingUntil = &expiry
	if saved, err := store.Save(ctx, state, state.Revision); err != nil || !saved {
		t.Fatal(err)
	}
	drainBatch(t, m)
	result, _ := m.BatchStatus(ctx, "admin", "user", batch.ID)
	if result.Status != "succeeded" || host.creates != 1 {
		t.Fatal("expired lease not recovered")
	}
}
