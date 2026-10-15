package application

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type blockingProvisioner struct {
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

func (h *blockingProvisioner) Create(ctx context.Context, generation, owner, name string) (Provisioned, error) {
	if h.calls.Add(1) == 1 {
		close(h.entered)
	}
	select {
	case <-h.release:
		return Provisioned{RemoteID: "peer", File: []byte("file")}, nil
	case <-ctx.Done():
		return Provisioned{}, ctx.Err()
	}
}
func (h *blockingProvisioner) Revoke(context.Context, string, string) error { return nil }
func TestWorkerLeasePreventsConcurrentHostCalls(t *testing.T) {
	m, _, _ := setupManager()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	host := &blockingProvisioner{entered: make(chan struct{}), release: make(chan struct{})}
	m.host = host
	batch, err := m.SubmitBatch(ctx, "admin", "user", "one", BatchRequest{Scope: "create", Count: 1})
	if err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { _, err := m.ProcessNext(ctx, "user"); first <- err }()
	select {
	case <-host.entered:
	case <-ctx.Done():
		t.Fatal("first worker did not start")
	}
	result, err := m.BatchStatus(ctx, "admin", "user", batch.ID)
	if err != nil || result.Status != "running" {
		t.Fatalf("%+v %v", result, err)
	}
	second := make(chan bool, 1)
	go func() { worked, _ := m.ProcessNext(ctx, "user"); second <- worked }()
	select {
	case worked := <-second:
		if worked {
			t.Fatal("second worker claimed live lease")
		}
	case <-ctx.Done():
		t.Fatal("second worker made a duplicate blocking call")
	}
	close(host.release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if host.calls.Load() != 1 {
		t.Fatal("duplicate host calls")
	}
}
