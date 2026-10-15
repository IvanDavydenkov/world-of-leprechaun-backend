package application

import (
	"context"
	"leprechaun/vpn-configs/internal/domain"
	"testing"
)

func TestPartialBulkRevocationMarksOnlyConfirmedRecordsDeleted(t *testing.T) {
	m, states, host := setupManager()
	ctx := context.Background()
	first, err := m.Submit(ctx, "admin", "user", "first", domain.CreateConfig, "", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Submit(ctx, "admin", "user", "second", domain.CreateConfig, "", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = m.ProcessNext(ctx, "user"); err != nil {
			t.Fatal(err)
		}
	}
	_, err = m.Submit(ctx, "admin", "user", "all", domain.RevokeAllConfigs, "", "")
	if err != nil {
		t.Fatal(err)
	}
	host.failGeneration = second.Generation
	if _, err = m.ProcessNext(ctx, "user"); err == nil {
		t.Fatal("expected partial failure")
	}
	state, _ := states.Load(ctx, "user")
	if state.Configs[0].ID != first.ConfigID || state.Configs[0].State() != "deleted" {
		t.Fatal("confirmed deletion not persisted")
	}
	if state.Configs[1].DeletedAt != nil || state.Configs[1].State() != "deleting" {
		t.Fatal("unconfirmed deletion marked successful")
	}
	if !state.Draining() {
		t.Fatal("bulk operation finished prematurely")
	}
	host.failGeneration = ""
	if _, err = m.ProcessNext(ctx, "user"); err != nil {
		t.Fatal(err)
	}
	state, _ = states.Load(ctx, "user")
	if state.Draining() || state.Configs[1].State() != "deleted" {
		t.Fatal("bulk retry incomplete")
	}
}
