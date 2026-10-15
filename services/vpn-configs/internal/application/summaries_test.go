package application

import (
	"context"
	"encoding/json"
	"leprechaun/vpn-configs/internal/domain"
	"strings"
	"testing"
	"time"
)

func TestConfigSummariesStatesAndNoSecrets(t *testing.T) {
	m, store, _ := setupManager()
	now := time.Now()
	store.accounts["user"] = domain.Account{OwnerID: "user", Configs: []domain.ManagedConfig{
		{ID: "z", Name: "Active", Desired: true, Provisioned: true, Version: 2, RemoteID: "secret-public", Generation: "secret-generation"},
		{ID: "a", Name: "Deleted", DeletedAt: &now, Version: 1},
		{ID: "c", Desired: true, Version: 1}, {ID: "d", Desired: false, Provisioned: true, Version: 1}, {ID: "e", Desired: true, Version: 2},
	}}
	result, err := m.ConfigSummaries(context.Background(), "admin", []string{"user", "empty"})
	if err != nil {
		t.Fatal(err)
	}
	s := result["user"]
	if *s.Counts != (ConfigCounts{Total: 5, Active: 1, Disabled: 1, Pending: 3}) {
		t.Fatal(s.Counts)
	}
	if s.Configs[0].ID != "a" || s.Traffic.Total != nil || s.Traffic.Freshness != "unavailable" {
		t.Fatal(s)
	}
	if result["empty"].Configs == nil || result["empty"].Counts.Total != 0 {
		t.Fatal("empty owner must have [] and zero counts")
	}
	data, _ := json.Marshal(result)
	if strings.Contains(string(data), "secret-") {
		t.Fatal("private metadata leaked")
	}
	if _, err := m.ConfigSummaries(context.Background(), "user", []string{"user"}); err != ErrForbidden {
		t.Fatal(err)
	}
}
