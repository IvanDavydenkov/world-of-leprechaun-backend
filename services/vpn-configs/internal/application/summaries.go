package application

import (
	"context"
	"sort"
)

type ConfigCounts struct {
	Total    int `json:"total"`
	Active   int `json:"active"`
	Disabled int `json:"disabled"`
	Pending  int `json:"pending"`
}
type ConfigMetadata struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Version int    `json:"version"`
}
type TrafficSummary struct {
	Upload        *uint64 `json:"upload_bytes"`
	Download      *uint64 `json:"download_bytes"`
	Total         *uint64 `json:"total_bytes"`
	Freshness     string  `json:"freshness"`
	Coverage      string  `json:"coverage"`
	ObservedSince *string `json:"observed_since"`
	UpdatedAt     *string `json:"updated_at"`
}
type ConfigSummary struct {
	Availability string           `json:"availability"`
	Counts       *ConfigCounts    `json:"counts"`
	Configs      []ConfigMetadata `json:"configs"`
	Traffic      *TrafficSummary  `json:"traffic"`
}

func (m *Manager) ConfigSummaries(ctx context.Context, actor string, owners []string) (map[string]ConfigSummary, error) {
	if err := m.AuthorizeAdmin(ctx, actor); err != nil {
		return nil, err
	}
	if len(owners) > 100 {
		return nil, ErrInvalid
	}
	for _, owner := range owners {
		if !ValidID(owner) {
			return nil, ErrInvalid
		}
	}
	result := make(map[string]ConfigSummary, len(owners))
	for _, owner := range owners {
		account, err := m.store.Load(ctx, owner)
		if err != nil {
			return nil, err
		}
		counts := &ConfigCounts{Total: len(account.Configs)}
		configs := make([]ConfigMetadata, 0, len(account.Configs))
		for _, config := range account.Configs {
			status := config.State()
			switch status {
			case "active":
				counts.Active++
			case "deleted":
				counts.Disabled++
			default:
				counts.Pending++
			}
			configs = append(configs, ConfigMetadata{config.ID, config.Name, status, config.Version})
		}
		sort.Slice(configs, func(i, j int) bool { return configs[i].ID < configs[j].ID })
		result[owner] = ConfigSummary{Availability: "available", Counts: counts, Configs: configs, Traffic: &TrafficSummary{Freshness: "unavailable", Coverage: "unknown"}}
	}
	return result, nil
}
