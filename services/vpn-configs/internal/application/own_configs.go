package application

import (
	"context"
	"errors"
	"leprechaun/vpn-configs/internal/domain"
	"sort"
	"time"
)

type OwnConfig struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Status            string    `json:"status"`
	Version           int       `json:"version"`
	CreatedAt         time.Time `json:"created_at"`
	DownloadAvailable bool      `json:"download_available"`
	DownloadURL       *string   `json:"download_url"`
}

func (m *Manager) OwnConfigs(ctx context.Context, owner string) ([]OwnConfig, error) {
	if err := m.access.RequireUser(ctx, owner); err != nil {
		return nil, err
	}
	state, err := m.store.Load(ctx, owner)
	if err != nil {
		return nil, err
	}
	result := make([]OwnConfig, 0)
	for _, c := range state.Configs {
		if c.State() != "active" {
			continue
		}
		_, err := m.files.Get(ctx, owner, c.ID, c.Generation)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, ErrUnavailable
		}
		item := OwnConfig{ID: c.ID, Name: c.Name, Status: "active", Version: c.Version, CreatedAt: c.CreatedAt, DownloadAvailable: err == nil}
		if item.DownloadAvailable {
			url := "/me/configs/" + c.ID + "/download"
			item.DownloadURL = &url
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}
func (m *Manager) OwnDownload(ctx context.Context, owner, id string) ([]byte, error) {
	if err := m.access.RequireUser(ctx, owner); err != nil {
		return nil, err
	}
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	current := func() (domain.ManagedConfig, error) {
		state, err := m.store.Load(ctx, owner)
		if err != nil {
			return domain.ManagedConfig{}, err
		}
		for _, c := range state.Configs {
			if c.ID == id && c.State() == "active" {
				return c, nil
			}
		}
		return domain.ManagedConfig{}, ErrNotFound
	}
	config, err := current()
	if err != nil {
		return nil, err
	}
	file, err := m.files.Get(ctx, owner, id, config.Generation)
	if err != nil {
		return nil, err
	}
	latest, err := current()
	if err != nil {
		return nil, err
	}
	if latest.Generation != config.Generation {
		return nil, ErrNotFound
	}
	return file, nil
}
