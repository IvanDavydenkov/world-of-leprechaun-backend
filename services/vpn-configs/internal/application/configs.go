package application

import (
	"context"
	"errors"
	"fmt"

	"leprechaun/vpn-configs/internal/domain"
)

var ErrForbidden = errors.New("config access forbidden")
var ErrNotFound = errors.New("config not found")

// Repository implementations must filter by both owner ID and config ID.
type Repository interface {
	ListByOwner(context.Context, string) ([]domain.Config, error)
	FindByOwner(context.Context, string, string) (domain.Config, error)
}

type Service struct {
	repository Repository
	files      FileVault
}

func New(repository Repository, files FileVault) *Service {
	return &Service{repository: repository, files: files}
}

// ownerID must be taken from a verified identity, never from a query parameter.
func (s *Service) List(ctx context.Context, ownerID string) ([]domain.Config, error) {
	if ownerID == "" {
		return nil, ErrForbidden
	}
	return s.repository.ListByOwner(ctx, ownerID)
}

func (s *Service) Download(ctx context.Context, ownerID, configID string) ([]byte, error) {
	if ownerID == "" || configID == "" {
		return nil, ErrForbidden
	}
	config, err := s.repository.FindByOwner(ctx, ownerID, configID)
	if err != nil {
		return nil, fmt.Errorf("find config: %w", err)
	}
	if config.OwnerID != ownerID {
		return nil, ErrForbidden
	}
	return s.files.Get(ctx, ownerID, config.ID, config.Generation)
}
