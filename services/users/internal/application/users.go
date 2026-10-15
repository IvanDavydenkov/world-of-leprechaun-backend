package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	"leprechaun/users/internal/domain"
)

var ErrNotFound = errors.New("user not found")

// Identity must come from the trusted Yandex OAuth adapter, never from request JSON.
type Identity struct{ Subject, DisplayName string }

// Repository must enforce unique YandexID and atomically return an existing user.
type Repository interface {
	FindOrCreate(context.Context, domain.User) (domain.User, error)
}

type IdentityProvider interface {
	ExchangeCode(context.Context, string, string) (Identity, error)
}

type Service struct {
	repository Repository
	provider   IdentityProvider
	newID      func() string
	now        func() time.Time
	roles      RolePolicy
}

func New(repository Repository, provider IdentityProvider, newID func() string, now func() time.Time, adminYandexID string) *Service {
	return &Service{repository: repository, provider: provider, newID: newID, now: now, roles: NewRolePolicy(adminYandexID)}
}

func (s *Service) SignIn(ctx context.Context, code, verifier string) (domain.User, error) {
	if code == "" {
		return domain.User{}, errors.New("authorization code is required")
	}
	identity, err := s.provider.ExchangeCode(ctx, code, verifier)
	if err != nil {
		return domain.User{}, fmt.Errorf("verify yandex identity: %w", err)
	}
	if identity.Subject == "" {
		return domain.User{}, errors.New("empty yandex subject")
	}
	user, err := s.repository.FindOrCreate(ctx, domain.User{
		ID: s.newID(), YandexID: identity.Subject, DisplayName: identity.DisplayName,
		Role: domain.RoleUser, CreatedAt: s.now().UTC(),
	})
	if err != nil {
		return domain.User{}, fmt.Errorf("find or create user: %w", err)
	}
	user.Role = s.roles.RoleFor(user.YandexID)
	return user, nil
}
