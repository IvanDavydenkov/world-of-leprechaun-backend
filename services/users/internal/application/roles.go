package application

import (
	"context"
	"errors"
	"leprechaun/users/internal/domain"
)

var ErrForbidden = errors.New("administrative access required")

// RolePolicy is the source of privileges. Persisted roles are never trusted.
// Reload configuration by restarting users; sessions must resolve privileges on each request.
type RolePolicy struct{ adminYandexID string }

func NewRolePolicy(adminYandexID string) RolePolicy { return RolePolicy{adminYandexID: adminYandexID} }

func (p RolePolicy) RoleFor(yandexID string) domain.Role {
	if p.adminYandexID != "" && yandexID == p.adminYandexID {
		return domain.RoleAdmin
	}
	return domain.RoleUser
}

type DirectoryRepository interface {
	FindByID(context.Context, string) (domain.User, error)
	List(context.Context, string, int) ([]domain.User, error)
}

type Directory struct {
	repository DirectoryRepository
	roles      RolePolicy
}

func NewDirectory(repository DirectoryRepository, adminYandexID string) *Directory {
	return &Directory{repository: repository, roles: NewRolePolicy(adminYandexID)}
}

// actorID must be resolved from a verified session, not supplied by a browser.
func (d *Directory) Resolve(ctx context.Context, actorID string) (domain.User, error) {
	if actorID == "" {
		return domain.User{}, ErrForbidden
	}
	user, err := d.repository.FindByID(ctx, actorID)
	if err != nil {
		return domain.User{}, err
	}
	user.Role = d.roles.RoleFor(user.YandexID)
	return user, nil
}

func (d *Directory) List(ctx context.Context, actorID, after string, limit int) ([]domain.User, error) {
	actor, err := d.Resolve(ctx, actorID)
	if err != nil {
		return nil, err
	}
	if actor.Role != domain.RoleAdmin {
		return nil, ErrForbidden
	}
	if limit < 1 || limit > 100 {
		return nil, errors.New("limit must be between 1 and 100")
	}
	users, err := d.repository.List(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	for i := range users {
		users[i].Role = d.roles.RoleFor(users[i].YandexID)
	}
	return users, nil
}
