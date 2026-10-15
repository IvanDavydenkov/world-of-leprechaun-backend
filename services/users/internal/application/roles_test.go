package application

import (
	"context"
	"errors"
	"leprechaun/users/internal/domain"
	"testing"
)

type directoryStub struct{ users map[string]domain.User }

func (r directoryStub) FindByID(_ context.Context, id string) (domain.User, error) {
	user, ok := r.users[id]
	if !ok {
		return domain.User{}, ErrNotFound
	}
	return user, nil
}
func (r directoryStub) List(context.Context, string, int) ([]domain.User, error) {
	result := make([]domain.User, 0)
	for _, user := range r.users {
		result = append(result, user)
	}
	return result, nil
}

func TestRolePolicy(t *testing.T) {
	for _, tc := range []struct {
		admin, subject string
		role           domain.Role
	}{
		{"", "", domain.RoleUser}, {"", "owner", domain.RoleUser},
		{"owner", "owner", domain.RoleAdmin}, {"owner", "other", domain.RoleUser},
		{"owner", "", domain.RoleUser},
	} {
		if got := NewRolePolicy(tc.admin).RoleFor(tc.subject); got != tc.role {
			t.Fatalf("%+v: got %s", tc, got)
		}
	}
}

func TestDirectoryRevokesStaleAdminAndIgnoresStoredRole(t *testing.T) {
	repository := directoryStub{users: map[string]domain.User{
		"old": {ID: "old", YandexID: "old-subject", Role: domain.RoleAdmin},
		"new": {ID: "new", YandexID: "new-subject", Role: domain.RoleUser},
	}}
	directory := NewDirectory(repository, "new-subject")
	if _, err := directory.List(context.Background(), "old", "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("old admin: %v", err)
	}
	if _, err := directory.List(context.Background(), "", "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("anonymous: %v", err)
	}
	if _, err := directory.List(context.Background(), "new", "", 10); err != nil {
		t.Fatal(err)
	}
	old, err := directory.Resolve(context.Background(), "old")
	if err != nil || old.Role != domain.RoleUser {
		t.Fatalf("%+v %v", old, err)
	}
}
