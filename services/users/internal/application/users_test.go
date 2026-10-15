package application

import (
	"context"
	"leprechaun/users/internal/domain"
	"testing"
	"time"
)

type providerStub struct{}

func (providerStub) ExchangeCode(context.Context, string, string) (Identity, error) {
	return Identity{Subject: "yandex-id", DisplayName: "Name"}, nil
}

type repositoryStub struct{ user domain.User }

func (r *repositoryStub) FindOrCreate(_ context.Context, user domain.User) (domain.User, error) {
	if r.user.ID == "" {
		r.user = user
	}
	return r.user, nil
}
func TestSignInIgnoresStoredAdministratorRole(t *testing.T) {
	repository := &repositoryStub{}
	service := New(repository, providerStub{}, func() string { return "id" }, time.Now, "")
	user, err := service.SignIn(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != domain.RoleUser || user.YandexID != "yandex-id" {
		t.Fatalf("unexpected user: %+v", user)
	}
	repository.user.Role = domain.RoleAdmin
	user, err = service.SignIn(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != domain.RoleUser {
		t.Fatal("stale stored role granted administrative access")
	}
}
