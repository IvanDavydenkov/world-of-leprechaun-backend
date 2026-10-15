package application

import (
	"context"
	"errors"
	"leprechaun/vpn-configs/internal/domain"
	"testing"
)

type repositoryStub struct{}

func (repositoryStub) ListByOwner(context.Context, string) ([]domain.Config, error) { return nil, nil }
func (repositoryStub) FindByOwner(context.Context, string, string) (domain.Config, error) {
	return domain.Config{OwnerID: "another-user", RemoteID: "secret"}, nil
}

type hostStub struct{ called bool }

func (h *hostStub) Get(context.Context, string, string, string) ([]byte, error) {
	h.called = true
	return nil, nil
}

func TestDownloadRejectsAnotherOwner(t *testing.T) {
	host := &hostStub{}
	service := New(repositoryStub{}, host)
	_, err := service.Download(context.Background(), "current-user", "config")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}
	if host.called {
		t.Fatal("remote host accessed for another user's config")
	}
}

func (h *hostStub) Put(context.Context, string, string, string, []byte) error { return nil }
