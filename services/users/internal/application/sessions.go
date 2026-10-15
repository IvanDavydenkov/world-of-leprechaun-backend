package application

import (
	"context"
	"errors"
	"time"
)

var ErrUnauthenticated = errors.New("authentication required")

// SessionStore persists only hashes of opaque browser credentials. OAuth access
// tokens are never persisted. Expiry must be checked on reads, not just by TTL cleanup.
type SessionStore interface {
	SaveState(context.Context, string, string, time.Time) error
	ConsumeState(context.Context, string, time.Time) (string, error)
	SaveSession(context.Context, string, string, time.Time) error
	SessionUser(context.Context, string, time.Time) (string, error)
	DeleteSession(context.Context, string) error
}
