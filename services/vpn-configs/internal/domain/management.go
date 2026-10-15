package domain

import "time"

type OperationKind string

const (
	CreateConfig     OperationKind = "create"
	ReactivateConfig OperationKind = "reactivate"
	RevokeConfig     OperationKind = "revoke"
	RevokeAllConfigs OperationKind = "revoke_all"
)

type ManagedConfig struct {
	ID         string
	Name       string
	RemoteID   string
	CreatedAt  time.Time
	Generation string
	Version    int
	DeletedAt  *time.Time
	// Desired is cleared before remote revocation, preventing further downloads.
	Desired     bool
	Provisioned bool
}

// State separates a pending deletion from a confirmed soft deletion.
func (c ManagedConfig) State() string {
	if c.DeletedAt != nil {
		return "deleted"
	}
	if !c.Desired {
		return "deleting"
	}
	if !c.Provisioned && c.Version > 1 {
		return "reactivating"
	}
	if !c.Provisioned {
		return "creating"
	}
	return "active"
}

type Operation struct {
	AttemptID       string
	ProcessingUntil *time.Time
	RetryAfter      *time.Time
	ID              string
	ActorID         string
	OwnerID         string
	Kind            OperationKind
	ConfigID        string
	Generation      string
	Name            string
	Targets         []string
	CreatedAt       time.Time
	CompletedAt     *time.Time
	Attempts        int
	// Public error codes only; never store raw host errors or configuration contents.
	ErrorCode string
}

// Account is a single-document aggregate: queueing revoke-all and preventing new
// creation is atomic without a MongoDB replica set or distributed transaction.
type Account struct {
	Batches    []Batch
	OwnerID    string
	Revision   int64
	Configs    []ManagedConfig
	Operations []Operation
}

func (a Account) Active() []Config {
	result := make([]Config, 0)
	for _, config := range a.Configs {
		if config.Desired && config.Provisioned {
			result = append(result, Config{ID: config.ID, OwnerID: a.OwnerID, RemoteID: config.RemoteID, Name: config.Name, CreatedAt: config.CreatedAt, Generation: config.Generation})
		}
	}
	return result
}

func (a Account) Draining() bool {
	for _, batch := range a.Batches {
		if batch.Scope != "all" {
			continue
		}
		for _, id := range batch.OperationIDs {
			for _, operation := range a.Operations {
				if operation.ID == id && operation.CompletedAt == nil {
					return true
				}
			}
		}
	}
	for _, operation := range a.Operations {
		if operation.Kind == RevokeAllConfigs && operation.CompletedAt == nil {
			return true
		}
	}
	return false
}
