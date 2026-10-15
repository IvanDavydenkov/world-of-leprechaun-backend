package domain

import "time"

// Batch and its child operations are persisted atomically in the owner aggregate.
type Batch struct {
	ID           string
	ActorID      string
	Key          string
	Scope        string
	Fingerprint  string
	Kind         OperationKind
	OperationIDs []string
	CreatedAt    time.Time
}
