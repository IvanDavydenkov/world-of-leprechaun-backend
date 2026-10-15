package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"leprechaun/vpn-configs/internal/domain"
)

var (
	ErrConflict = errors.New("operation conflict")
	ErrInvalid  = errors.New("invalid operation")
)

// Access resolves the actor's CURRENT privileges in users, using a verified session.
// It must fail closed on communication errors; client role fields are never trusted.
type Access interface {
	RequireAdmin(context.Context, string) error
	RequireUser(context.Context, string) error
}

// StateStore uses compare-and-swap on Revision. A false result means retry on fresh state.
type StateStore interface {
	Load(context.Context, string) (domain.Account, error)
	Save(context.Context, domain.Account, int64) (bool, error)
}

// Provisioner must durably deduplicate creation by generationID, including after
// revocation. A repeated Create may NEVER recreate a revoked peer. Unknown
// outcomes must be reconciled with the host before retrying. Revoke is idempotent.
// The concrete Amnezia adapter must demonstrate these guarantees before wiring.
type Provisioner interface {
	Create(context.Context, string, string, string) (Provisioned, error)
	Revoke(context.Context, string, string) error
}

// Generation identifies one issuance, not the permanent profile record.
// The remote adapter must return the same file for retries of that generation.
type Provisioned struct {
	RemoteID string
	File     []byte
}

// FileVault encrypts data before persistence and binds it to owner/config/generation.
type FileVault interface {
	Put(context.Context, string, string, string, []byte) error
	Get(context.Context, string, string, string) ([]byte, error)
}

type Manager struct {
	store  StateStore
	access Access
	host   Provisioner
	newID  func() string
	now    func() time.Time
	files  FileVault
}

func NewManager(store StateStore, access Access, host Provisioner, files FileVault, newID func() string, now func() time.Time) *Manager {
	return &Manager{store: store, access: access, host: host, files: files, newID: newID, now: now}
}

// Submit records durable intent before any host calls. requestID is an
// administrator-scoped idempotency key; retries must repeat identical parameters.
func (m *Manager) Submit(ctx context.Context, actorID, ownerID, requestID string, kind domain.OperationKind, configID, name string) (domain.Operation, error) {
	if err := m.access.RequireAdmin(ctx, actorID); err != nil {
		return domain.Operation{}, err
	}
	if ownerID == "" || requestID == "" || len(requestID) > 128 {
		return domain.Operation{}, ErrInvalid
	}
	if err := m.access.RequireUser(ctx, ownerID); err != nil {
		return domain.Operation{}, err
	}
	if kind != domain.CreateConfig && kind != domain.ReactivateConfig && kind != domain.RevokeConfig && kind != domain.RevokeAllConfigs {
		return domain.Operation{}, ErrInvalid
	}
	name = strings.TrimSpace(name)
	if kind == domain.CreateConfig && (name == "" || len(name) > 128 || configID != "") {
		return domain.Operation{}, ErrInvalid
	}
	if kind == domain.RevokeConfig && (configID == "" || name != "") {
		return domain.Operation{}, ErrInvalid
	}
	if kind == domain.ReactivateConfig && (configID == "" || name != "") {
		return domain.Operation{}, ErrInvalid
	}
	if kind == domain.RevokeAllConfigs && (configID != "" || name != "") {
		return domain.Operation{}, ErrInvalid
	}
	operation := domain.Operation{ID: requestID, ActorID: actorID, OwnerID: ownerID, Kind: kind, ConfigID: configID, Name: name, CreatedAt: m.now().UTC()}
	newConfigID := ""
	if kind == domain.CreateConfig {
		newConfigID = m.newID()
	}
	if kind == domain.CreateConfig || kind == domain.ReactivateConfig {
		operation.Generation = m.newID()
	}
	for retries := 0; retries < 32; retries++ {
		account, err := m.store.Load(ctx, ownerID)
		if err != nil {
			return domain.Operation{}, err
		}
		for _, previous := range account.Operations {
			if previous.ID == requestID && previous.ActorID == actorID {
				// For create the server generates ConfigID; it is not part of request parameters.
				if previous.Kind != kind || previous.Name != name || (kind != domain.CreateConfig && previous.ConfigID != configID) {
					return domain.Operation{}, ErrConflict
				}
				return previous, nil
			}
		}
		revision := account.Revision
		switch kind {
		case domain.CreateConfig:
			if account.Draining() {
				return domain.Operation{}, ErrConflict
			}
			operation.ConfigID = newConfigID
			account.Configs = append(account.Configs, domain.ManagedConfig{ID: newConfigID, Name: name, CreatedAt: operation.CreatedAt, Desired: true, Generation: operation.Generation, Version: 1})
		case domain.ReactivateConfig:
			if account.Draining() {
				return domain.Operation{}, ErrConflict
			}
			for _, pending := range account.Operations {
				if pending.CompletedAt != nil {
					continue
				}
				if pending.ConfigID == configID {
					return domain.Operation{}, ErrConflict
				}
				for _, target := range pending.Targets {
					if target == configID {
						return domain.Operation{}, ErrConflict
					}
				}
			}
			found := false
			for i := range account.Configs {
				config := &account.Configs[i]
				if config.ID != configID {
					continue
				}
				found = true
				if config.DeletedAt == nil {
					return domain.Operation{}, ErrConflict
				}
				config.Desired, config.Provisioned = true, false
				config.DeletedAt, config.RemoteID = nil, ""
				config.Generation = operation.Generation
				config.Version++
			}
			if !found {
				return domain.Operation{}, ErrNotFound
			}
		case domain.RevokeConfig:
			found := false
			for i := range account.Configs {
				if account.Configs[i].ID == configID {
					found = true
					if account.Configs[i].DeletedAt != nil || !account.Configs[i].Desired {
						return domain.Operation{}, ErrConflict
					}
					account.Configs[i].Desired = false
				}
			}
			if !found {
				return domain.Operation{}, ErrNotFound
			}
			operation.Targets = []string{configID}
		case domain.RevokeAllConfigs:
			if account.Draining() {
				return domain.Operation{}, ErrConflict
			}
			operation.Targets = make([]string, 0)
			for i := range account.Configs {
				if account.Configs[i].Desired || account.Configs[i].Provisioned {
					operation.Targets = append(operation.Targets, account.Configs[i].ID)
				}
				account.Configs[i].Desired = false
			}
		}
		account.Operations = append(account.Operations, operation)
		saved, err := m.store.Save(ctx, account, revision)
		if err != nil {
			return domain.Operation{}, err
		}
		if saved {
			return operation, nil
		}
	}
	return domain.Operation{}, ErrConflict
}

func (m *Manager) Status(ctx context.Context, actorID, ownerID, requestID string) (domain.Operation, error) {
	if err := m.access.RequireAdmin(ctx, actorID); err != nil {
		return domain.Operation{}, err
	}
	account, err := m.store.Load(ctx, ownerID)
	if err != nil {
		return domain.Operation{}, err
	}
	for _, op := range account.Operations {
		if op.ID == requestID && op.ActorID == actorID {
			return op, nil
		}
	}
	return domain.Operation{}, ErrNotFound
}

// History includes soft-deleted records for the administrator. It contains no
// decrypted file contents; normal users must use Service.List instead.
func (m *Manager) History(ctx context.Context, actorID, ownerID string) ([]domain.ManagedConfig, error) {
	if err := m.access.RequireAdmin(ctx, actorID); err != nil {
		return nil, err
	}
	if err := m.access.RequireUser(ctx, ownerID); err != nil {
		return nil, err
	}
	state, err := m.store.Load(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	result := make([]domain.ManagedConfig, len(state.Configs))
	copy(result, state.Configs)
	return result, nil
}

// ProcessNext is an internal worker entry point, never a public unauthenticated
// endpoint. Queued creations precede revocations, so draining catches late creates.
// Concurrent retries rely on the durable idempotency guarantee of Provisioner.
func (m *Manager) ProcessNext(ctx context.Context, ownerID string) (bool, error) {
	if m.host == nil || m.files == nil {
		return false, errors.New("VPN provisioner or file vault is not configured")
	}
	account, err := m.store.Load(ctx, ownerID)
	if err != nil {
		return false, err
	}
	var operation domain.Operation
	found := false
	for _, op := range account.Operations {
		if op.CompletedAt == nil {
			operation = op
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}
	remoteID := ""
	var hostErr error
	if operation.Kind == domain.CreateConfig || operation.Kind == domain.ReactivateConfig {
		name := operation.Name
		for _, config := range account.Configs {
			if config.ID == operation.ConfigID {
				name = config.Name
				break
			}
		}
		var result Provisioned
		result, hostErr = m.host.Create(ctx, operation.Generation, ownerID, name)
		remoteID = result.RemoteID
		if hostErr == nil && (remoteID == "" || len(result.File) == 0 || len(result.File) > 1024*1024) {
			hostErr = errors.New("invalid remote config result")
		}
		if hostErr == nil {
			hostErr = m.files.Put(ctx, ownerID, operation.ConfigID, operation.Generation, result.File)
		}
	} else {
		// Keep the operation pending on partial failure. Already successful revokes
		// are idempotent and safe to repeat after restart.
		for _, target := range operation.Targets {
			remote := ""
			for _, config := range account.Configs {
				if config.ID == target {
					remote = config.RemoteID
					break
				}
			}
			if remote == "" {
				hostErr = errors.New("unresolved remote config")
				break
			}
			generation := ""
			for _, config := range account.Configs {
				if config.ID == target {
					generation = config.Generation
					break
				}
			}
			if err := m.host.Revoke(ctx, generation, remote); err != nil {
				hostErr = err
				break
			}
			if err := m.confirmRevocation(ctx, ownerID, target, generation); err != nil {
				return true, err
			}
		}
	}
	for retries := 0; retries < 32; retries++ {
		current, err := m.store.Load(ctx, ownerID)
		if err != nil {
			return true, err
		}
		index := -1
		for i := range current.Operations {
			op := current.Operations[i]
			if op.ID == operation.ID && op.ActorID == operation.ActorID {
				index = i
				break
			}
		}
		if index < 0 {
			return true, ErrNotFound
		}
		if current.Operations[index].CompletedAt != nil {
			return true, nil
		}
		revision := current.Revision
		current.Operations[index].Attempts++
		if hostErr != nil {
			current.Operations[index].ErrorCode = "host_operation_unconfirmed"
		} else {
			completed := m.now().UTC()
			current.Operations[index].CompletedAt = &completed
			current.Operations[index].ErrorCode = ""
			for i := range current.Configs {
				config := &current.Configs[i]
				if (operation.Kind == domain.CreateConfig || operation.Kind == domain.ReactivateConfig) && config.ID == operation.ConfigID && config.Generation == operation.Generation {
					config.RemoteID, config.Provisioned = remoteID, true
					// Never set Desired=true here: a concurrent revoke may already have cleared it.
				}
			}
		}
		saved, err := m.store.Save(ctx, current, revision)
		if err != nil {
			return true, err
		}
		if saved {
			if hostErr != nil {
				return true, fmt.Errorf("host operation unconfirmed")
			}
			return true, nil
		}
	}
	return true, ErrConflict
}

func (m *Manager) confirmRevocation(ctx context.Context, ownerID, configID, generation string) error {
	for retry := 0; retry < 32; retry++ {
		state, err := m.store.Load(ctx, ownerID)
		if err != nil {
			return err
		}
		revision := state.Revision
		for i := range state.Configs {
			config := &state.Configs[i]
			if config.ID != configID {
				continue
			}
			// An old worker retry must never mark a newer issuance deleted.
			if config.Generation != generation || config.DeletedAt != nil {
				return nil
			}
			now := m.now().UTC()
			config.Provisioned = false
			config.DeletedAt = &now
		}
		saved, err := m.store.Save(ctx, state, revision)
		if err != nil {
			return err
		}
		if saved {
			return nil
		}
	}
	return ErrConflict
}
