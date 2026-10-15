package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"leprechaun/vpn-configs/internal/domain"
)

type BatchRequest struct {
	Scope     string
	Count     int
	ConfigIDs []string
}
type BatchItem struct {
	ConfigID  string  `json:"config_id"`
	Status    string  `json:"status"`
	ErrorCode *string `json:"error_code"`
}
type BatchResult struct {
	ID        string               `json:"operation_id"`
	Kind      domain.OperationKind `json:"kind"`
	Status    string               `json:"status"`
	Requested int                  `json:"requested_count"`
	Succeeded int                  `json:"succeeded_count"`
	Pending   int                  `json:"pending_count"`
	Failed    int                  `json:"failed_count"`
	Items     []BatchItem          `json:"items"`
}

func ValidID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func ValidKey(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func (m *Manager) SubmitBatch(ctx context.Context, actor, owner, key string, request BatchRequest) (BatchResult, error) {
	if err := m.access.RequireAdmin(ctx, actor); err != nil {
		return BatchResult{}, err
	}
	if !ValidID(owner) || !ValidKey(key) {
		return BatchResult{}, ErrInvalid
	}
	if err := m.access.RequireUser(ctx, owner); err != nil {
		return BatchResult{}, err
	}
	ids := append([]string(nil), request.ConfigIDs...)
	sort.Strings(ids)
	switch request.Scope {
	case "create":
		if request.Count < 1 || request.Count > 20 || len(ids) > 0 {
			return BatchResult{}, ErrInvalid
		}
	case "single", "selected":
		if request.Count != 0 || len(ids) < 1 || len(ids) > 100 || request.Scope == "single" && len(ids) != 1 {
			return BatchResult{}, ErrInvalid
		}
		for i, id := range ids {
			if !ValidID(id) || i > 0 && id == ids[i-1] {
				return BatchResult{}, ErrInvalid
			}
		}
	case "all":
		if request.Count != 0 || len(ids) > 0 {
			return BatchResult{}, ErrInvalid
		}
	default:
		return BatchResult{}, ErrInvalid
	}
	canonical, _ := json.Marshal(BatchRequest{Scope: request.Scope, Count: request.Count, ConfigIDs: ids})
	digest := sha256.Sum256(canonical)
	fingerprint := hex.EncodeToString(digest[:])
	batch := domain.Batch{ID: m.newID(), ActorID: actor, Key: key, Scope: request.Scope, Fingerprint: fingerprint, CreatedAt: m.now().UTC(), Kind: domain.RevokeConfig}
	if request.Scope == "create" {
		batch.Kind = domain.CreateConfig
	}
	if request.Scope == "all" {
		batch.Kind = domain.RevokeAllConfigs
	}
	// Generate child identities once, before retrying a CAS conflict.
	creations := make([]domain.ManagedConfig, request.Count)
	for i := range creations {
		id := m.newID()
		creations[i] = domain.ManagedConfig{ID: id, Generation: m.newID(), Name: "Конфиг " + id, Version: 1, Desired: true, CreatedAt: batch.CreatedAt}
	}
	for retry := 0; retry < 32; retry++ {
		account, err := m.store.Load(ctx, owner)
		if err != nil {
			return BatchResult{}, err
		}
		revision := account.Revision
		for _, previous := range account.Batches {
			if previous.Key != key || previous.ActorID != actor || previous.Scope != request.Scope {
				continue
			}
			if previous.Fingerprint != fingerprint {
				return BatchResult{}, ErrConflict
			}
			// An explicit retry resumes only failed children; completed ones are immutable.
			changed := false
			for i := range account.Operations {
				op := &account.Operations[i]
				for _, id := range previous.OperationIDs {
					if op.ID == id && op.CompletedAt == nil && op.ErrorCode != "" {
						op.ErrorCode = ""
						op.RetryAfter = nil
						changed = true
					}
				}
			}
			if !changed {
				return summarize(account, previous, m.now()), nil
			}
			saved, err := m.store.Save(ctx, account, revision)
			if err != nil {
				return BatchResult{}, err
			}
			if saved {
				return summarize(account, previous, m.now()), nil
			}
			break
		}
		// A conflicting retry above must reload rather than append a second batch.
		exists := false
		for _, previous := range account.Batches {
			if previous.Key == key && previous.ActorID == actor && previous.Scope == request.Scope {
				exists = true
			}
		}
		if exists {
			continue
		}
		if m.host == nil || m.files == nil {
			return BatchResult{}, ErrUnavailable
		}
		if account.Draining() {
			return BatchResult{}, ErrConflict
		}
		targets := append([]string(nil), ids...)
		if request.Scope == "all" {
			targets = nil
			for _, config := range account.Configs {
				if config.DeletedAt == nil {
					targets = append(targets, config.ID)
				}
			}
		}
		if request.Scope == "single" || request.Scope == "selected" {
			for _, id := range targets {
				found := false
				for _, config := range account.Configs {
					if config.ID == id {
						found = true
						break
					}
				}
				if !found {
					return BatchResult{}, ErrNotFound
				}
			}
		}
		batch.OperationIDs = nil
		if request.Scope == "create" {
			for _, config := range creations {
				opID := batch.ID + "_" + config.ID
				account.Configs = append(account.Configs, config)
				account.Operations = append(account.Operations, domain.Operation{ID: opID, ActorID: actor, OwnerID: owner, Kind: domain.CreateConfig, ConfigID: config.ID, Generation: config.Generation, Name: config.Name, CreatedAt: batch.CreatedAt})
				batch.OperationIDs = append(batch.OperationIDs, opID)
			}
		} else {
			for _, id := range targets {
				op := domain.Operation{ID: batch.ID + "_" + id, ActorID: actor, OwnerID: owner, Kind: domain.RevokeConfig, ConfigID: id, Targets: []string{id}, CreatedAt: batch.CreatedAt}
				for i := range account.Configs {
					config := &account.Configs[i]
					if config.ID != id {
						continue
					}
					if config.DeletedAt != nil {
						done := m.now().UTC()
						op.CompletedAt = &done
					} else {
						config.Desired = false
					}
				}
				account.Operations = append(account.Operations, op)
				batch.OperationIDs = append(batch.OperationIDs, op.ID)
			}
		}
		account.Batches = append(account.Batches, batch)
		saved, err := m.store.Save(ctx, account, revision)
		if err != nil {
			return BatchResult{}, err
		}
		if saved {
			return summarize(account, batch, m.now()), nil
		}
	}
	return BatchResult{}, ErrConflict
}

func (m *Manager) BatchStatus(ctx context.Context, actor, owner, id string) (BatchResult, error) {
	if err := m.access.RequireAdmin(ctx, actor); err != nil {
		return BatchResult{}, err
	}
	if !ValidID(owner) || !ValidID(id) {
		return BatchResult{}, ErrInvalid
	}
	if err := m.access.RequireUser(ctx, owner); err != nil {
		return BatchResult{}, err
	}
	account, err := m.store.Load(ctx, owner)
	if err != nil {
		return BatchResult{}, err
	}
	for _, batch := range account.Batches {
		if batch.ID == id {
			return summarize(account, batch, m.now()), nil
		}
	}
	return BatchResult{}, ErrNotFound
}

func summarize(account domain.Account, batch domain.Batch, now time.Time) BatchResult {
	result := BatchResult{ID: batch.ID, Kind: batch.Kind, Status: "pending", Requested: len(batch.OperationIDs), Items: make([]BatchItem, 0, len(batch.OperationIDs))}
	running := false
	for _, id := range batch.OperationIDs {
		for _, op := range account.Operations {
			if op.ID != id {
				continue
			}
			item := BatchItem{ConfigID: op.ConfigID, Status: "pending"}
			switch {
			case op.CompletedAt != nil:
				item.Status = "succeeded"
				result.Succeeded++
			case op.ProcessingUntil != nil && op.ProcessingUntil.After(now):
				item.Status = "running"
				result.Pending++
				running = true
			case op.ErrorCode != "":
				item.Status = "failed"
				code := op.ErrorCode
				item.ErrorCode = &code
				result.Failed++
			default:
				result.Pending++
			}
			result.Items = append(result.Items, item)
			break
		}
	}
	switch {
	case result.Succeeded == result.Requested:
		result.Status = "succeeded"
	case result.Failed > 0 && result.Succeeded > 0:
		result.Status = "partial"
	case result.Failed == result.Requested:
		result.Status = "failed"
	case running:
		result.Status = "running"
	}
	return result
}
