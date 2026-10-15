package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"leprechaun/vpn-configs/internal/domain"
)

type fileVaultStub struct {
	files map[string][]byte
	fail  bool
}

type stateReader struct{ store StateStore }

func (r stateReader) ListByOwner(ctx context.Context, owner string) ([]domain.Config, error) {
	state, err := r.store.Load(ctx, owner)
	return state.Active(), err
}
func (r stateReader) FindByOwner(ctx context.Context, owner, id string) (domain.Config, error) {
	configs, err := r.ListByOwner(ctx, owner)
	if err != nil {
		return domain.Config{}, err
	}
	for _, config := range configs {
		if config.ID == id {
			return config, nil
		}
	}
	return domain.Config{}, ErrNotFound
}

func (v *fileVaultStub) Put(_ context.Context, owner, id, generation string, file []byte) error {
	if v.fail {
		return errors.New("storage unavailable")
	}
	v.files[owner+":"+id+":"+generation] = append([]byte(nil), file...)
	return nil
}
func (v *fileVaultStub) Get(_ context.Context, owner, id, generation string) ([]byte, error) {
	file, ok := v.files[owner+":"+id+":"+generation]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), file...), nil
}

func TestSoftDeleteAndReactivationReplaceFileInSameRecord(t *testing.T) {
	m, states, host := setupManager()
	files := &fileVaultStub{files: map[string][]byte{}}
	m.files = files
	ctx := context.Background()
	original, err := m.Submit(ctx, "admin", "user", "create", domain.CreateConfig, "", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.ProcessNext(ctx, "user"); err != nil {
		t.Fatal(err)
	}
	originalFile, _ := files.Get(ctx, "user", original.ConfigID, original.Generation)
	if len(originalFile) == 0 {
		t.Fatal("file not stored")
	}
	reader := New(stateReader{store: states}, files)
	downloaded, err := reader.Download(ctx, "user", original.ConfigID)
	if err != nil || string(downloaded) != string(originalFile) {
		t.Fatal("active download failed", err)
	}
	if _, err = reader.Download(ctx, "another-user", original.ConfigID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign download allowed", err)
	}
	_, err = m.Submit(ctx, "admin", "user", "delete", domain.RevokeConfig, original.ConfigID, "")
	if err != nil {
		t.Fatal(err)
	}
	host.failRevoke = true
	_, _ = m.ProcessNext(ctx, "user")
	state, _ := states.Load(ctx, "user")
	if state.Configs[0].DeletedAt != nil || state.Configs[0].State() != "deleting" {
		t.Fatal("marked deleted before host confirmation")
	}
	if _, err = m.Submit(ctx, "admin", "user", "too-early", domain.ReactivateConfig, original.ConfigID, ""); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	host.failRevoke = false
	if _, err = m.ProcessNext(ctx, "user"); err != nil {
		t.Fatal(err)
	}
	state, _ = states.Load(ctx, "user")
	if len(state.Configs) != 1 || state.Configs[0].DeletedAt == nil || state.Configs[0].State() != "deleted" {
		t.Fatal("soft-deleted record missing")
	}
	if _, err = reader.Download(ctx, "user", original.ConfigID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted download allowed", err)
	}
	history, err := m.History(ctx, "admin", "user")
	if err != nil || len(history) != 1 || history[0].DeletedAt == nil {
		t.Fatal("deleted record absent from admin history", err)
	}
	if _, err = m.History(ctx, "user", "user"); !errors.Is(err, ErrForbidden) {
		t.Fatal("user accessed admin history", err)
	}
	renewed, err := m.Submit(ctx, "admin", "user", "reactivate", domain.ReactivateConfig, original.ConfigID, "")
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ConfigID != original.ConfigID || renewed.Generation == original.Generation {
		t.Fatal("invalid reactivation identity")
	}
	// Reconstruct the manager: durable state and file vault survive application restart.
	m = NewManager(states, accessStub{}, host, files, func() string { return "another" }, time.Now)
	if _, err = m.ProcessNext(ctx, "user"); err != nil {
		t.Fatal(err)
	}
	state, _ = states.Load(ctx, "user")
	config := state.Configs[0]
	if len(state.Configs) != 1 || config.Version != 2 || config.State() != "active" || !host.revoked[original.Generation] {
		t.Fatalf("unexpected state: %+v", state)
	}
	replacementFile, err := files.Get(ctx, "user", config.ID, config.Generation)
	if err != nil || string(replacementFile) == string(originalFile) {
		t.Fatal("download file was not replaced")
	}
	downloaded, err = reader.Download(ctx, "user", original.ConfigID)
	if err != nil || string(downloaded) != string(replacementFile) {
		t.Fatal("new download did not replace old file", err)
	}
	// A stale revocation confirmation cannot delete the new generation.
	if err = m.confirmRevocation(ctx, "user", config.ID, original.Generation); err != nil {
		t.Fatal(err)
	}
	state, _ = states.Load(ctx, "user")
	if state.Configs[0].State() != "active" {
		t.Fatal("old revocation affected new issuance")
	}
}

func TestFilePersistenceFailureDoesNotPublishOrDuplicateRemoteConfig(t *testing.T) {
	m, states, host := setupManager()
	ctx := context.Background()
	files := &fileVaultStub{files: map[string][]byte{}, fail: true}
	m.files = files
	_, err := m.Submit(ctx, "admin", "user", "create", domain.CreateConfig, "", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.ProcessNext(ctx, "user"); err == nil {
		t.Fatal("file persistence failure ignored")
	}
	state, _ := states.Load(ctx, "user")
	if len(state.Active()) != 0 {
		t.Fatal("unpersisted file was published")
	}
	files.fail = false
	if _, err = m.ProcessNext(ctx, "user"); err != nil {
		t.Fatal(err)
	}
	state, _ = states.Load(ctx, "user")
	if len(state.Active()) != 1 || host.creates != 1 {
		t.Fatal("retry duplicated or failed to publish")
	}
}
