package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"leprechaun/vpn-configs/internal/domain"
	"sort"
	"time"
)

type Fleet struct {
	Store    FleetStore
	Accounts AccountCatalog
	Servers  ServerRepository
	Access   Access
	Host     FleetHost
	Files    FileVault
	Guard    Coordinator
	NewID    func() string
	Now      func() time.Time
}

func (f *Fleet) save(ctx context.Context, s *domain.FleetControl) error {
	ok, err := f.Store.SaveFleet(ctx, *s, s.Revision)
	if err != nil {
		return err
	}
	if !ok {
		return ErrConflict
	}
	s.Revision++
	return nil
}
func (f *Fleet) eachAccount(ctx context.Context, fn func(domain.Account) error) error {
	after := ""
	for {
		owners, err := f.Accounts.OwnersAfter(ctx, after, 100)
		if err != nil {
			return err
		}
		for _, id := range owners {
			s, err := f.Accounts.Load(ctx, id)
			if err != nil {
				return err
			}
			if err = fn(s); err != nil {
				return err
			}
		}
		if len(owners) < 100 {
			return nil
		}
		after = owners[len(owners)-1]
	}
}
func (f *Fleet) Initialize(ctx context.Context) error {
	return f.Guard.With(ctx, func(ctx context.Context) error {
		s, err := f.Store.LoadFleet(ctx)
		if err != nil || s.SchemaReady {
			return err
		}
		legacy := false
		if err = f.eachAccount(ctx, func(a domain.Account) error {
			if len(a.Configs) > 0 || len(a.Operations) > 0 {
				legacy = true
			}
			return nil
		}); err != nil {
			return err
		}
		if !legacy {
			s.SchemaReady = true
			return f.save(ctx, &s)
		}
		return nil
	})
}
func (f *Fleet) ConfigMutation(ctx context.Context, fn func(context.Context) error) error {
	return f.Guard.With(ctx, func(ctx context.Context) error {
		s, err := f.Store.LoadFleet(ctx)
		if err != nil {
			return err
		}
		if !s.SchemaReady {
			return Fault("schema_migration_required", ErrUnavailable)
		}
		return fn(ctx)
	})
}
func (f *Fleet) DefaultServer(ctx context.Context) (string, error) {
	s, err := f.Store.LoadFleet(ctx)
	if err != nil {
		return "", err
	}
	if !s.SchemaReady {
		return "", Fault("schema_migration_required", ErrUnavailable)
	}
	server, err := f.Servers.Get(ctx, s.Routing.DefaultServerID)
	if err != nil || !ready(server) {
		return "", Fault("server_not_ready", ErrConflict)
	}
	return server.ID, nil
}
func ready(s domain.VPNServer) bool {
	return s.PreparationStatus == "ready" && s.PreparedRevision != nil && *s.PreparedRevision == s.Revision
}
func (f *Fleet) Provider(ctx context.Context, id string) (Provisioner, error) {
	s, err := f.Servers.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return f.Host.ForServer(ctx, s)
}
func (f *Fleet) Routing(ctx context.Context, actor string) (any, error) {
	if err := f.Access.RequireAdmin(ctx, actor); err != nil {
		return nil, err
	}
	s, err := f.Store.LoadFleet(ctx)
	if err != nil {
		return nil, err
	}
	return struct {
		domain.Routing
		Features map[string]bool `json:"features"`
	}{s.Routing, map[string]bool{"prepare": true, "switch": s.SchemaReady, "revoke": s.SchemaReady}}, nil
}
func digest(v any) string {
	data, _ := json.Marshal(v)
	d := sha256.Sum256(data)
	return hex.EncodeToString(d[:])
}
func ptr(s string) *string { return &s }
func (f *Fleet) operation(kind, actor, key string, payload any) domain.FleetOperation {
	return domain.FleetOperation{ID: f.NewID(), Kind: kind, Actor: actor, Key: key, Fingerprint: digest(payload), Status: "queued", Phase: "planning", Steps: []domain.FleetStep{}, Items: []domain.FleetItem{}, CreatedAt: f.Now().UTC(), UpdatedAt: f.Now().UTC()}
}
func prior(s domain.FleetControl, kind, actor, key, fp string, resource ...string) (domain.FleetOperation, bool, error) {
	if !ValidKey(key) {
		return domain.FleetOperation{}, false, Fault("invalid_idempotency_key", ErrInvalid)
	}
	for _, o := range s.Operations {
		if kind == "prepare" && len(resource) > 0 && (o.Server == nil || *o.Server != resource[0]) {
			continue
		}
		if o.Kind == kind && o.Actor == actor && o.Key == key {
			if o.Fingerprint != fp {
				return o, true, Fault("idempotency_conflict", ErrConflict)
			}
			return o, true, nil
		}
	}
	return domain.FleetOperation{}, false, nil
}
func (f *Fleet) busy(s domain.FleetControl, server string) bool {
	for _, o := range s.Operations {
		if o.Status != "queued" && o.Status != "running" && o.Status != "needs_input" {
			continue
		}
		if o.Kind == "switch" || o.Server != nil && *o.Server == server || o.Target != nil && *o.Target == server {
			return true
		}
	}
	return false
}
func (f *Fleet) SubmitPrepare(ctx context.Context, actor, id, key string, revision int64) (domain.FleetOperation, error) {
	var result domain.FleetOperation
	err := f.Access.RequireAdmin(ctx, actor)
	if err != nil {
		return result, err
	}
	err = f.Guard.With(ctx, func(ctx context.Context) error {
		s, err := f.Store.LoadFleet(ctx)
		if err != nil {
			return err
		}
		o := f.operation("prepare", actor, key, struct {
			ID       string
			Revision int64
		}{id, revision})
		if old, ok, e := prior(s, o.Kind, actor, key, o.Fingerprint, id); ok || e != nil {
			result = old
			return e
		}
		server, err := f.Servers.Get(ctx, id)
		if err != nil {
			return err
		}
		if server.Revision != revision {
			return ErrConflict
		}
		if f.busy(s, id) {
			return Fault("server_busy", ErrConflict)
		}
		o.Server = ptr(id)
		o.ExpectedRevision = revision
		for _, name := range []string{"verify_host_key", "authenticate", "inspect_ubuntu", "inspect_docker", "discover_awg", "install_helper", "verify_helper"} {
			o.Steps = append(o.Steps, domain.FleetStep{Name: name, Status: "pending"})
		}
		s.Operations = append(s.Operations, o)
		if err = f.save(ctx, &s); err != nil {
			return err
		}
		server.PreparationStatus = "preparing"
		server.LastOperation = ptr(o.ID)
		server.LastError = nil
		if ok, e := f.Servers.Update(ctx, server, server.Revision); e != nil {
			return e
		} else if !ok {
			return ErrConflict
		}
		result = o
		return nil
	})
	return result, err
}
func (f *Fleet) SubmitSwitch(ctx context.Context, actor, key, target string, revision int64) (domain.FleetOperation, error) {
	var result domain.FleetOperation
	if err := f.Access.RequireAdmin(ctx, actor); err != nil {
		return result, err
	}
	err := f.Guard.With(ctx, func(ctx context.Context) error {
		s, err := f.Store.LoadFleet(ctx)
		if err != nil {
			return err
		}
		o := f.operation("switch", actor, key, struct {
			Target   string
			Revision int64
		}{target, revision})
		if old, ok, e := prior(s, o.Kind, actor, key, o.Fingerprint); ok || e != nil {
			result = old
			return e
		}
		if !s.SchemaReady {
			return Fault("schema_migration_required", ErrUnavailable)
		}
		if s.Routing.Revision != revision {
			return ErrConflict
		}
		if f.busy(s, target) {
			return Fault("switch_in_progress", ErrConflict)
		}
		server, err := f.Servers.Get(ctx, target)
		if err != nil {
			return err
		}
		if !ready(server) {
			return Fault("server_not_ready", ErrConflict)
		}
		err = f.eachAccount(ctx, func(a domain.Account) error {
			for _, op := range a.Operations {
				if op.CompletedAt == nil {
					return Fault("pending_config_operations", ErrConflict)
				}
			}
			for _, c := range a.Configs {
				if c.State() == "active" {
					o.Items = append(o.Items, domain.FleetItem{ID: f.NewID(), ConfigID: c.ID, OwnerID: a.OwnerID, Source: nullable(c.ServerID), Target: ptr(target), Status: "pending"})
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		sort.Slice(o.Items, func(i, j int) bool { return o.Items[i].ID < o.Items[j].ID })
		s.Routing.DefaultServerID = target
		s.Routing.Revision++
		s.Routing.ActiveSwitchID = ptr(o.ID)
		o.Target = ptr(target)
		r := s.Routing.Revision
		o.RoutingRevision = &r
		o.Counts = &domain.FleetCounts{Requested: len(o.Items), Pending: len(o.Items)}
		o.Phase = "processing"
		s.Operations = append(s.Operations, o)
		if err = f.save(ctx, &s); err != nil {
			return err
		}
		result = o
		return nil
	})
	return result, err
}
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return ptr(s)
}

type RevokeRequest struct {
	Scope     string   `json:"scope"`
	ServerID  string   `json:"server_id,omitempty"`
	All       bool     `json:"all_configs,omitempty"`
	ConfigIDs []string `json:"config_ids,omitempty"`
}

func (f *Fleet) SubmitRevoke(ctx context.Context, actor, key string, in RevokeRequest) (domain.FleetOperation, error) {
	var result domain.FleetOperation
	if err := f.Access.RequireAdmin(ctx, actor); err != nil {
		return result, err
	}
	if in.Scope != "server" && in.Scope != "all_servers" || in.Scope == "server" && !ValidID(in.ServerID) || in.Scope == "all_servers" && in.ServerID != "" || in.All == (len(in.ConfigIDs) > 0) || len(in.ConfigIDs) > 100 {
		return result, ErrInvalid
	}
	ids := append([]string(nil), in.ConfigIDs...)
	sort.Strings(ids)
	for i, id := range ids {
		if !ValidID(id) || i > 0 && id == ids[i-1] {
			return result, ErrInvalid
		}
	}
	in.ConfigIDs = ids
	err := f.Guard.With(ctx, func(ctx context.Context) error {
		s, err := f.Store.LoadFleet(ctx)
		if err != nil {
			return err
		}
		o := f.operation("revoke", actor, key, in)
		if old, ok, e := prior(s, o.Kind, actor, key, o.Fingerprint); ok || e != nil {
			result = old
			return e
		}
		if !s.SchemaReady {
			return Fault("schema_migration_required", ErrUnavailable)
		}
		if s.Routing.ActiveSwitchID != nil {
			return Fault("switch_in_progress", ErrConflict)
		}
		if in.Scope == "server" {
			if _, err = f.Servers.Get(ctx, in.ServerID); err != nil {
				return err
			}
			if s.Routing.DefaultServerID == in.ServerID || f.busy(s, in.ServerID) {
				return Fault("server_in_use", ErrConflict)
			}
			o.Server = ptr(in.ServerID)
		}
		o.Scope = in.Scope
		found := map[string]bool{}
		err = f.eachAccount(ctx, func(a domain.Account) error {
			for _, c := range a.Configs {
				wanted := in.All
				for _, id := range ids {
					if id == c.ID {
						wanted = true
						found[id] = true
					}
				}
				if !wanted {
					continue
				}
				generationIDs := []string{}
				if in.Scope == "server" {
					if c.ServerID == in.ServerID && c.Desired {
						return Fault("server_in_use", ErrConflict)
					}
					has := false
					for _, b := range c.Issuances {
						if b.ServerID == in.ServerID && b.State != "revoked" {
							has = true
							generationIDs = append(generationIDs, b.Generation)
						}
					}
					if !has {
						continue
					}
				}
				o.Items = append(o.Items, domain.FleetItem{GenerationIDs: generationIDs, ID: f.NewID(), ConfigID: c.ID, OwnerID: a.OwnerID, Source: nullable(c.ServerID), Target: nullable(in.ServerID), Status: "pending"})
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, id := range ids {
			if !found[id] {
				return ErrNotFound
			}
		}
		sort.Slice(o.Items, func(i, j int) bool { return o.Items[i].ID < o.Items[j].ID })
		o.Counts = &domain.FleetCounts{Requested: len(o.Items), Pending: len(o.Items)}
		o.Phase = "processing"
		s.Operations = append(s.Operations, o)
		if err = f.save(ctx, &s); err != nil {
			return err
		}
		if in.Scope == "all_servers" {
			for _, item := range o.Items {
				if err = f.mutateConfig(ctx, item.OwnerID, item.ConfigID, func(c *domain.ManagedConfig) error { c.Desired = false; return nil }); err != nil {
					return err
				}
			}
		}
		result = o
		return nil
	})
	return result, err
}
func (f *Fleet) Status(ctx context.Context, actor, id string) (domain.FleetOperation, error) {
	if err := f.Access.RequireAdmin(ctx, actor); err != nil {
		return domain.FleetOperation{}, err
	}
	s, err := f.Store.LoadFleet(ctx)
	if err != nil {
		return domain.FleetOperation{}, err
	}
	for _, o := range s.Operations {
		if o.ID == id {
			return o, nil
		}
	}
	return domain.FleetOperation{}, ErrNotFound
}
func (f *Fleet) Operations(ctx context.Context, actor string) ([]domain.FleetOperation, error) {
	if err := f.Access.RequireAdmin(ctx, actor); err != nil {
		return nil, err
	}
	s, err := f.Store.LoadFleet(ctx)
	if err != nil {
		return nil, err
	}
	result := append([]domain.FleetOperation{}, s.Operations...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID > result[j].ID
		}
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}
func (f *Fleet) Command(ctx context.Context, actor, id, key, route string, revision int64, selection domain.Selection) (domain.FleetOperation, error) {
	var result domain.FleetOperation
	if err := f.Access.RequireAdmin(ctx, actor); err != nil {
		return result, err
	}
	if !ValidKey(key) {
		return result, ErrInvalid
	}
	err := f.Guard.With(ctx, func(ctx context.Context) error {
		s, err := f.Store.LoadFleet(ctx)
		if err != nil {
			return err
		}
		for i := range s.Operations {
			o := &s.Operations[i]
			if o.ID != id {
				continue
			}
			fp := digest(struct {
				Revision  int64
				Selection domain.Selection
			}{revision, selection})
			for _, c := range o.Commands {
				if c.Actor == actor && c.Route == route && c.Key == key {
					if c.Fingerprint != fp {
						return Fault("idempotency_conflict", ErrConflict)
					}
					result = *o
					return nil
				}
			}
			if o.Server != nil {
				server, e := f.Servers.Get(ctx, *o.Server)
				if e != nil {
					return e
				}
				if o.Kind == "prepare" && server.Revision != o.ExpectedRevision {
					return ErrConflict
				}
				for _, other := range s.Operations {
					if other.ID == o.ID || other.Status != "queued" && other.Status != "running" && other.Status != "needs_input" {
						continue
					}
					if other.Kind == "switch" || other.Server != nil && *other.Server == *o.Server {
						return Fault("server_busy", ErrConflict)
					}
				}
			}
			if route == "resume" {
				if o.Kind != "prepare" || o.Status != "needs_input" {
					return Fault("operation_not_resumable", ErrConflict)
				}
				if revision != o.ExpectedRevision {
					return ErrConflict
				}
				match := false
				for _, c := range o.Details.Candidates {
					if c.ID == selection.CandidateID {
						for _, port := range c.Ports {
							if port == selection.UDPPort {
								match = true
							}
						}
					}
				}
				if !match {
					return ErrInvalid
				}
				o.Selection = selection
			} else {
				if (o.Status != "partial" && o.Status != "failed") || !o.Retryable {
					return Fault("operation_not_resumable", ErrConflict)
				}
				if o.Kind == "switch" {
					if o.RoutingRevision == nil || s.Routing.Revision != *o.RoutingRevision || s.Routing.DefaultServerID != *o.Target {
						return Fault("switch_superseded", ErrConflict)
					}
					if s.Routing.ActiveSwitchID != nil {
						return Fault("switch_in_progress", ErrConflict)
					}
					s.Routing.ActiveSwitchID = ptr(o.ID)
				}
				if o.Kind == "revoke" && o.Server != nil {
					if e := f.serverRevocationSafe(ctx, s, *o.Server, o.Items); e != nil {
						return e
					}
				}
				for j := range o.Items {
					if o.Items[j].Status == "failed" {
						o.Items[j].Status = "pending"
						o.Items[j].Error = nil
					}
				}
			}
			o.Commands = append(o.Commands, domain.FleetCommand{Actor: actor, Key: key, Route: route, Fingerprint: fp})
			o.Status = "queued"
			o.Error = nil
			o.Retryable = false
			o.UpdatedAt = f.Now().UTC()
			recount(o)
			if err = f.save(ctx, &s); err != nil {
				return err
			}
			result = *o
			return nil
		}
		return ErrNotFound
	})
	return result, err
}
func (f *Fleet) mutateConfig(ctx context.Context, owner, id string, fn func(*domain.ManagedConfig) error) error {
	for retry := 0; retry < 32; retry++ {
		a, err := f.Accounts.Load(ctx, owner)
		if err != nil {
			return err
		}
		found := false
		for i := range a.Configs {
			if a.Configs[i].ID == id {
				found = true
				if err = fn(&a.Configs[i]); err != nil {
					return err
				}
				break
			}
		}
		if !found {
			return ErrNotFound
		}
		ok, err := f.Accounts.Save(ctx, a, a.Revision)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return ErrConflict
}
func recount(o *domain.FleetOperation) {
	if o.Counts == nil {
		return
	}
	c := &domain.FleetCounts{Requested: len(o.Items)}
	for _, item := range o.Items {
		switch item.Status {
		case "succeeded":
			c.Succeeded++
		case "failed":
			c.Failed++
		case "skipped":
			c.Skipped++
		default:
			c.Pending++
		}
	}
	o.Counts = c
}
func (f *Fleet) Process(ctx context.Context) (bool, error) {
	worked := false
	err := f.Guard.With(ctx, func(ctx context.Context) error {
		s, err := f.Store.LoadFleet(ctx)
		if err != nil {
			return err
		}
		for index := range s.Operations {
			o := &s.Operations[index]
			if o.Status != "queued" && o.Status != "running" {
				continue
			}
			worked = true
			o.Status = "running"
			o.Phase = "processing"
			o.UpdatedAt = f.Now().UTC()
			if err = f.save(ctx, &s); err != nil {
				return err
			}
			if o.Kind == "prepare" {
				return f.prepare(ctx, &s, index)
			}
			for i := range o.Items {
				item := &o.Items[i]
				if item.Status != "pending" && item.Status != "running" {
					continue
				}
				item.Status = "running"
				item.Attempts++
				if err = f.save(ctx, &s); err != nil {
					return err
				}
				var e error
				if o.Kind == "switch" {
					e = f.switchItem(ctx, o, item)
				} else {
					e = f.revokeItem(ctx, o, item)
				}
				if e != nil {
					item.Status = "failed"
					item.Error = ptr(ErrorCode(e))
				} else if item.Status != "skipped" {
					item.Status = "succeeded"
					item.Error = nil
				}
				o.UpdatedAt = f.Now().UTC()
				recount(o)
				return f.save(ctx, &s)
			}
			recount(o)
			o.Status = "succeeded"
			if o.Counts.Failed > 0 {
				if o.Counts.Succeeded > 0 {
					o.Status = "partial"
				} else {
					o.Status = "failed"
				}
				o.Retryable = true
			}
			o.Phase = "finished"
			if o.Kind == "switch" && s.Routing.ActiveSwitchID != nil && *s.Routing.ActiveSwitchID == o.ID {
				s.Routing.ActiveSwitchID = nil
			}
			return f.save(ctx, &s)
		}
		return nil
	})
	return worked, err
}
func (f *Fleet) prepare(ctx context.Context, s *domain.FleetControl, index int) error {
	o := &s.Operations[index]
	server, err := f.Servers.Get(ctx, *o.Server)
	if err != nil {
		return err
	}
	if server.PublicHost == "" {
		if e := publicHost(&server); e != nil {
			return e
		}
	}
	var prepared Prepared
	if server.Revision != o.ExpectedRevision {
		err = ErrConflict
	} else {
		var progressErr error
		prepared, err = f.Host.Prepare(ctx, server, o.Selection, func(name, status string) {
			if progressErr != nil {
				return
			}
			for j := range o.Steps {
				if o.Steps[j].Name == name {
					o.Steps[j].Status = status
				}
			}
			o.UpdatedAt = f.Now().UTC()
			progressErr = f.save(ctx, s)
		})
		if progressErr != nil {
			return progressErr
		}
	}
	if err == nil && prepared.Discovery == nil && (server.PublicEndpoint != "" && server.PublicEndpoint != prepared.Endpoint || server.Container != "" && server.Container != prepared.Container || server.Interface != "" && server.Interface != prepared.Interface) {
		used := false
		scanErr := f.eachAccount(ctx, func(a domain.Account) error {
			for _, c := range a.Configs {
				if c.ServerID == server.ID {
					used = true
				}
				for _, b := range c.Issuances {
					if b.ServerID == server.ID {
						used = true
					}
				}
			}
			return nil
		})
		if scanErr != nil {
			return scanErr
		}
		if used {
			err = Fault("discovery_changed", ErrConflict)
		}
	}

	o.UpdatedAt = f.Now().UTC()
	if err != nil {
		o.Status = "failed"
		o.Phase = "finished"
		o.Error = ptr(ErrorCode(err))
		o.Retryable = !errors.Is(err, ErrConflict)
		server.PreparationStatus = "failed"
		server.LastError = o.Error
		for j := range o.Steps {
			if o.Steps[j].Status == "running" {
				o.Steps[j].Status = "failed"
				o.Steps[j].ErrorCode = o.Error
			}
		}
	} else if prepared.Discovery != nil {
		o.Status = "needs_input"
		o.Phase = "waiting_input"
		o.Details = prepared.Discovery
		server.PreparationStatus = "needs_input"
	} else {
		server.SSHHostKey = prepared.HostKey
		server.SSHHostFingerprint = prepared.Fingerprint
		server.PublicEndpoint = prepared.Endpoint
		server.Container = prepared.Container
		server.Interface = prepared.Interface
		server.Helper = &domain.HelperRelease{Version: prepared.HelperVersion, SHA256: prepared.HelperHash}
		server.PreparationStatus = "ready"
		r := server.Revision
		server.PreparedRevision = &r
		now := f.Now().UTC()
		server.CheckedAt = &now
		server.LastError = nil
		o.Status = "succeeded"
		o.Phase = "finished"
		o.Details = nil
		o.Error = nil
		o.Retryable = false
	}
	server.LastOperation = ptr(o.ID)
	server.UpdatedAt = f.Now().UTC()
	if server.Revision == o.ExpectedRevision {
		ok, e := f.Servers.Update(ctx, server, server.Revision)
		if e != nil {
			return e
		}
		if !ok {
			return ErrConflict
		}
	}
	return f.save(ctx, s)
}
func (f *Fleet) switchItem(ctx context.Context, o *domain.FleetOperation, item *domain.FleetItem) error {
	server, err := f.Servers.Get(ctx, *o.Target)
	if err != nil {
		return err
	}
	if !ready(server) {
		return Fault("server_not_ready", ErrConflict)
	}
	var binding domain.Issuance
	var name string
	err = f.mutateConfig(ctx, item.OwnerID, item.ConfigID, func(c *domain.ManagedConfig) error {
		if c.State() != "active" {
			return Fault("deleted_during_switch", ErrNotFound)
		}
		name = c.Name
		for i := len(c.Issuances) - 1; i >= 0; i-- {
			if c.Issuances[i].ServerID == server.ID {
				binding = c.Issuances[i]
				break
			}
		}
		if binding.Generation == "" || binding.State == "revoked" {
			binding = domain.Issuance{ServerID: server.ID, Generation: f.NewID(), State: "provisioning", CreatedAt: f.Now().UTC()}
			c.Issuances = append(c.Issuances, binding)
		}
		return nil
	})
	if err != nil {
		if ErrorCode(err) == "deleted_during_switch" {
			item.Status = "skipped"
			item.Error = ptr("deleted_during_switch")
			return nil
		}
		return err
	}
	action := "reused"
	if binding.State == "active" {
		if err = f.Host.Verify(ctx, server, binding.Generation, binding.RemoteID); err != nil {
			return err
		}
		if _, err = f.Files.Get(ctx, item.OwnerID, item.ConfigID, binding.Generation); err != nil {
			return Fault("file_unavailable", err)
		}
	} else if binding.State == "provisioning" {
		host, e := f.Host.ForServer(ctx, server)
		if e != nil {
			return e
		}
		created, e := host.Create(ctx, binding.Generation, item.OwnerID, name)
		if e != nil {
			return e
		}
		if created.RemoteID == "" || len(created.File) == 0 {
			return Fault("host_operation_unconfirmed", ErrUnavailable)
		}
		if e = f.Files.Put(ctx, item.OwnerID, item.ConfigID, binding.Generation, created.File); e != nil {
			return Fault("storage_unavailable", e)
		}
		binding.RemoteID = created.RemoteID
		binding.State = "active"
		action = "created"
	} else {
		return Fault("host_operation_unconfirmed", ErrConflict)
	}
	err = f.mutateConfig(ctx, item.OwnerID, item.ConfigID, func(c *domain.ManagedConfig) error {
		for i := range c.Issuances {
			if c.Issuances[i].Generation == binding.Generation {
				c.Issuances[i] = binding
			}
		}
		if !c.Desired || c.DeletedAt != nil {
			return Fault("deleted_during_switch", ErrNotFound)
		}
		if c.Generation == binding.Generation && c.ServerID == server.ID {
			action = "already_selected"
		} else {
			c.Version++
		}
		c.ServerID = server.ID
		c.Generation = binding.Generation
		c.RemoteID = binding.RemoteID
		c.Provisioned = true
		return nil
	})
	if err != nil {
		return err
	}
	item.Action = ptr(action)
	return nil
}
func (f *Fleet) RevokeConfig(ctx context.Context, owner, id, serverID string) error {
	return f.revokeGenerations(ctx, owner, id, serverID, nil)
}
func (f *Fleet) revokeGenerations(ctx context.Context, owner, id, serverID string, generations []string) error {
	a, err := f.Accounts.Load(ctx, owner)
	if err != nil {
		return err
	}
	var config *domain.ManagedConfig
	for i := range a.Configs {
		if a.Configs[i].ID == id {
			config = &a.Configs[i]
			break
		}
	}
	if config == nil {
		return ErrNotFound
	}
	for _, b := range config.Issuances {
		if generations != nil {
			matched := false
			for _, g := range generations {
				if g == b.Generation {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if b.State == "revoked" || serverID != "" && b.ServerID != serverID {
			continue
		}

		host, e := f.Provider(ctx, b.ServerID)
		if e != nil {
			return e
		}
		if b.RemoteID == "" {
			resolver, ok := host.(interface {
				Resolve(context.Context, string) (string, error)
			})
			if !ok {
				return Fault("host_operation_unconfirmed", ErrUnavailable)
			}
			b.RemoteID, e = resolver.Resolve(ctx, b.Generation)
			if e != nil {
				return e
			}
			if e = f.mutateConfig(ctx, owner, id, func(c *domain.ManagedConfig) error {
				for i := range c.Issuances {
					if c.Issuances[i].Generation == b.Generation {
						c.Issuances[i].RemoteID = b.RemoteID
					}
				}
				return nil
			}); e != nil {
				return e
			}
		}
		if e = host.Revoke(ctx, b.Generation, b.RemoteID); e != nil {
			return e
		}
		if e = f.mutateConfig(ctx, owner, id, func(c *domain.ManagedConfig) error {
			for i := range c.Issuances {
				if c.Issuances[i].Generation == b.Generation {
					c.Issuances[i].State = "revoked"
				}
			}
			return nil
		}); e != nil {
			return e
		}
	}
	return nil
}
func (f *Fleet) revokeItem(ctx context.Context, o *domain.FleetOperation, item *domain.FleetItem) error {
	scope := ""
	if o.Server != nil {
		scope = *o.Server
	}
	if scope == "" {
		if err := f.mutateConfig(ctx, item.OwnerID, item.ConfigID, func(c *domain.ManagedConfig) error { c.Desired = false; return nil }); err != nil {
			return err
		}
	}
	var revokeErr error
	if scope != "" {
		revokeErr = f.revokeGenerations(ctx, item.OwnerID, item.ConfigID, scope, item.GenerationIDs)
	} else {
		revokeErr = f.RevokeConfig(ctx, item.OwnerID, item.ConfigID, scope)
	}
	if err := revokeErr; err != nil {
		return err
	}
	if scope == "" {
		return f.mutateConfig(ctx, item.OwnerID, item.ConfigID, func(c *domain.ManagedConfig) error {
			now := f.Now().UTC()
			c.Provisioned = false
			c.DeletedAt = &now
			return nil
		})
	}
	return nil
}
func (f *Fleet) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		for n := 0; n < 100; n++ {
			worked, err := f.Process(ctx)
			if err != nil || !worked {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (f *Fleet) serverRevocationSafe(ctx context.Context, s domain.FleetControl, server string, items []domain.FleetItem) error {
	if s.Routing.DefaultServerID == server || s.Routing.ActiveSwitchID != nil {
		return Fault("server_in_use", ErrConflict)
	}
	for _, item := range items {
		a, err := f.Accounts.Load(ctx, item.OwnerID)
		if err != nil {
			return err
		}
		for _, c := range a.Configs {
			if c.ID == item.ConfigID && c.ServerID == server && c.Desired {
				return Fault("server_in_use", ErrConflict)
			}
		}
	}
	return nil
}
