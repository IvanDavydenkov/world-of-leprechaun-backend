package application

import (
	"context"
	"leprechaun/vpn-configs/internal/domain"
)

type LegacyImportReport struct {
	Accounts   int    `json:"accounts"`
	Configs    int    `json:"configs_to_bind"`
	Operations int    `json:"operations_to_bind"`
	ServerID   string `json:"server_id"`
	Applied    bool   `json:"applied"`
}

func (f *Fleet) ImportLegacy(ctx context.Context, serverID string, apply bool) (LegacyImportReport, error) {
	report := LegacyImportReport{ServerID: serverID}
	err := f.Guard.With(ctx, func(ctx context.Context) error {
		if _, err := f.Servers.Get(ctx, serverID); err != nil {
			return err
		}
		state, err := f.Store.LoadFleet(ctx)
		if err != nil {
			return err
		}
		scan := func(write bool) error {
			return f.eachAccount(ctx, func(a domain.Account) error {
				if !write {
					report.Accounts++
				}
				changed := false
				for i := range a.Configs {
					c := &a.Configs[i]
					if c.ServerID == "" {
						if !write {
							report.Configs++
						}
						c.ServerID = serverID
						changed = true
					}
					if c.ServerID == serverID && c.Generation != "" {
						found := false
						for _, b := range c.Issuances {
							if b.Generation == c.Generation {
								found = true
							}
						}
						if !found {
							status := "provisioning"
							if c.Provisioned {
								status = "active"
							}
							if c.DeletedAt != nil {
								status = "revoked"
							}
							c.Issuances = append(c.Issuances, domain.Issuance{ServerID: serverID, Generation: c.Generation, RemoteID: c.RemoteID, State: status, CreatedAt: c.CreatedAt})
							changed = true
						}
					}
				}
				for i := range a.Operations {
					o := &a.Operations[i]
					if o.ServerID == "" {
						if !write {
							report.Operations++
						}
						o.ServerID = serverID
						changed = true
					}
				}
				if write && changed {
					ok, e := f.Accounts.Save(ctx, a, a.Revision)
					if e != nil {
						return e
					}
					if !ok {
						return ErrConflict
					}
				}
				return nil
			})
		}
		if err = scan(false); err != nil {
			return err
		}
		if !apply {
			return nil
		}
		state.SchemaReady = false
		if err = f.save(ctx, &state); err != nil {
			return err
		}
		if err = scan(true); err != nil {
			return err
		}
		state.SchemaReady = true
		if state.Routing.DefaultServerID == "" {
			state.Routing.DefaultServerID = serverID
			state.Routing.Revision++
		}
		if err = f.save(ctx, &state); err != nil {
			return err
		}
		report.Applied = true
		return nil
	})
	return report, err
}
