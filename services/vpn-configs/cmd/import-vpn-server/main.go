// import-vpn-server is an operator-only schema migration. It never contacts VPN hosts.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/domain"
	"leprechaun/vpn-configs/internal/infrastructure/config"
	"leprechaun/vpn-configs/internal/infrastructure/mongodb"
	"leprechaun/vpn-configs/internal/infrastructure/vault"
	"net"
	"os"
	"time"
)

type localOperator struct{}

func (localOperator) RequireAdmin(context.Context, string) error { return nil }
func (localOperator) RequireUser(context.Context, string) error  { return nil }
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Migration failed:", application.ErrorCode(err))
		os.Exit(1)
	}
}
func run() error {
	serverID := flag.String("server-id", "", "Existing registry record matching the legacy env host")
	create := flag.Bool("create-server", false, "Explicitly create/reuse a deterministic legacy record")
	apply := flag.Bool("apply", false, "Apply changes; default is dry run")
	stopped := flag.Bool("confirm-workers-stopped", false, "Confirm old API/workers are stopped before apply")
	flag.Parse()
	if *apply && !*stopped {
		return application.ErrInvalid
	}
	if (*serverID == "") == (!*create) {
		return application.ErrInvalid
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.HostAddress == "" || cfg.PublicEndpoint == "" || cfg.KnownHostsFile == "" {
		return application.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client, accounts, err := mongodb.Open(ctx, cfg.MongoURI, cfg.MongoDatabase)
	if err != nil {
		return err
	}
	defer client.Disconnect(context.Background())
	db := client.Database(cfg.MongoDatabase)
	repo := mongodb.NewServerRepository(db)
	secrets, err := vault.New(mongodb.NewFileStore(db), cfg.EncryptionKey)
	if err != nil {
		return err
	}
	guard := mongodb.NewCoordinator(db)
	fleet := &application.Fleet{Store: mongodb.NewFleetStore(db), Accounts: accounts, Servers: repo, Files: secrets, Guard: guard, Access: localOperator{}, Now: time.Now}
	var key ssh.PublicKey
	if *create {
		data, e := os.ReadFile(cfg.KnownHostsFile)
		if e != nil {
			return application.ErrInvalid
		}
		host, port, e := net.SplitHostPort(cfg.HostAddress)
		if e != nil {
			return application.ErrInvalid
		}
		normalized := host
		if port != "22" {
			normalized = "[" + host + "]:" + port
		}
		remaining := data
		for len(remaining) > 0 {
			_, hosts, k, _, rest, e := ssh.ParseKnownHosts(remaining)
			if e != nil {
				break
			}
			remaining = rest
			for _, candidate := range hosts {
				if candidate == normalized && k.Type() == ssh.KeyAlgoED25519 {
					key = k
				}
			}
		}
		if key == nil {
			return application.ErrInvalid
		}
		hash := sha256.Sum256(append([]byte(cfg.HostAddress), key.Marshal()...))
		*serverID = "legacy_" + hex.EncodeToString(hash[:16])
	}
	server, err := repo.Get(ctx, *serverID)
	if errors.Is(err, application.ErrNotFound) && *create {
		host, _, _ := net.SplitHostPort(cfg.PublicEndpoint)
		server = domain.VPNServer{ID: *serverID, Name: "Legacy VPN", SSHAddress: cfg.HostAddress, SSHUsername: cfg.HostUsername, SSHHostKey: string(ssh.MarshalAuthorizedKey(key)), SSHHostFingerprint: ssh.FingerprintSHA256(key), PublicHost: host, PublicEndpoint: cfg.PublicEndpoint, Container: "amnezia-awg2", Interface: "awg0", Revision: 1, PreparationStatus: "not_prepared", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
		server.PasswordCiphertext, err = secrets.EncryptServerPassword(server.ID, cfg.HostPassword)
		if err != nil {
			return err
		}
		if !*apply {
			report := application.LegacyImportReport{ServerID: server.ID}
			after := ""
			for {
				ids, e := accounts.OwnersAfter(ctx, after, 100)
				if e != nil {
					return e
				}
				for _, id := range ids {
					a, e := accounts.Load(ctx, id)
					if e != nil {
						return e
					}
					report.Accounts++
					for _, c := range a.Configs {
						if c.ServerID == "" {
							report.Configs++
						}
					}
					for _, o := range a.Operations {
						if o.ServerID == "" {
							report.Operations++
						}
					}
				}
				if len(ids) < 100 {
					break
				}
				after = ids[len(ids)-1]
			}
			return json.NewEncoder(os.Stdout).Encode(report)
		}
		if err = repo.Create(ctx, server); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if server.SSHAddress != cfg.HostAddress || server.PublicEndpoint != cfg.PublicEndpoint || server.Container != "amnezia-awg2" || server.Interface != "awg0" {
		return application.ErrConflict
	}
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(server.SSHHostKey))
	if err != nil {
		return application.ErrInvalid
	}
	callback, err := knownhosts.New(cfg.KnownHostsFile)
	if err != nil {
		return application.ErrInvalid
	}
	if err = callback(cfg.HostAddress, &net.TCPAddr{}, public); err != nil {
		return application.ErrConflict
	}
	report, err := fleet.ImportLegacy(ctx, server.ID, *apply)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}
