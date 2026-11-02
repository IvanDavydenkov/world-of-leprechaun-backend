package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"leprechaun/vpn-configs/internal/domain"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ServerRepository interface {
	Create(context.Context, domain.VPNServer) error
	Get(context.Context, string) (domain.VPNServer, error)
	List(context.Context) ([]domain.VPNServer, error)
	Update(context.Context, domain.VPNServer, int64) (bool, error)
}
type ServerSecrets interface {
	EncryptServerPassword(string, string) ([]byte, error)
}
type ServerFields struct {
	Name               string `json:"name"`
	SSHAddress         string `json:"ssh_address"`
	SSHUsername        string `json:"ssh_username"`
	Password           string `json:"password"`
	SSHHostKey         string `json:"ssh_host_key"`
	SSHHostFingerprint string `json:"ssh_host_fingerprint"`
	PublicHost         string `json:"public_host"`
	PublicEndpoint     string `json:"public_endpoint"`
	Container          string `json:"container"`
	Interface          string `json:"interface"`
}
type ServerPatch struct {
	ExpectedRevision   int64   `json:"expected_revision"`
	Name               *string `json:"name"`
	SSHAddress         *string `json:"ssh_address"`
	SSHUsername        *string `json:"ssh_username"`
	Password           *string `json:"password"`
	SSHHostKey         *string `json:"ssh_host_key"`
	SSHHostFingerprint *string `json:"ssh_host_fingerprint"`
	PublicHost         *string `json:"public_host"`
	PublicEndpoint     *string `json:"public_endpoint"`
	Container          *string `json:"container"`
	Interface          *string `json:"interface"`
}
type ServerView struct {
	domain.VPNServer
	PasswordSet    bool `json:"password_set"`
	IsDefault      bool `json:"is_default"`
	BindingsCounts struct {
		Active  int `json:"active"`
		Revoked int `json:"revoked"`
		Pending int `json:"pending"`
	} `json:"bindings_counts"`
}
type ServerRegistry struct {
	repo    ServerRepository
	secrets ServerSecrets
	access  Access
	id      func() string
	now     func() time.Time
	fleet   *Fleet
}

func (r *ServerRegistry) Authorize(ctx context.Context, actor string) error {
	return r.access.RequireAdmin(ctx, actor)
}
func NewServerRegistry(repo ServerRepository, secrets ServerSecrets, access Access, id func() string, now func() time.Time) *ServerRegistry {
	return &ServerRegistry{repo: repo, secrets: secrets, access: access, id: id, now: now}
}
func viewServer(s domain.VPNServer) ServerView {
	if s.PreparationStatus == "" {
		s.PreparationStatus = "not_prepared"
	}
	if s.PublicHost == "" {
		_ = publicHost(&s)
	}
	set := len(s.PasswordCiphertext) > 0
	s.PasswordCiphertext = nil
	return ServerView{VPNServer: s, PasswordSet: set}
}

var serverIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var serverHost = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

func validServerAddress(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && (net.ParseIP(host) != nil || serverHost.MatchString(host))
}

var fingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

func validateServer(s domain.VPNServer) error {
	if strings.TrimSpace(s.Name) == "" || len(s.Name) > 128 || strings.ContainsAny(s.Name, "\r\n\x00") || !validServerAddress(s.SSHAddress) || !serverIdentifier.MatchString(s.SSHUsername) {
		return ErrInvalid
	}
	if s.PublicEndpoint != "" && !validServerAddress(s.PublicEndpoint) || s.Container != "" && !serverIdentifier.MatchString(s.Container) || s.Interface != "" && (!serverIdentifier.MatchString(s.Interface) || len(s.Interface) > 15) {
		return ErrInvalid
	}
	if s.PublicHost != "" && net.ParseIP(s.PublicHost) == nil && !serverHost.MatchString(s.PublicHost) {
		return ErrInvalid
	}
	if s.PublicHost != "" && s.PublicEndpoint != "" {
		h, _, _ := net.SplitHostPort(s.PublicEndpoint)
		if h != s.PublicHost {
			return ErrInvalid
		}
	}
	if s.SSHHostKey == "" {
		if !fingerprintPattern.MatchString(s.SSHHostFingerprint) {
			return ErrInvalid
		}
		return nil
	}
	fields := strings.Fields(s.SSHHostKey)
	if len(fields) != 2 || fields[0] != "ssh-ed25519" {
		return ErrInvalid
	}
	key, err := base64.StdEncoding.DecodeString(fields[1])
	prefix := append([]byte{0, 0, 0, 11}, []byte("ssh-ed25519")...)
	prefix = append(prefix, 0, 0, 0, 32)
	if err != nil || len(key) != 51 || !bytes.Equal(key[:19], prefix) {
		return ErrInvalid
	}
	if s.SSHHostFingerprint != "" {
		d := sha256.Sum256(key)
		if s.SSHHostFingerprint != "SHA256:"+base64.RawStdEncoding.EncodeToString(d[:]) {
			return ErrInvalid
		}
	}
	return nil
}
func publicHost(s *domain.VPNServer) error {
	if s.PublicHost != "" {
		return nil
	}
	h, _, _ := net.SplitHostPort(s.SSHAddress)
	if s.PublicEndpoint != "" {
		h, _, _ = net.SplitHostPort(s.PublicEndpoint)
	}
	if ip := net.ParseIP(h); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()) {
		return Fault("public_host_required", ErrInvalid)
	}
	if h == "localhost" {
		return Fault("public_host_required", ErrInvalid)
	}
	s.PublicHost = h
	return nil
}

type registryFleetContext struct{}

func (r *ServerRegistry) UseFleet(f *Fleet) { r.fleet = f }
func (r *ServerRegistry) enrich(ctx context.Context, s domain.VPNServer) (ServerView, error) {
	v := viewServer(s)
	if r.fleet == nil {
		return v, nil
	}
	state, err := r.fleet.Store.LoadFleet(ctx)
	if err != nil {
		return v, err
	}
	v.IsDefault = state.Routing.DefaultServerID == s.ID
	err = r.fleet.eachAccount(ctx, func(a domain.Account) error {
		for _, c := range a.Configs {
			seen := map[string]domain.Issuance{}
			for _, b := range c.Issuances {
				seen[b.ServerID] = b
			}
			if b, ok := seen[s.ID]; ok {
				switch b.State {
				case "active":
					v.BindingsCounts.Active++
				case "revoked":
					v.BindingsCounts.Revoked++
				default:
					v.BindingsCounts.Pending++
				}
			}
		}
		return nil
	})
	return v, err
}
func (r *ServerRegistry) Create(ctx context.Context, actor string, in ServerFields) (ServerView, error) {
	if r.fleet != nil && ctx.Value(registryFleetContext{}) == nil {
		var result ServerView
		err := r.fleet.Guard.With(ctx, func(c context.Context) error {
			var e error
			result, e = r.Create(context.WithValue(c, registryFleetContext{}, true), actor, in)
			return e
		})
		return result, err
	}
	if err := r.access.RequireAdmin(ctx, actor); err != nil {
		return ServerView{}, err
	}
	s := domain.VPNServer{ID: r.id(), Name: in.Name, SSHAddress: in.SSHAddress, SSHUsername: in.SSHUsername, SSHHostKey: in.SSHHostKey, SSHHostFingerprint: in.SSHHostFingerprint, PublicHost: in.PublicHost, PreparationStatus: "not_prepared", PublicEndpoint: in.PublicEndpoint, Container: in.Container, Interface: in.Interface, Revision: 1, CreatedAt: r.now().UTC(), UpdatedAt: r.now().UTC()}
	if err := validateServer(s); err != nil {
		return ServerView{}, err
	}
	if in.Password == "" || len(in.Password) > 4096 {
		return ServerView{}, ErrInvalid
	}
	encrypted, err := r.secrets.EncryptServerPassword(s.ID, in.Password)
	if err != nil {
		return ServerView{}, ErrUnavailable
	}
	if (in.SSHHostKey == "") == (in.SSHHostFingerprint == "") {
		return ServerView{}, ErrInvalid
	}
	if err := publicHost(&s); err != nil {
		return ServerView{}, err
	}
	normalizeServerKey(&s)
	s.PasswordCiphertext = encrypted
	if err = r.repo.Create(ctx, s); err != nil {
		return ServerView{}, err
	}
	return r.enrich(ctx, s)
}
func (r *ServerRegistry) Get(ctx context.Context, actor, id string) (ServerView, error) {
	if err := r.access.RequireAdmin(ctx, actor); err != nil {
		return ServerView{}, err
	}
	if !ValidID(id) {
		return ServerView{}, ErrNotFound
	}
	s, err := r.repo.Get(ctx, id)
	if err != nil {
		return ServerView{}, err
	}
	return r.enrich(ctx, s)
}
func (r *ServerRegistry) List(ctx context.Context, actor string) ([]ServerView, error) {
	if err := r.access.RequireAdmin(ctx, actor); err != nil {
		return nil, err
	}
	items, err := r.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]ServerView, 0, len(items))
	for _, s := range items {
		v, e := r.enrich(ctx, s)
		if e != nil {
			return nil, e
		}
		result = append(result, v)
	}
	return result, nil
}
func (r *ServerRegistry) Patch(ctx context.Context, actor, id string, in ServerPatch) (ServerView, error) {
	if r.fleet != nil && ctx.Value(registryFleetContext{}) == nil {
		var result ServerView
		err := r.fleet.Guard.With(ctx, func(c context.Context) error {
			var e error
			result, e = r.Patch(context.WithValue(c, registryFleetContext{}, true), actor, id, in)
			return e
		})
		return result, err
	}
	if err := r.access.RequireAdmin(ctx, actor); err != nil {
		return ServerView{}, err
	}
	if !ValidID(id) {
		return ServerView{}, ErrNotFound
	}
	if in.ExpectedRevision < 1 {
		return ServerView{}, ErrInvalid
	}
	s, err := r.repo.Get(ctx, id)
	if err != nil {
		return ServerView{}, err
	}
	if s.Revision != in.ExpectedRevision {
		return ServerView{}, ErrConflict
	}
	if in.SSHHostKey != nil && in.SSHHostFingerprint != nil {
		return ServerView{}, ErrInvalid
	}
	if r.fleet != nil {
		state, e := r.fleet.Store.LoadFleet(ctx)
		if e != nil {
			return ServerView{}, e
		}
		if r.fleet.busy(state, id) {
			return ServerView{}, Fault("server_busy", ErrConflict)
		}
	}
	different := func(v *string, old string) bool { return v != nil && *v != old }
	connectionChanged := different(in.SSHAddress, s.SSHAddress) || different(in.SSHUsername, s.SSHUsername) || in.Password != nil || different(in.SSHHostKey, s.SSHHostKey) || different(in.SSHHostFingerprint, s.SSHHostFingerprint) || different(in.PublicHost, s.PublicHost) || different(in.PublicEndpoint, s.PublicEndpoint) || different(in.Container, s.Container) || different(in.Interface, s.Interface)
	if connectionChanged && r.fleet != nil {
		state, e := r.fleet.Store.LoadFleet(ctx)
		if e != nil {
			return ServerView{}, e
		}
		if r.fleet.busy(state, id) {
			return ServerView{}, Fault("server_busy", ErrConflict)
		}
		identityChanged := different(in.SSHHostKey, s.SSHHostKey) || different(in.SSHHostFingerprint, s.SSHHostFingerprint) || different(in.PublicHost, s.PublicHost) || different(in.PublicEndpoint, s.PublicEndpoint) || different(in.Container, s.Container) || different(in.Interface, s.Interface)
		if identityChanged {
			used := false
			e = r.fleet.eachAccount(ctx, func(a domain.Account) error {
				for _, c := range a.Configs {
					if c.ServerID == id {
						used = true
					}
					for _, b := range c.Issuances {
						if b.ServerID == id {
							used = true
						}
					}
				}
				return nil
			})
			if e != nil {
				return ServerView{}, e
			}
			if used {
				return ServerView{}, Fault("server_identity_locked", ErrConflict)
			}
		}
	}
	if in.SSHHostKey != nil {
		s.SSHHostFingerprint = ""
	}
	if in.SSHHostFingerprint != nil {
		s.SSHHostKey = ""
	}
	changed := false
	for _, field := range []struct {
		dst   *string
		value *string
	}{{&s.Name, in.Name}, {&s.SSHAddress, in.SSHAddress}, {&s.SSHUsername, in.SSHUsername}, {&s.SSHHostKey, in.SSHHostKey}, {&s.SSHHostFingerprint, in.SSHHostFingerprint}, {&s.PublicHost, in.PublicHost}, {&s.PublicEndpoint, in.PublicEndpoint}, {&s.Container, in.Container}, {&s.Interface, in.Interface}} {
		if field.value != nil {
			*field.dst = *field.value
			changed = true
		}
	}
	if err := validateServer(s); err != nil {
		return ServerView{}, err
	}
	normalizeServerKey(&s)
	if in.Password != nil {
		if *in.Password == "" || len(*in.Password) > 4096 {
			return ServerView{}, ErrInvalid
		}
		s.PasswordCiphertext, err = r.secrets.EncryptServerPassword(s.ID, *in.Password)
		if err != nil {
			return ServerView{}, ErrUnavailable
		}
		changed = true
	}
	if !changed {
		return ServerView{}, ErrInvalid
	}
	if connectionChanged {
		s.PreparationStatus = "stale"
		s.PreparedRevision = nil
	} else if s.PreparedRevision != nil {
		next := s.Revision + 1
		s.PreparedRevision = &next
	}
	s.Revision++
	s.UpdatedAt = r.now().UTC()
	ok, err := r.repo.Update(ctx, s, in.ExpectedRevision)
	if err != nil {
		return ServerView{}, err
	}
	if !ok {
		return ServerView{}, ErrConflict
	}
	return r.enrich(ctx, s)
}

func (v ServerView) MarshalJSON() ([]byte, error) {
	type alias ServerView
	return json.Marshal(struct {
		alias
		HostKey   *string `json:"ssh_host_key"`
		Endpoint  *string `json:"public_endpoint"`
		Container *string `json:"container"`
		Interface *string `json:"interface"`
	}{alias(v), nullable(v.VPNServer.SSHHostKey), nullable(v.PublicEndpoint), nullable(v.Container), nullable(v.Interface)})
}

func normalizeServerKey(s *domain.VPNServer) {
	if s.SSHHostKey == "" {
		return
	}
	parts := strings.Fields(s.SSHHostKey)
	if len(parts) != 2 {
		return
	}
	key, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	hash := sha256.Sum256(key)
	s.SSHHostFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
	s.SSHHostKey = parts[0] + " " + parts[1]
}
