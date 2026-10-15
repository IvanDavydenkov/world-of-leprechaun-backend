package application

import (
	"bytes"
	"context"
	"encoding/base64"
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
	Name           string `json:"name"`
	SSHAddress     string `json:"ssh_address"`
	SSHUsername    string `json:"ssh_username"`
	Password       string `json:"password"`
	SSHHostKey     string `json:"ssh_host_key"`
	PublicEndpoint string `json:"public_endpoint"`
	Container      string `json:"container"`
	Interface      string `json:"interface"`
}
type ServerPatch struct {
	ExpectedRevision int64   `json:"expected_revision"`
	Name             *string `json:"name"`
	SSHAddress       *string `json:"ssh_address"`
	SSHUsername      *string `json:"ssh_username"`
	Password         *string `json:"password"`
	SSHHostKey       *string `json:"ssh_host_key"`
	PublicEndpoint   *string `json:"public_endpoint"`
	Container        *string `json:"container"`
	Interface        *string `json:"interface"`
}
type ServerView struct {
	domain.VPNServer
	PasswordSet bool `json:"password_set"`
}
type ServerRegistry struct {
	repo    ServerRepository
	secrets ServerSecrets
	access  Access
	id      func() string
	now     func() time.Time
}

func (r *ServerRegistry) Authorize(ctx context.Context, actor string) error {
	return r.access.RequireAdmin(ctx, actor)
}
func NewServerRegistry(repo ServerRepository, secrets ServerSecrets, access Access, id func() string, now func() time.Time) *ServerRegistry {
	return &ServerRegistry{repo, secrets, access, id, now}
}
func viewServer(s domain.VPNServer) ServerView {
	set := len(s.PasswordCiphertext) > 0
	s.PasswordCiphertext = nil
	return ServerView{s, set}
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
func validateServer(s domain.VPNServer) error {
	if strings.TrimSpace(s.Name) == "" || len(s.Name) > 128 || strings.ContainsAny(s.Name, "\r\n\x00") || !validServerAddress(s.SSHAddress) || !validServerAddress(s.PublicEndpoint) || !serverIdentifier.MatchString(s.SSHUsername) || !serverIdentifier.MatchString(s.Container) || !serverIdentifier.MatchString(s.Interface) || len(s.Interface) > 15 {
		return ErrInvalid
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
	return nil
}
func (r *ServerRegistry) Create(ctx context.Context, actor string, in ServerFields) (ServerView, error) {
	if err := r.access.RequireAdmin(ctx, actor); err != nil {
		return ServerView{}, err
	}
	s := domain.VPNServer{ID: r.id(), Name: in.Name, SSHAddress: in.SSHAddress, SSHUsername: in.SSHUsername, SSHHostKey: in.SSHHostKey, PublicEndpoint: in.PublicEndpoint, Container: in.Container, Interface: in.Interface, Revision: 1, CreatedAt: r.now().UTC(), UpdatedAt: r.now().UTC()}
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
	s.PasswordCiphertext = encrypted
	if err = r.repo.Create(ctx, s); err != nil {
		return ServerView{}, err
	}
	return viewServer(s), nil
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
	return viewServer(s), nil
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
		result = append(result, viewServer(s))
	}
	return result, nil
}
func (r *ServerRegistry) Patch(ctx context.Context, actor, id string, in ServerPatch) (ServerView, error) {
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
	changed := false
	for _, field := range []struct {
		dst   *string
		value *string
	}{{&s.Name, in.Name}, {&s.SSHAddress, in.SSHAddress}, {&s.SSHUsername, in.SSHUsername}, {&s.SSHHostKey, in.SSHHostKey}, {&s.PublicEndpoint, in.PublicEndpoint}, {&s.Container, in.Container}, {&s.Interface, in.Interface}} {
		if field.value != nil {
			*field.dst = *field.value
			changed = true
		}
	}
	if err := validateServer(s); err != nil {
		return ServerView{}, err
	}
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
	s.Revision++
	s.UpdatedAt = r.now().UTC()
	ok, err := r.repo.Update(ctx, s, in.ExpectedRevision)
	if err != nil {
		return ServerView{}, err
	}
	if !ok {
		return ServerView{}, ErrConflict
	}
	return viewServer(s), nil
}
