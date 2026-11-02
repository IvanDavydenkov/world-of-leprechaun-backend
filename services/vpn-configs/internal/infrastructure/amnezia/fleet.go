package amnezia

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/domain"
	"net"
	"strconv"
	"strings"
	"time"
)

//go:embed assets/leprechaun_awg.py
var HelperSource []byte

//go:embed assets/prepare.py
var prepareSource string

const HelperVersion = "2.0.0"

type PasswordDecryptor interface {
	DecryptServerPassword(string, []byte) (string, error)
}
type FleetHost struct{ Secrets PasswordDecryptor }

func serverKeyCallback(keyText, fingerprint string, capture *string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if key.Type() != ssh.KeyAlgoED25519 {
			return application.Fault("host_key_mismatch", application.ErrForbidden)
		}
		if keyText != "" {
			expected, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyText))
			if err != nil || !bytes.Equal(expected.Marshal(), key.Marshal()) {
				return application.Fault("host_key_mismatch", application.ErrForbidden)
			}
		} else if ssh.FingerprintSHA256(key) != fingerprint {
			return application.Fault("host_key_mismatch", application.ErrForbidden)
		}
		if capture != nil {
			*capture = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		}
		return nil
	}
}
func (f *FleetHost) settings(s domain.VPNServer) (Settings, error) {
	password, err := f.Secrets.DecryptServerPassword(s.ID, s.PasswordCiphertext)
	if err != nil {
		return Settings{}, application.Fault("storage_unavailable", application.ErrUnavailable)
	}
	return Settings{Address: s.SSHAddress, Username: s.SSHUsername, Password: password, HostKey: s.SSHHostKey, Fingerprint: s.SSHHostFingerprint, Container: s.Container, Interface: s.Interface, PublicEndpoint: s.PublicEndpoint}, nil
}
func (f *FleetHost) ForServer(ctx context.Context, s domain.VPNServer) (application.Provisioner, error) {
	settings, err := f.settings(s)
	if err != nil {
		return nil, err
	}
	return New(settings)
}
func (f *FleetHost) Verify(ctx context.Context, s domain.VPNServer, generation, remote string) error {
	host, err := f.ForServer(ctx, s)
	if err != nil {
		return err
	}
	c := host.(*Client)
	data, _ := json.Marshal(request{Action: "verify", Generation: generation, RemoteID: remote, Container: c.container, Interface: c.iface})
	output, err := c.remote.Run(ctx, data)
	if err != nil {
		return err
	}
	var result struct {
		Verified bool   `json:"verified"`
		Error    string `json:"error"`
	}
	if json.Unmarshal(output, &result) != nil {
		return ErrUnconfirmed
	}
	if result.Verified {
		return nil
	}
	switch result.Error {
	case "helper_journal_missing", "binding_missing_on_host":
		return application.Fault(result.Error, application.ErrUnavailable)
	default:
		return ErrUnconfirmed
	}
}
func sessionRun(ctx context.Context, client *ssh.Client, command string, input any) ([]byte, error) {
	s, err := client.NewSession()
	if err != nil {
		return nil, ErrUnconfirmed
	}
	defer s.Close()
	data, _ := json.Marshal(input)
	out := &boundedBuffer{limit: 2 * 1024 * 1024}
	s.Stdin = bytes.NewReader(data)
	s.Stdout = out
	s.Stderr = io.Discard
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	if err = s.Run(command); err != nil {
		return nil, ErrUnconfirmed
	}
	return out.Bytes(), nil
}
func (f *FleetHost) Prepare(ctx context.Context, server domain.VPNServer, selection domain.Selection, progress func(string, string)) (application.Prepared, error) {
	var result application.Prepared
	settings, err := f.settings(server)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	progress("verify_host_key", "running")
	connection, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", settings.Address)
	if err != nil {
		return result, application.Fault("host_unreachable", application.ErrUnavailable)
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	verified := false
	keyCheck := serverKeyCallback(settings.HostKey, settings.Fingerprint, &result.HostKey)
	callback := func(host string, remote net.Addr, key ssh.PublicKey) error {
		if err := keyCheck(host, remote, key); err != nil {
			return err
		}
		result.Fingerprint = ssh.FingerprintSHA256(key)
		verified = true
		progress("verify_host_key", "succeeded")
		progress("authenticate", "running")
		return nil
	}
	conn, ch, req, err := ssh.NewClientConn(connection, settings.Address, &ssh.ClientConfig{User: settings.Username, Auth: []ssh.AuthMethod{ssh.Password(settings.Password)}, HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, HostKeyCallback: callback})
	if err != nil {
		if !verified {
			return result, application.Fault("host_key_mismatch", application.ErrForbidden)
		}
		return result, application.Fault("ssh_auth_failed", application.ErrForbidden)
	}
	client := ssh.NewClient(conn, ch, req)
	defer client.Close()
	progress("authenticate", "succeeded")
	progress("inspect_ubuntu", "running")
	command := "python3 -c " + shellQuote(prepareSource)
	if server.SSHUsername != "root" {
		command = "sudo -n " + command
	}
	response, err := sessionRun(ctx, client, command, map[string]any{"action": "discover"})
	if err != nil {
		code := "helper_install_failed"
		if server.SSHUsername != "root" {
			code = "sudo_required"
		}
		return result, application.Fault(code, application.ErrUnavailable)
	}
	var discovered struct {
		Candidates []domain.Candidate `json:"candidates"`
		Error      string             `json:"error"`
	}
	if json.Unmarshal(response, &discovered) != nil {
		return result, ErrUnconfirmed
	}
	if discovered.Error != "" {
		return result, prepareError(discovered.Error)
	}
	progress("inspect_ubuntu", "succeeded")
	progress("inspect_docker", "succeeded")
	progress("discover_awg", "running")
	candidates := discovered.Candidates
	if len(candidates) == 0 {
		return result, application.Fault("awg_not_found", application.ErrUnavailable)
	}
	chosen := selection
	if chosen.CandidateID == "" {
		filtered := []domain.Candidate{}
		for _, c := range candidates {
			if server.Container != "" && c.Container != server.Container || server.Interface != "" && c.Interface != server.Interface {
				continue
			}
			filtered = append(filtered, c)
		}
		if len(filtered) == 1 && len(filtered[0].Ports) == 1 {
			chosen.CandidateID = filtered[0].ID
			chosen.UDPPort = filtered[0].Ports[0]
		} else {
			result.Discovery = &domain.Discovery{Candidates: candidates, Required: []string{"candidate_id", "udp_port"}}
			return result, nil
		}
	}
	var candidate *domain.Candidate
	for i := range candidates {
		if candidates[i].ID == chosen.CandidateID {
			for _, port := range candidates[i].Ports {
				if port == chosen.UDPPort {
					candidate = &candidates[i]
				}
			}
		}
	}
	if candidate == nil {
		return result, application.Fault("discovery_changed", application.ErrConflict)
	}
	publicHost := server.PublicHost
	if chosen.PublicHost != "" {
		publicHost = chosen.PublicHost
	}
	if publicHost == "" {
		return result, application.Fault("public_host_required", application.ErrInvalid)
	}
	result.Endpoint = net.JoinHostPort(publicHost, strconv.Itoa(chosen.UDPPort))
	result.Container = candidate.Container
	result.Interface = candidate.Interface
	progress("discover_awg", "succeeded")
	progress("install_helper", "running")
	hash := sha256.Sum256(HelperSource)
	helperHash := hex.EncodeToString(hash[:])
	allowedHashes := []string{"d82f39c2c000bf4db65ebaa9a3325e724865ed3d9c86e40ee28d30a1e43cbf44"}
	if server.Helper != nil {
		allowedHashes = append(allowedHashes, server.Helper.SHA256)
	}
	response, err = sessionRun(ctx, client, command, map[string]any{"action": "install", "selection": chosen, "helper": base64.StdEncoding.EncodeToString(HelperSource), "sha256": helperHash, "allowed_hashes": allowedHashes})
	if err != nil {
		return result, application.Fault("helper_install_failed", application.ErrUnavailable)
	}
	var installed struct {
		Version string `json:"helper_version"`
		Hash    string `json:"helper_hash"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(response, &installed) != nil {
		return result, ErrUnconfirmed
	}
	if installed.Error != "" {
		return result, prepareError(installed.Error)
	}
	progress("install_helper", "succeeded")
	progress("verify_helper", "running")
	if installed.Hash != helperHash || installed.Version != HelperVersion {
		return result, application.Fault("helper_verify_failed", application.ErrUnavailable)
	}
	result.HelperVersion = installed.Version
	result.HelperHash = installed.Hash
	progress("verify_helper", "succeeded")
	return result, nil
}
func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
func prepareError(code string) error {
	switch code {
	case "sudo_required", "unsupported_os", "docker_missing", "awg_not_found", "awg_unsupported", "discovery_changed", "helper_conflict", "helper_install_failed", "helper_verify_failed":
		return application.Fault(code, application.ErrUnavailable)
	default:
		return errors.New("host operation unconfirmed")
	}
}
