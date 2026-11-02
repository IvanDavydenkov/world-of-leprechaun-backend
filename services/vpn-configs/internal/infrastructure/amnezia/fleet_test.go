package amnezia

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/crypto/ssh"
	"leprechaun/vpn-configs/internal/application"
	"leprechaun/vpn-configs/internal/domain"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type testDecrypt struct{}

func (testDecrypt) DecryptServerPassword(string, []byte) (string, error) { return "test-password", nil }
func prepareSSHFixture(t *testing.T, ambiguous bool) (domain.VPNServer, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	auth := &atomic.Int32{}
	installs := &atomic.Int32{}
	config := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) { auth.Add(1); return nil, nil }}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			raw, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer raw.Close()
				conn, channels, requests, e := ssh.NewServerConn(raw, config)
				if e != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					ch, req, e := channel.Accept()
					if e != nil {
						return
					}
					go func() {
						defer ch.Close()
						for request := range req {
							if request.Type != "exec" {
								request.Reply(false, nil)
								continue
							}
							request.Reply(true, nil)
							var in map[string]json.RawMessage
							if json.NewDecoder(ch).Decode(&in) != nil {
								return
							}
							var action string
							json.Unmarshal(in["action"], &action)
							var response any
							if action == "discover" {
								candidates := []domain.Candidate{{ID: "one", Container: "amnezia-awg2", Interface: "awg0", Ports: []int{48892}}}
								if ambiguous {
									candidates = append(candidates, domain.Candidate{ID: "two", Container: "amnezia-other", Interface: "awg0", Ports: []int{50000}})
								}
								response = map[string]any{"candidates": candidates}
							} else {
								installs.Add(1)
								hash := sha256.Sum256(HelperSource)
								response = map[string]any{"helper_version": HelperVersion, "helper_hash": hex.EncodeToString(hash[:])}
							}
							json.NewEncoder(ch).Encode(response)
							ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							return
						}
					}()
				}
			}()
		}
	}()
	return domain.VPNServer{ID: "server", SSHAddress: listener.Addr().String(), SSHUsername: "root", SSHHostFingerprint: ssh.FingerprintSHA256(signer.PublicKey()), PublicHost: "vpn.example"}, auth, installs
}
func TestPreparePinsHostBeforePasswordAndInstallsThroughJSON(t *testing.T) {
	server, auth, installs := prepareSSHFixture(t, false)
	host := &FleetHost{Secrets: testDecrypt{}}
	result, err := host.Prepare(context.Background(), server, domain.Selection{}, func(string, string) {})
	if err != nil || result.Endpoint != "vpn.example:48892" || result.HelperVersion != HelperVersion || auth.Load() != 1 || installs.Load() != 1 {
		t.Fatal(result, err)
	}
	server.SSHHostFingerprint = "SHA256:" + strings.Repeat("a", 43)
	_, err = host.Prepare(context.Background(), server, domain.Selection{}, func(string, string) {})
	if application.ErrorCode(err) != "host_key_mismatch" || auth.Load() != 1 {
		t.Fatal("password sent before key verification", err, auth.Load())
	}
}
func TestPrepareAmbiguousDiscoveryNeedsExplicitSelection(t *testing.T) {
	server, _, installs := prepareSSHFixture(t, true)
	host := &FleetHost{Secrets: testDecrypt{}}
	result, err := host.Prepare(context.Background(), server, domain.Selection{}, func(string, string) {})
	if err != nil || result.Discovery == nil || len(result.Discovery.Candidates) != 2 || installs.Load() != 0 {
		t.Fatal(result, err)
	}
	result, err = host.Prepare(context.Background(), server, domain.Selection{CandidateID: "two", UDPPort: 50000}, func(string, string) {})
	if err != nil || result.Container != "amnezia-other" || installs.Load() != 1 {
		t.Fatal(result, err)
	}
}
func TestEmbeddedHelperMatchesDeploymentSource(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "deploy", "amnezia", "leprechaun_awg.py"))
	if err != nil {
		t.Fatal(err)
	}
	if string(source) != string(HelperSource) {
		t.Fatal("embedded helper differs from deployment artifact")
	}
}
