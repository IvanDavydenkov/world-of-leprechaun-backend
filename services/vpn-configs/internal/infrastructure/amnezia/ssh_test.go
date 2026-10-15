package amnezia

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type remoteStub struct {
	request  request
	response []byte
	err      error
}

func (r *remoteStub) Run(_ context.Context, data []byte) ([]byte, error) {
	if err := json.Unmarshal(data, &r.request); err != nil {
		return nil, err
	}
	return r.response, r.err
}
func TestCreateSendsDataOverStdinAndReceivesNativeFile(t *testing.T) {
	remote := &remoteStub{response: []byte("{\"remote_id\":\"public-key\",\"file\":\"[Interface]\\nPrivateKey = secret\\n\"}")}
	client := NewRemote(remote, "vpn.example:51820")
	result, err := client.Create(context.Background(), "generation", "owner", "Phone'; touch /tmp/test")
	if err != nil {
		t.Fatal(err)
	}
	if remote.request.Generation != "generation" || remote.request.Endpoint != "vpn.example:51820" || remote.request.Name != "Phone'; touch /tmp/test" {
		t.Fatalf("%+v", remote.request)
	}
	if result.RemoteID != "public-key" || !strings.Contains(string(result.File), "PrivateKey") {
		t.Fatal("file missing")
	}
}
func TestRemoteErrorsDoNotExposePrivateMaterial(t *testing.T) {
	remote := &remoteStub{err: errors.New("PrivateKey = secret")}
	client := NewRemote(remote, "vpn.example:51820")
	if _, err := client.Create(context.Background(), "gen", "owner", "Phone"); !errors.Is(err, ErrUnconfirmed) || strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
	if err := client.Revoke(context.Background(), "gen", "peer"); !errors.Is(err, ErrUnconfirmed) {
		t.Fatal(err)
	}
}
func TestRevocationRequiresExplicitConfirmation(t *testing.T) {
	remote := &remoteStub{response: []byte("{\"revoked\":false}")}
	client := NewRemote(remote, "vpn.example:51820")
	if err := client.Revoke(context.Background(), "gen", "peer"); !errors.Is(err, ErrUnconfirmed) {
		t.Fatal(err)
	}
	remote.response = []byte("{\"revoked\":true}")
	if err := client.Revoke(context.Background(), "gen", "peer"); err != nil {
		t.Fatal(err)
	}
}
func TestOutputIsBounded(t *testing.T) {
	b := &boundedBuffer{limit: 4}
	if _, err := b.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("5")); err == nil {
		t.Fatal("unbounded output")
	}
}
func TestSSHConfigurationFailsClosed(t *testing.T) {
	if _, err := New(Settings{Address: "vpn.example:22", Username: "root", Password: "secret", PublicEndpoint: "vpn.example:51820", KnownHostsFile: "missing-file"}); err == nil {
		t.Fatal("missing host verification accepted")
	}
}
