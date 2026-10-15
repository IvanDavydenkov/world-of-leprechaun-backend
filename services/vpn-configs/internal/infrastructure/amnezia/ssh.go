package amnezia

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"leprechaun/vpn-configs/internal/application"
)

var ErrUnconfirmed = errors.New("Amnezia SSH operation unconfirmed")

type Settings struct {
	Address        string // Explicit SSH host:port.
	Username       string
	Password       string
	KnownHostsFile string
	PublicEndpoint string // VPN host:UDP port, not SSH port.
}

type Remote interface {
	Run(context.Context, []byte) ([]byte, error)
}

type Client struct {
	remote   Remote
	endpoint string
}

var _ application.Provisioner = (*Client)(nil)

// NewRemote permits testing the JSON protocol without a live VPN host.
func NewRemote(remote Remote, endpoint string) *Client {
	return &Client{remote: remote, endpoint: endpoint}
}

func New(settings Settings) (*Client, error) {
	if _, _, err := net.SplitHostPort(settings.Address); err != nil {
		return nil, errors.New("VPN_HOST_ADDRESS must be SSH host:port")
	}
	host, port, err := net.SplitHostPort(settings.PublicEndpoint)
	if err != nil || host == "" || port == "" || strings.ContainsAny(settings.PublicEndpoint, "\r\n") {
		return nil, errors.New("VPN_PUBLIC_ENDPOINT must be VPN host:UDP port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("VPN_PUBLIC_ENDPOINT must have a valid UDP port")
	}
	if settings.Username == "" || settings.Password == "" || settings.KnownHostsFile == "" {
		return nil, errors.New("SSH username, password and known_hosts file are required")
	}
	callback, err := knownhosts.New(settings.KnownHostsFile)
	if err != nil {
		return nil, errors.New("cannot read VPN SSH known_hosts")
	}
	remote := &sshRemote{address: settings.Address, config: &ssh.ClientConfig{
		User: settings.Username, Auth: []ssh.AuthMethod{ssh.Password(settings.Password)}, HostKeyCallback: callback,
	}}
	if settings.Username == "root" {
		remote.command = "/usr/local/libexec/leprechaun-awg"
	} else {
		remote.command = "sudo -n /usr/local/libexec/leprechaun-awg"
	}
	return NewRemote(remote, settings.PublicEndpoint), nil
}

type request struct {
	Action     string `json:"action"`
	Generation string `json:"generation"`
	Owner      string `json:"owner,omitempty"`
	Name       string `json:"name,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	RemoteID   string `json:"remote_id,omitempty"`
}

func (c *Client) Create(ctx context.Context, generation, owner, name string) (application.Provisioned, error) {
	if generation == "" || owner == "" || name == "" {
		return application.Provisioned{}, application.ErrInvalid
	}
	data, _ := json.Marshal(request{Action: "create", Generation: generation, Owner: owner, Name: name, Endpoint: c.endpoint})
	output, err := c.remote.Run(ctx, data)
	if err != nil {
		return application.Provisioned{}, ErrUnconfirmed
	}
	var response struct {
		RemoteID string `json:"remote_id"`
		File     string `json:"file"`
	}
	if err = json.Unmarshal(output, &response); err != nil || response.RemoteID == "" || response.File == "" || len(response.File) > 1024*1024 {
		return application.Provisioned{}, ErrUnconfirmed
	}
	return application.Provisioned{RemoteID: response.RemoteID, File: []byte(response.File)}, nil
}

func (c *Client) Revoke(ctx context.Context, generation, remoteID string) error {
	if generation == "" || remoteID == "" {
		return application.ErrInvalid
	}
	data, _ := json.Marshal(request{Action: "revoke", Generation: generation, RemoteID: remoteID})
	output, err := c.remote.Run(ctx, data)
	if err != nil {
		return ErrUnconfirmed
	}
	var response struct {
		Revoked bool `json:"revoked"`
	}
	if json.Unmarshal(output, &response) != nil || !response.Revoked {
		return ErrUnconfirmed
	}
	return nil
}

type sshRemote struct {
	address, command string
	config           *ssh.ClientConfig
}

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if len(data) > b.limit-b.Len() {
		return 0, errors.New("SSH output exceeded limit")
	}
	return b.Buffer.Write(data)
}

func (r *sshRemote) Run(ctx context.Context, input []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", r.address)
	if err != nil {
		return nil, ErrUnconfirmed
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = connection.SetDeadline(deadline); err != nil {
		return nil, ErrUnconfirmed
	}
	conn, channels, requests, err := ssh.NewClientConn(connection, r.address, r.config)
	if err != nil {
		return nil, ErrUnconfirmed
	}
	client := ssh.NewClient(conn, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return nil, ErrUnconfirmed
	}
	defer session.Close()
	output := &boundedBuffer{limit: 2 * 1024 * 1024}
	session.Stdin = bytes.NewReader(input)
	session.Stdout = output
	session.Stderr = io.Discard // Remote stderr can contain private config material.
	if err = session.Run(r.command); err != nil {
		return nil, ErrUnconfirmed
	}
	return output.Bytes(), nil
}
