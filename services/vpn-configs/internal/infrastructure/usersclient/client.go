package usersclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"leprechaun/vpn-configs/internal/application"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	base, token string
	http        *http.Client
}

func New(base, token string) (*Client, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || len(token) < 32 {
		return nil, errors.New("invalid USERS_API_URL or INTERNAL_SERVICE_TOKEN")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost" || parsed.Hostname() == "users")) {
		return nil, errors.New("USERS_API_URL requires HTTPS outside private local network")
	}
	return &Client{base: base, token: token, http: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) resolve(ctx context.Context, id string) (string, error) {
	if !application.ValidID(id) {
		return "", application.ErrNotFound
	}
	request, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/internal/users/"+url.PathEscape(id), nil)
	request.Header.Set("X-Service-Token", c.token)
	response, err := c.http.Do(request)
	if err != nil {
		return "", errors.New("identity service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == 404 || response.StatusCode == 401 {
		return "", application.ErrNotFound
	}
	if response.StatusCode != 200 {
		return "", errors.New("identity service unavailable")
	}
	var user struct {
		ID   string `json:"id"`
		Role string `json:"role"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&user) != nil || user.ID != id {
		return "", errors.New("invalid identity response")
	}
	return user.Role, nil
}
func (c *Client) RequireAdmin(ctx context.Context, id string) error {
	role, err := c.resolve(ctx, id)
	if err != nil {
		return err
	}
	if role != "admin" {
		return application.ErrForbidden
	}
	return nil
}
func (c *Client) RequireUser(ctx context.Context, id string) error {
	_, err := c.resolve(ctx, id)
	return err
}
