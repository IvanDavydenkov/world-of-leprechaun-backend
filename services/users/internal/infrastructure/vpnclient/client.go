package vpnclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"leprechaun/users/internal/application"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	base, token string
	http        *http.Client
}

func New(base, token string) (*Client, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || len(token) < 32 {
		return nil, errors.New("invalid VPN_API_URL or INTERNAL_SERVICE_TOKEN")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost" || parsed.Hostname() == "vpn-configs")) {
		return nil, errors.New("VPN_API_URL requires HTTPS outside the private local network")
	}
	return &Client{base: base, token: token, http: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Forward(ctx context.Context, actor, method, path, key string, body []byte) (application.ConfigResponse, error) {
	if !strings.HasPrefix(path, "/admin/users/") && path != "/me/configs" && !strings.HasPrefix(path, "/me/configs/") {
		return application.ConfigResponse{}, errors.New("invalid VPN route")
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return application.ConfigResponse{}, errors.New("VPN unavailable")
	}
	request.Header.Set("X-Service-Token", c.token)
	request.Header.Set("X-Actor-ID", actor)
	request.Header.Set("Idempotency-Key", key)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return application.ConfigResponse{}, errors.New("VPN unavailable")
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(content) > 1024*1024 {
		return application.ConfigResponse{}, errors.New("invalid VPN response")
	}
	location := response.Header.Get("Location")
	if location != "" && !strings.HasPrefix(location, "/admin/users/") {
		location = ""
	}
	return application.ConfigResponse{Status: response.StatusCode, Body: content, Location: location, ContentType: response.Header.Get("Content-Type"), Disposition: response.Header.Get("Content-Disposition")}, nil
}
