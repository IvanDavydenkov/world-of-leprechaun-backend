package yandex

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"leprechaun/users/internal/application"
)

var ErrProvider = errors.New("Yandex authentication failed")

type Provider struct {
	clientID, clientSecret, redirectURL string
	client                              *http.Client
	authorizeURL, tokenURL, infoURL     string
}

var _ application.IdentityProvider = (*Provider)(nil)

func New(clientID, clientSecret, redirectURL string) *Provider {
	return &Provider{
		clientID: clientID, clientSecret: clientSecret, redirectURL: redirectURL,
		client:       &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		authorizeURL: "https://oauth.yandex.ru/authorize",
		tokenURL:     "https://oauth.yandex.ru/token",
		infoURL:      "https://login.yandex.ru/info?format=json",
	}
}
func (p *Provider) AuthorizationURL(state, challenge string) string {
	query := url.Values{"response_type": {"code"}, "client_id": {p.clientID}, "redirect_uri": {p.redirectURL},
		"scope": {"login:info"}, "state": {state}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	return p.authorizeURL + "?" + query.Encode()
}

func (p *Provider) ExchangeCode(ctx context.Context, code, verifier string) (application.Identity, error) {
	if code == "" || len(verifier) < 43 || len(verifier) > 128 {
		return application.Identity{}, ErrProvider
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {p.redirectURL}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return application.Identity{}, ErrProvider
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(p.clientID, p.clientSecret)
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err = p.json(ctx, request, &token); err != nil || token.AccessToken == "" {
		return application.Identity{}, ErrProvider
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, p.infoURL, nil)
	if err != nil {
		return application.Identity{}, ErrProvider
	}
	request.Header.Set("Authorization", "OAuth "+token.AccessToken)
	var info struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
		RealName    string `json:"real_name"`
		Login       string `json:"login"`
	}
	if err = p.json(ctx, request, &info); err != nil || info.ID == "" {
		return application.Identity{}, ErrProvider
	}
	name := info.DisplayName
	if name == "" {
		name = info.RealName
	}
	if name == "" {
		name = info.Login
	}
	return application.Identity{Subject: info.ID, DisplayName: name}, nil
}
func (p *Provider) json(_ context.Context, request *http.Request, target any) error {
	response, err := p.client.Do(request)
	if err != nil {
		return ErrProvider
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrProvider
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(content) > 1024*1024 || json.Unmarshal(content, target) != nil {
		return ErrProvider
	}
	return nil
}
