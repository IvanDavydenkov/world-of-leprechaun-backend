package http

import (
	"context"
	"encoding/json"
	"leprechaun/users/internal/application"
	"leprechaun/users/internal/domain"
	"net/http"
)

func (a *Auth) configSummaries(ctx context.Context, actor string, users []domain.User) map[string]application.ConfigSummary {
	if a.configGateway == nil || len(users) == 0 {
		return nil
	}
	ids := make([]string, 0, len(users))
	for _, user := range users {
		ids = append(ids, user.ID)
	}
	body, _ := json.Marshal(struct {
		UserIDs []string `json:"user_ids"`
	}{ids})
	response, err := a.configGateway.Forward(ctx, actor, http.MethodPost, "/admin/users/config-summaries", "", body)
	if err != nil || response.Status != http.StatusOK {
		return nil
	}
	var result map[string]application.ConfigSummary
	if json.Unmarshal(response.Body, &result) != nil {
		return nil
	}
	return result
}
