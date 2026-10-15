package config

import (
	"fmt"
	"net"
	"os"
)

type Config struct {
	InternalToken                                         string
	PeerAPIURL                                            string
	FrontendOrigin                                        string
	AdminYandexID                                         string
	MongoURI, MongoDatabase                               string
	HTTPAddress                                           string
	YandexClientID, YandexClientSecret, YandexRedirectURL string
}

func Load() (Config, error) {
	address := os.Getenv("USERS_HTTP_ADDR")
	if address == "" {
		address = ":8080"
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return Config{}, fmt.Errorf("invalid USERS_HTTP_ADDR: %w", err)
	}
	return Config{
		InternalToken:  os.Getenv("INTERNAL_SERVICE_TOKEN"),
		PeerAPIURL:     envOrDefault("VPN_API_URL", "http://127.0.0.1:8081"),
		FrontendOrigin: os.Getenv("FRONTEND_ORIGIN"),
		AdminYandexID:  os.Getenv("ADMIN_YANDEX_ID"),
		MongoURI:       envOrDefault("MONGO_URI", "mongodb://localhost:27017"),
		MongoDatabase:  envOrDefault("MONGO_DATABASE", "users"),
		HTTPAddress:    address,
		YandexClientID: os.Getenv("YANDEX_CLIENT_ID"), YandexClientSecret: os.Getenv("YANDEX_CLIENT_SECRET"), YandexRedirectURL: os.Getenv("YANDEX_REDIRECT_URL"),
	}, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
