package config

import (
	"fmt"
	"net"
	"os"
)

type Config struct {
	EncryptionKey                           string
	MongoURI, MongoDatabase                 string
	HTTPAddress                             string
	HostAddress, HostUsername, HostPassword string
}

func Load() (Config, error) {
	address := os.Getenv("VPN_CONFIGS_HTTP_ADDR")
	if address == "" {
		address = ":8081"
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return Config{}, fmt.Errorf("invalid VPN_CONFIGS_HTTP_ADDR: %w", err)
	}
	return Config{
		EncryptionKey: os.Getenv("VPN_CONFIG_ENCRYPTION_KEY"),
		MongoURI:      envOrDefault("MONGO_URI", "mongodb://localhost:27017"),
		MongoDatabase: envOrDefault("MONGO_DATABASE", "vpn_configs"),
		HTTPAddress:   address,
		HostAddress:   os.Getenv("VPN_HOST_ADDRESS"), HostUsername: os.Getenv("VPN_HOST_USERNAME"), HostPassword: os.Getenv("VPN_HOST_PASSWORD"),
	}, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
