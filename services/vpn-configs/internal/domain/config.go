package domain

import "time"

// Config contains metadata only. VPN credentials and private keys are not stored here.
type Config struct {
	ID         string
	OwnerID    string
	RemoteID   string
	Name       string
	CreatedAt  time.Time
	Generation string
}
