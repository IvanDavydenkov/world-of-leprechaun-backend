package domain

import "time"

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

type User struct {
	ID          string
	YandexID    string
	DisplayName string
	Role        Role
	CreatedAt   time.Time
}
