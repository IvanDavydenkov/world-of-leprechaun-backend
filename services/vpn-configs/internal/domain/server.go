package domain

import "time"

type VPNServer struct {
	ID                 string    `json:"id" bson:"_id"`
	Name               string    `json:"name"`
	SSHAddress         string    `json:"ssh_address"`
	SSHUsername        string    `json:"ssh_username"`
	PasswordCiphertext []byte    `json:"-" bson:"password_ciphertext"`
	SSHHostKey         string    `json:"ssh_host_key"`
	PublicEndpoint     string    `json:"public_endpoint"`
	Container          string    `json:"container"`
	Interface          string    `json:"interface"`
	Revision           int64     `json:"revision"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}
