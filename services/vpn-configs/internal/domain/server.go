package domain

import "time"

type VPNServer struct {
	ID                 string         `json:"id" bson:"_id"`
	Name               string         `json:"name"`
	SSHAddress         string         `json:"ssh_address"`
	SSHUsername        string         `json:"ssh_username"`
	PasswordCiphertext []byte         `json:"-" bson:"password_ciphertext"`
	SSHHostKey         string         `json:"ssh_host_key"`
	SSHHostFingerprint string         `json:"ssh_host_fingerprint"`
	PublicHost         string         `json:"public_host"`
	PreparationStatus  string         `json:"preparation_status"`
	PreparedRevision   *int64         `json:"prepared_revision"`
	CheckedAt          *time.Time     `json:"checked_at"`
	Helper             *HelperRelease `json:"helper"`
	LastError          *string        `json:"last_error_code"`
	LastOperation      *string        `json:"last_operation_id"`
	PublicEndpoint     string         `json:"public_endpoint"`
	Container          string         `json:"container"`
	Interface          string         `json:"interface"`
	Revision           int64          `json:"revision"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

type HelperRelease struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}
