package domain

import "time"

type Issuance struct {
	ServerID, Generation, RemoteID, State string
	CreatedAt                             time.Time
}
type Routing struct {
	DefaultServerID string  `json:"default_server_id"`
	Revision        int64   `json:"revision"`
	ActiveSwitchID  *string `json:"active_switch_operation_id"`
}
type FleetStep struct {
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	ErrorCode *string `json:"error_code"`
}
type FleetCounts struct {
	Requested int `json:"requested_count"`
	Succeeded int `json:"succeeded_count"`
	Failed    int `json:"failed_count"`
	Pending   int `json:"pending_count"`
	Skipped   int `json:"skipped_count"`
}
type Candidate struct {
	ID        string `json:"candidate_id"`
	Container string `json:"container"`
	Interface string `json:"interface"`
	Ports     []int  `json:"published_udp_ports"`
}
type Discovery struct {
	Candidates []Candidate `json:"candidates"`
	Required   []string    `json:"required_fields"`
}
type Selection struct {
	CandidateID string `json:"candidate_id"`
	UDPPort     int    `json:"udp_port"`
	PublicHost  string `json:"public_host,omitempty"`
}
type FleetItem struct {
	GenerationIDs []string `json:"-"`
	ID            string   `json:"item_id"`
	ConfigID      string   `json:"config_id"`
	OwnerID       string   `json:"user_id"`
	Source        *string  `json:"source_server_id"`
	Target        *string  `json:"target_server_id"`
	Status        string   `json:"status"`
	Action        *string  `json:"action"`
	Error         *string  `json:"error_code"`
	Attempts      int      `json:"attempts"`
}
type FleetOperation struct {
	ID                             string         `json:"operation_id"`
	Kind                           string         `json:"kind"`
	Status                         string         `json:"status"`
	Phase                          string         `json:"phase"`
	Target                         *string        `json:"target_server_id"`
	Server                         *string        `json:"server_id"`
	RoutingRevision                *int64         `json:"routing_revision"`
	Counts                         *FleetCounts   `json:"counts"`
	Steps                          []FleetStep    `json:"steps"`
	Details                        *Discovery     `json:"details"`
	Error                          *string        `json:"error_code"`
	Retryable                      bool           `json:"retryable"`
	CreatedAt                      time.Time      `json:"created_at"`
	UpdatedAt                      time.Time      `json:"updated_at"`
	Actor, Key, Fingerprint, Scope string         `json:"-"`
	ExpectedRevision               int64          `json:"-"`
	Selection                      Selection      `json:"-"`
	Items                          []FleetItem    `json:"-"`
	Commands                       []FleetCommand `json:"-"`
}
type FleetCommand struct{ Actor, Key, Route, Fingerprint string }
type FleetControl struct {
	Revision    int64
	SchemaReady bool
	Routing     Routing
	Operations  []FleetOperation
}
