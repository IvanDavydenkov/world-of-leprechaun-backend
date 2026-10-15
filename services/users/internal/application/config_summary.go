package application

type ConfigCounts struct {
	Total    int `json:"total"`
	Active   int `json:"active"`
	Disabled int `json:"disabled"`
	Pending  int `json:"pending"`
}
type ConfigMetadata struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Version int    `json:"version"`
}
type TrafficSummary struct {
	Upload        *uint64 `json:"upload_bytes"`
	Download      *uint64 `json:"download_bytes"`
	Total         *uint64 `json:"total_bytes"`
	Freshness     string  `json:"freshness"`
	Coverage      string  `json:"coverage"`
	ObservedSince *string `json:"observed_since"`
	UpdatedAt     *string `json:"updated_at"`
}
type ConfigSummary struct {
	Availability string           `json:"availability"`
	Counts       *ConfigCounts    `json:"counts"`
	Configs      []ConfigMetadata `json:"configs"`
	Traffic      *TrafficSummary  `json:"traffic"`
}
