package application

import "context"

type ConfigResponse struct {
	Status      int
	Body        []byte
	Location    string
	ContentType string
	Disposition string
}
type ConfigGateway interface {
	Forward(context.Context, string, string, string, string, []byte) (ConfigResponse, error)
}
