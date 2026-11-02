package application

import (
	"context"
	"errors"
	"leprechaun/vpn-configs/internal/domain"
)

type FleetStore interface {
	LoadFleet(context.Context) (domain.FleetControl, error)
	SaveFleet(context.Context, domain.FleetControl, int64) (bool, error)
}
type AccountCatalog interface {
	StateStore
	OwnersAfter(context.Context, string, int64) ([]string, error)
}
type Coordinator interface {
	With(context.Context, func(context.Context) error) error
}
type Prepared struct {
	HostKey, Fingerprint, Endpoint, Container, Interface, HelperVersion, HelperHash string
	Discovery                                                                       *domain.Discovery
}
type FleetHost interface {
	Prepare(context.Context, domain.VPNServer, domain.Selection, func(string, string)) (Prepared, error)
	ForServer(context.Context, domain.VPNServer) (Provisioner, error)
	Verify(context.Context, domain.VPNServer, string, string) error
}
type CodeError struct {
	Code  string
	Cause error
}

func (e *CodeError) Error() string         { return e.Code }
func (e *CodeError) Unwrap() error         { return e.Cause }
func Fault(code string, cause error) error { return &CodeError{code, cause} }
func ErrorCode(err error) string {
	var coded *CodeError
	if errors.As(err, &coded) {
		return coded.Code
	}
	if errors.Is(err, ErrNotFound) {
		return "not_found"
	}
	if errors.Is(err, ErrConflict) {
		return "revision_conflict"
	}
	if errors.Is(err, ErrInvalid) {
		return "invalid_request"
	}
	if errors.Is(err, ErrForbidden) {
		return "admin_required"
	}
	return "host_operation_unconfirmed"
}
