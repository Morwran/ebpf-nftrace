package nftrace

import (
	"errors"
	"fmt"
)

// ErrCollect -
type (
	ErrCollect struct {
		Err error
	}
	ErrPrint struct {
		Err error
	}
)

// Error -
func (e ErrCollect) Error() string {
	return fmt.Sprintf("Collector: %v", e.Err)
}

// Cause -
func (e ErrCollect) Cause() error {
	return e.Err
}

// Error -
func (e ErrPrint) Error() string {
	return fmt.Sprintf("Sender: %v", e.Err)
}

// Cause -
func (e ErrPrint) Cause() error {
	return e.Err
}

// Error messages
var (
	ErrTraceDataNotReady = errors.New("trace not ready")
	ErrTraceTypeUnknown  = errors.New("unknown trace type")
	ErrTraceGroupEmpty   = errors.New("trace group is empty")
	ErrTraceEmpty        = errors.New("empty trace")
)
