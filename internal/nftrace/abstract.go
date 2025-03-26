package nftrace

import (
	"context"

	model "github.com/Morwran/ebpf-nftrace/internal/models"
	rl "github.com/Morwran/ebpf-nftrace/internal/providers/nfrule-provider"
)

const (
	MaxConnectionsPerSec = 200000
	MaxCPUs              = 128
)

type (
	// TraceCollector - common interface to collect traces
	TraceCollector interface {
		Run(ctx context.Context) error
		Reader() <-chan model.Trace
		Close() error
	}

	TracePrinter interface {
		Run(ctx context.Context) error
		Close() error
	}

	ifaceProvider interface {
		GetIface(index int) (string, error)
	}

	ruleProvider interface {
		GetRuleForTrace(tr rl.TraceRuleDescriptor) (rl.RuleEntry, error)
	}
)
