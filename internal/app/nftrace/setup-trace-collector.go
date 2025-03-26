package nftrace

import (
	"context"
	"strings"

	"github.com/Morwran/ebpf-nftrace/internal/nftrace"
	"github.com/Morwran/ebpf-nftrace/internal/providers/iface-provider"
	"github.com/Morwran/ebpf-nftrace/internal/providers/nfrule-provider"

	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/pkg/errors"
)

type (
	collectorConstrutor func(context.Context, iface.IfaceProvider, nfrule.RuleProvider, observer.Subject) (nftrace.TraceCollector, error)
)

var collectorConstrutors = map[string]collectorConstrutor{
	"ebpf":    setupEbpfCollector,
	"netlink": setupNetlinkCollector,
}

func SetupCollector(ctx context.Context, ifaceProvider iface.IfaceProvider, ruleProvider nfrule.RuleProvider, subj observer.Subject) (nftrace.TraceCollector, error) {
	collector, ok := collectorConstrutors[strings.ToLower(strings.TrimSpace(CollectorType))]
	if !ok {
		return nil, errors.Errorf("unknown trace collector type '%s'", CollectorType)
	}
	return collector(ctx, ifaceProvider, ruleProvider, subj)
}

func setupNetlinkCollector(ctx context.Context, ifaceProvider iface.IfaceProvider, ruleProvider nfrule.RuleProvider, subj observer.Subject) (nftrace.TraceCollector, error) {
	return nftrace.NewNetlinkCollector(
		nftrace.NetlinkCollectorDeps{
			IfaceProvider: ifaceProvider,
			RuleProvider:  ruleProvider,
			Subj:          subj,
		},
		1<<30,
		UseAggregation,
		5000000,
	)
}

func setupEbpfCollector(ctx context.Context, ifaceProvider iface.IfaceProvider, ruleProvider nfrule.RuleProvider, subj observer.Subject) (nftrace.TraceCollector, error) {
	return nftrace.NewEbpfCollector(
		nftrace.EbpfCollectorDeps{
			IfaceProvider: ifaceProvider,
			RuleProvider:  ruleProvider,
			Subj:          subj,
		},
		SampleRate,
		RingBuffSize,
		UseAggregation,
		EvRate,
		5000000,
	)
}
