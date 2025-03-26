package main

import (
	"context"
	"time"

	"github.com/Morwran/ebpf-nftrace/internal/app"
	. "github.com/Morwran/ebpf-nftrace/internal/app/nftrace" //nolint:revive
	"github.com/Morwran/ebpf-nftrace/internal/nftrace"
	"github.com/Morwran/ebpf-nftrace/internal/nftrace/printer"
	"github.com/Morwran/ebpf-nftrace/internal/nl"
	iface "github.com/Morwran/ebpf-nftrace/internal/providers/iface-provider"
	"github.com/Morwran/ebpf-nftrace/internal/providers/nfrule-provider"

	"github.com/H-BF/corlib/logger"
	pkgNet "github.com/H-BF/corlib/pkg/net"
	"github.com/H-BF/corlib/pkg/parallel"
	gs "github.com/H-BF/corlib/pkg/patterns/graceful-shutdown"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/H-BF/corlib/server"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func main() {
	SetupContext()
	SetupAgentSubject()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= HELLO =-")
	if err := SetupLogger(LogLevel); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "when setup logger"))
	}

	if err := SetupMetrics(ctx); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup metrics"))
	}

	err := WhenSetupTelemtryServer(ctx, func(srv *server.APIServer) error {
		ep, e := pkgNet.ParseEndpoint(TelemetryEndpoint)
		if e != nil {
			return errors.WithMessagef(e, "parse telemetry endpoint (%s): %v", TelemetryEndpoint, e)
		}
		go func() { //start telemetry endpoint
			if e1 := srv.Run(ctx, ep); e1 != nil {
				logger.Fatalf(ctx, "telemetry server is failed: %v", e1)
			}
		}()
		return nil
	})
	if err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup telemetry server"))
	}

	AgentSubject().ObserversAttach(
		observer.NewObserver(agentMetricsObserver, false,
			nftrace.CountLostSampleEvent{},
			nftrace.CountRcvSampleEvent{},
			nftrace.CountRcvPktEvent{},
			nftrace.CountOverflowQueEvent{},
			iface.CountIfaceNlErrMemEvent{},
			nfrule.CountRulerNlErrMemEvent{},
			nftrace.CountCollectNlErrMemEvent{},
		),
	)

	gracefulDuration := 5 * time.Second
	errc := make(chan error, 1)

	go func() {
		defer close(errc)
		errc <- runJobs(ctx)
	}()
	var jobErr error

	select {
	case <-ctx.Done():
		if gracefulDuration >= time.Second {
			logger.Infof(ctx, "%s in shutdowning...", gracefulDuration)
			_ = gs.ForDuration(gracefulDuration).Run(
				gs.Chan(errc).Consume(
					func(_ context.Context, err error) {
						jobErr = err
					},
				),
			)
		}
	case jobErr = <-errc:
	}

	if jobErr != nil {
		logger.Fatal(ctx, jobErr)
	}

	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}

func agentMetricsObserver(ev observer.EventType) {
	if metrics := GetAgentMetrics(); metrics != nil {
		switch o := ev.(type) {
		case nftrace.CountLostSampleEvent:
			metrics.ObserveCounters(LostTraceCountSrc{Cnt: o.Cnt})
		case nftrace.CountRcvSampleEvent:
			metrics.ObserveCounters(RcvTraceCountSrc{Cnt: o.Cnt})
		case nftrace.CountRcvPktEvent:
			metrics.ObserveCounters(RcvPktCountSrc{Cnt: o.Cnt})
		case nftrace.CountOverflowQueEvent:
			metrics.ObserveCounters(TraceQueOvflCountSrc{Cnt: o.Cnt})
		case iface.CountIfaceNlErrMemEvent:
			metrics.ObserveErrNlMemCounter(ESrcIface)
		case nfrule.CountRulerNlErrMemEvent:
			metrics.ObserveErrNlMemCounter(ESrcRuler)
		case nftrace.CountCollectNlErrMemEvent:
			metrics.ObserveErrNlMemCounter(ESrcCollector)
		}
	}
}

type mainJob struct {
	ifaceProvider iface.IfaceProvider
	nlWatcher     nl.NetlinkWatcher
	ruleProvider  nfrule.RuleProvider
	trCollect     nftrace.TraceCollector
	printer       nftrace.TracePrinter
}

func (m *mainJob) cleanup() {
	if m.ifaceProvider != nil {
		_ = m.ifaceProvider.Close()
	}
	if m.nlWatcher != nil {
		_ = m.nlWatcher.Close()
	}
	if m.ruleProvider != nil {
		_ = m.ruleProvider.Close()
	}
	if m.trCollect != nil {
		_ = m.trCollect.Close()
	}
	if m.printer != nil {
		_ = m.printer.Close()
	}
}

func (m *mainJob) init(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			m.cleanup()
		}
	}()

	as := AgentSubject()

	m.ifaceProvider = iface.NewIfaceProvider(as)

	if m.nlWatcher, err = nl.NewNetlinkWatcher(ctx, 1, unix.NETLINK_NETFILTER,
		nl.WithReadBuffLen(nl.SockBuffLen16MB),
		nl.WithNetlinkGroups(unix.NFNLGRP_NFTABLES),
	); err != nil {
		return err
	}

	m.ruleProvider = nfrule.NewRuleProvider(nfrule.Deps{
		AgentSubject: as,
		NlWatcher:    m.nlWatcher.Reader(0),
	})

	if m.trCollect, err = SetupCollector(ctx, m.ifaceProvider, m.ruleProvider, as); err != nil {
		return err
	}

	var opts []printer.Option

	if JsonFormat {
		opts = append(opts, printer.WithJsonFormat())
	}

	m.printer = nftrace.NewTracePrinter(nftrace.PrinterDeps{
		TraceProvider: m.trCollect,
		Printer:       printer.NewTracePrinter(opts...),
	})

	return nil
}

func (m *mainJob) run(ctx context.Context) error {
	defer m.cleanup()
	ctx1, cancel := context.WithCancel(ctx)
	defer cancel()
	ff := [...]func() error{
		func() error {
			return m.ifaceProvider.Run(ctx1)
		},
		func() error {
			return m.ruleProvider.Run(ctx1)
		},
		func() error {
			return m.trCollect.Run(ctx1)
		},
		func() error {
			return m.printer.Run(ctx1)
		},
	}
	errs := make([]error, len(ff))
	_ = parallel.ExecAbstract(len(ff), int32(len(ff))-1, func(i int) error {
		defer cancel()
		errs[i] = ff[i]()
		return nil
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return multierr.Combine(errs...)
}

func runJobs(ctx context.Context) (err error) {
	var jb mainJob
	if err = jb.init(ctx); err != nil {
		return err
	}

	return jb.run(ctx)
}
