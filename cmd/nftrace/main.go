package main

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/Morwran/ebpf-nftrace/internal/app"
	. "github.com/Morwran/ebpf-nftrace/internal/app/nftrace" //nolint:revive

	"github.com/H-BF/corlib/logger"
	pkgNet "github.com/H-BF/corlib/pkg/net"
	gs "github.com/H-BF/corlib/pkg/patterns/graceful-shutdown"
	"github.com/H-BF/corlib/server"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func main() {
	SetupContext()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= HELLO =-")
	if err := SetupLogger(LogLevel); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "when setup logger"))
	}

	if err := SetupMetrics(ctx); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup metrics"))
	}

	if metrics := GetAgentMetrics(); metrics != nil {
		go metrics.MonitorGC()
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

	gracefulDuration := 5 * time.Second
	errc := make(chan error, 1)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer func() {
			close(errc)
			wg.Done()
		}()
		collector, err := NewCollector(SampleRate, RingBuffSize, TimeInterval, EvRate)
		if err != nil {
			errc <- err
			return
		}
		defer collector.Close()

		cnt := uint64(0)
		i := uint64(0)
		defer func() {
			logger.Infof(ctx, "counted traces: %d", cnt)
		}()

		errc <- collector.Run(ctx, func(event TraceInfo) {
			cnt += event.Counter
			i++
			logger.Debugf(ctx,
				"i: %d, sum: %d, id: %d, type: %s, family: %s, tbl name: %s tbl handle: %d, chain name: %s, chain handle: %d, rule handle: %d, verdict: %s, "+
					"jt: %s, nfproto: %d, policy: %s, makr: %d, iif: %d, iif_type: %d, iif_name: %s, oif: %d, oif_type: %d, oif_name: %s, "+
					"src=%s:%d, dst=%s:%d, proto=%s, mac-src: %s, mac-dst: %s, len=%d, counter=%d, ts=%d ns\n",
				i,
				cnt,
				event.Id,
				TraceType(event.Type),
				FamilyTable(event.Family),
				unix.ByteSliceToString(event.TableName[:]),
				event.TableHandle,
				unix.ByteSliceToString(event.ChainName[:]),
				event.ChainHandle,
				event.RuleHandle,
				Verdict(event.Verdict),
				unix.ByteSliceToString(event.JumpTarget[:]),
				event.Nfproto,
				Verdict(event.Policy),
				event.Mark,
				event.Iif,
				event.IifType,
				unix.ByteSliceToString(event.IifName[:]),
				event.Oif,
				event.OifType,
				unix.ByteSliceToString(event.OifName[:]),
				Ip2String(event.Family == unix.NFPROTO_IPV6, event.SrcIp, event.SrcIp6.In6U.U6Addr8[:]),
				event.SrcPort,
				Ip2String(event.Family == unix.NFPROTO_IPV6, event.DstIp, event.DstIp6.In6U.U6Addr8[:]),
				event.DstPort,
				IpProto(event.IpProto),
				net.HardwareAddr(event.SrcMac[:]),
				net.HardwareAddr(event.DstMac[:]),
				event.Len,
				event.Counter,
				event.Time,
			)
		})
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
	wg.Wait()
	if jobErr != nil {
		logger.Fatal(ctx, jobErr)
	}

	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}
