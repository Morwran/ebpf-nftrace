package main

import (
	"context"
	"time"

	"github.com/Morwran/ebpf-nftrace/internal/app"
	. "github.com/Morwran/ebpf-nftrace/internal/app/nftrace" //nolint:revive
	"golang.org/x/sys/unix"

	"github.com/H-BF/corlib/logger"
	gs "github.com/H-BF/corlib/pkg/patterns/graceful-shutdown"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func main() {
	SetupContext()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= HELLO =-")
	if err := SetupLogger(zap.DebugLevel); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "when setup logger"))
	}

	gracefulDuration := 5 * time.Second
	errc := make(chan error, 1)

	go func() {
		defer func() {
			close(errc)
		}()
		collector, err := NewCollector(SampleRate)
		if err != nil {
			errc <- err
			return
		}
		defer collector.Close()

		errc <- collector.Run(ctx, func(event TraceInfo) {
			logger.Infof(ctx,
				"id: %d, type: %s, family: %s, tbl name: %s tbl handle: %d, chain name: %s, chain handle: %d, rule handle: %d, verdict: %s, "+
					"jt: %s, nfproto: %d, policy: %s, makr: %d, iif: %d, iif_type: %d, iif_name: %s, oif: %d, oif_type: %d, oif_name: %s,\n",
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

	if jobErr != nil {
		logger.Fatal(ctx, jobErr)
	}

	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}
