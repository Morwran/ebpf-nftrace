package nftrace

import (
	"context"
	"sync"

	model "github.com/Morwran/ebpf-nftrace/internal/models"

	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
)

type (
	traceReader interface {
		Reader() <-chan model.Trace
	}
	tracePrinter interface {
		Print(...model.Trace)
	}
	PrinterDeps struct {
		// Adapters
		TraceProvider traceReader
		Printer       tracePrinter
	}
	tracePrinterImpl struct {
		PrinterDeps
		onceRun   sync.Once
		onceClose sync.Once
		stop      chan struct{}
		stopped   chan struct{}
	}
)

func NewTracePrinter(d PrinterDeps) *tracePrinterImpl {
	return &tracePrinterImpl{
		PrinterDeps: d,
		stop:        make(chan struct{}),
	}
}

func (t *tracePrinterImpl) Run(ctx context.Context) (err error) {
	var doRun bool
	t.onceRun.Do(func() {
		doRun = true
		t.stopped = make(chan struct{})
	})
	if !doRun {
		return ErrPrint{Err: errors.New("it has been run or closed yet")}
	}
	log := logger.FromContext(ctx).Named("trace-printer")
	log.Info("start")
	defer func() {
		close(t.stopped)
		log.Info("stop")
	}()
Loop:
	for que := t.TraceProvider.Reader(); err == nil; {
		select {
		case <-ctx.Done():
			log.Info("will exit cause ctx canceled")
			err = ctx.Err()
		case <-t.stop:
			log.Info("will exit cause it has closed")
			return nil
		case trace, ok := <-que:
			if !ok {
				log.Info("failed to read trace from queue")
				err = ErrPrint{Err: errors.New("failed to read trace from queue")}
				goto Loop
			}
			t.Printer.Print(trace)
		}
	}
	return err
}

// Close printer
func (t *tracePrinterImpl) Close() error {
	t.onceClose.Do(func() {
		close(t.stop)
		t.onceRun.Do(func() {})
		if t.stopped != nil {
			<-t.stopped
		}
	})
	return nil
}
