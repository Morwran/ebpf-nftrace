package nftrace

import (
	"context"
	"fmt"
	"sync"

	model "github.com/Morwran/ebpf-nftrace/internal/models"
	queue "github.com/Morwran/ebpf-nftrace/internal/nftrace/trace-que"
	"github.com/Morwran/ebpf-nftrace/internal/nl"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// netlinkTraceCollector - implementation of the TraceCollector interface
type (
	NetlinkCollectorDeps struct {
		IfaceProvider ifaceProvider
		RuleProvider  ruleProvider
		Subj          observer.Subject
	}
	netlinkTraceCollector struct {
		NetlinkCollectorDeps
		que          queue.CachedQueFace
		nlRcvBuffLen int
		aggregate    bool
		onceRun      sync.Once
		onceClose    sync.Once
		stop         chan struct{}
		stopped      chan struct{}
	}
)

var _ TraceCollector = (*netlinkTraceCollector)(nil)

func NewNetlinkCollector(d NetlinkCollectorDeps, nlBuffLen int, useAggregation bool, queSize int) (TraceCollector, error) {
	if nlBuffLen < nl.SockBuffLen16MB {
		panic(
			fmt.Errorf("'TraceCollector/nlBuffLen' is %d bytes less than %d bytes", nlBuffLen, nl.SockBuffLen16MB),
		)
	}
	if queSize <= 0 {
		panic(
			fmt.Errorf("'TraceCollector/queSize' must be > 0"),
		)
	}
	cl := &netlinkTraceCollector{
		NetlinkCollectorDeps: d,
		que:                  queue.NewCachedQue(queSize),
		nlRcvBuffLen:         nlBuffLen,
		aggregate:            useAggregation,
		stop:                 make(chan struct{}),
	}

	return cl, nil
}

// Run
func (c *netlinkTraceCollector) Run(ctx context.Context) (err error) {
	var doRun bool
	c.onceRun.Do(func() {
		doRun = true
		c.stopped = make(chan struct{})
	})
	if !doRun {
		return ErrCollect{Err: errors.New("it has been run or closed yet")}
	}

	nlWatcher, err := nl.NewNetlinkWatcher(ctx, 1, unix.NETLINK_NETFILTER,
		nl.WithReadBuffLen(c.nlRcvBuffLen),
		nl.WithNetlinkGroups(unix.NFNLGRP_NFTRACE),
	)

	if err != nil {
		return ErrCollect{Err: fmt.Errorf("failed to create trace-watcher: %v", err)}
	}

	log := logger.FromContext(ctx).Named("netlink-trace-collector")
	log.Infof("start with options: rcv-buffer-size=%d, use-aggregation=%v",
		c.nlRcvBuffLen, c.aggregate)

	defer func() {
		log.Info("stop")
		_ = nlWatcher.Close()
		close(c.stopped)
	}()
	reader := nlWatcher.Reader(0)

	tg := NewTraceGroup(c.IfaceProvider, c.RuleProvider)
	defer tg.Close()

	for {
		select {
		case <-ctx.Done():
			log.Info("will exit cause ctx canceled")
			return ctx.Err()
		case <-c.stop:
			log.Info("will exit cause it has closed")
			return nil
		case nlData, ok := <-reader.Read():
			if !ok {
				log.Info("will exit cause trace watcher has already closed")
				return ErrCollect{Err: errors.New("trace watcher has already closed")}
			}
			err = nlData.Err
			messages := nlData.Messages

			if err != nil {
				if errors.Is(err, nl.ErrNlMem) {
					c.Subj.Notify(CountCollectNlErrMemEvent{})
					continue
				}
				if errors.Is(err, nl.ErrNlDataNotReady) ||
					errors.Is(err, nl.ErrNlReadInterrupted) {
					continue
				}

				return ErrCollect{Err: errors.WithMessage(err, "failed to rcv nl message")}
			}

			for _, msg := range messages {
				var tr NetlinkTrace
				if err = tr.InitFromMsg(msg); err != nil {
					return err
				}
				if err = tg.AddTrace(tr.ToNftTrace()); err != nil {
					return err
				}
				if !tg.GroupReady() {
					continue
				}
				m, err := tg.ToModel()
				if err != nil {
					return errors.WithMessage(err, "failed to convert obtained trace into model")
				}
				tg.Reset()

				if !c.aggregate {
					err = c.que.Enque(m)
				} else {
					err = c.que.Upsert(m.Hash(), m)
				}
				if errors.Is(err, queue.ErrQueIsFull) {
					c.Subj.Notify(CountOverflowQueEvent{Cnt: 1})
					err = nil
				}
				if err != nil {
					return err
				}
				c.Subj.Notify(CountRcvSampleEvent{Cnt: 1})
			}
		}
	}
}

// Reader
func (c *netlinkTraceCollector) Reader() <-chan model.Trace {
	return c.que.Reader()
}

// Close collector
func (c *netlinkTraceCollector) Close() (err error) {
	c.onceClose.Do(func() {
		close(c.stop)
		c.onceRun.Do(func() {})
		if c.stopped != nil {
			<-c.stopped
		}
		err = c.que.Close()
	})
	return err
}
