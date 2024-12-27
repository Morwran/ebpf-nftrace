//go:build linux

package nftrace

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"sync"
	"time"

	"github.com/H-BF/corlib/logger"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type trace_info -go-package=nftrace -target amd64 bpf ./ebpf/nftrace.c -- -I./ebpf/

type (
	TraceInfo      bpfTraceInfo
	traceCollector struct {
		objs      bpfObjects
		bufflen   int
		onceRun   sync.Once
		onceClose sync.Once
		stop      chan struct{}
		stopped   chan struct{}
	}
)

func NewCollector(sampleRate uint64, ringBuffSize int) (*traceCollector, error) {
	if ringBuffSize < 1 {
		panic(errors.Errorf("Collector/ringBuffSize is %d, but should be > 1", ringBuffSize))
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, errors.WithMessage(err, "failed to load bpf objects")
	}

	key := uint32(0)
	if err := objs.SampleRate.Put(key, sampleRate); err != nil {
		return nil, errors.WithMessage(err, "failed to update sample_rate map")
	}

	return &traceCollector{objs: objs, bufflen: ringBuffSize, stop: make(chan struct{})}, nil
}

func (t *traceCollector) Run(ctx context.Context, callback func(event TraceInfo)) error {
	var doRun bool

	t.onceRun.Do(func() {
		doRun = true
		t.stopped = make(chan struct{})
	})
	if !doRun {
		return errors.New("it has been run or closed yet")
	}

	const fn = "nft_trace_notify"

	log := logger.FromContext(ctx).Named("trace-collector")

	defer func() {
		log.Info("stop")
		close(t.stopped)
	}()

	kp, err := link.Kprobe(fn, t.objs.KprobeNftTraceNotify, nil)
	if err != nil {
		return errors.WithMessage(err, "opening kprobe")
	}
	defer kp.Close()

	rd, err := newReader(t.objs.Events, t.bufflen)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()
	log.Infof("created map with entries=%d and buff size=%d", t.objs.Events.MaxEntries(), rd.BufferSize())

	log.Info("Waiting for events..")
	errCh := make(chan error)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		var (
			event           bpfTraceInfo
			e               error
			record          = newRecord()
			lostCnt, rcvCnt uint64
		)
		defer func() {
			log.Infof("lost samples: %d (%.2f%%), expected samples: %d",
				lostCnt, float64(lostCnt)/float64(rcvCnt+lostCnt)*100, rcvCnt+lostCnt)
			close(errCh)
			wg.Done()
		}()

	Loop:
		for e == nil {
			select {
			case <-ctx.Done():
				return
			case <-t.stop:
				return
			default:
				rd.SetDeadline(time.Now().Add(time.Second))
				err := rd.ReadInto(record)
				if err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						continue
					}
					e = errors.WithMessage(err, "reading trace from reader")
					goto Loop
				}
				lostCnt += getLostSamples(record)
				if len(record.RawSample) == 0 {
					log.Debug("Empty RawSample received")
					continue
				}
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
					e = errors.WithMessage(err, "parsing trace event")
					goto Loop
				}
				rcvCnt++
				if callback != nil {
					callback(TraceInfo(event))
				}
			}
		}
		if e != nil {
			errCh <- e
		}
	}()
	var jobErr error
	select {
	case <-ctx.Done():
		log.Info("will exit cause ctx canceled")
		jobErr = ctx.Err()
	case <-t.stop:
		log.Info("will exit cause it has closed")

	case jobErr = <-errCh:
	}

	wg.Wait()

	return jobErr
}

// Close
func (t *traceCollector) Close() error {
	t.onceClose.Do(func() {
		close(t.stop)
		t.onceRun.Do(func() {})
		if t.stopped != nil {
			<-t.stopped
		}
		t.objs.Close()
	})
	return nil
}
