//go:build linux

package nftrace

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"

	"github.com/H-BF/corlib/logger"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type trace_info -go-package=nftrace -target amd64 bpf ./ebpf/nftrace.c -- -I./ebpf/

type (
	TraceInfo      bpfTraceInfo
	traceCollector struct {
		objs       bpfObjects
		sampleRate uint64
		onceRun    sync.Once
		onceClose  sync.Once
		stop       chan struct{}
		stopped    chan struct{}
	}
)

func NewCollector(sampleRate uint64) (*traceCollector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	objs := bpfObjects{}
	err := loadBpfObjects(&objs, nil)

	return &traceCollector{objs: objs, sampleRate: sampleRate, stop: make(chan struct{})}, err
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

	fn := "nft_trace_notify"
	key := uint32(0)
	if err := t.objs.SampleRate.Put(key, t.sampleRate); err != nil {
		return errors.WithMessage(err, "failed to update sample_rate map")
	}

	var checkValue uint64
	if err := t.objs.SampleRate.Lookup(key, &checkValue); err != nil {
		return errors.WithMessage(err, "failed to read from sample_rate map")
	}
	log := logger.FromContext(ctx).Named("trace-collector")
	log.Infof("sample_rate map initialized with value: %d", checkValue)

	kp, err := link.Kprobe(fn, t.objs.KprobeNftTraceNotify, nil)
	if err != nil {
		return errors.WithMessage(err, "opening kprobe")
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(t.objs.Events)
	//	rd, err = perf.NewReader(objs.PerfTraceEvt, 1)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	log.Info("Waiting for events..")

	var event bpfTraceInfo
	for {
		select {
		case <-ctx.Done():
			log.Info("will exit cause ctx canceled")
			return ctx.Err()
		case <-t.stop:
			log.Info("will exit cause it has closed")
			return nil
		default:
			record, err := rd.Read()
			if err != nil {
				return errors.WithMessage(err, "reading trace from reader")
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				return errors.WithMessage(err, "parsing trace event")
			}
			if callback != nil {
				callback(TraceInfo(event))
			}
		}
	}
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
