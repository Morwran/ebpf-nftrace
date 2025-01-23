//go:build linux

package nftrace

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/Morwran/ebpf-nftrace/pkg/meta"

	"github.com/H-BF/corlib/logger"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
)

var (
	memReserveForGC       []byte
	requiredKernelModules = []string{"nf_tables"}
)

const (
	MaxSessions = 200000
	MaxCPUs     = 128
)

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(errors.WithMessage(err, "failed to remove memory limit for process"))
	}
	memReserveForGC = make([]byte, 1<<30)
	_ = memReserveForGC
}

type (
	TraceInfo      bpfTraceInfo
	traceCollector struct {
		objs         bpfObjects
		bufflen      int
		timeInterval uint64
		evRate       uint64
		onceRun      sync.Once
		onceClose    sync.Once
		stop         chan struct{}
		stopped      chan struct{}
	}
)

func NewCollector(sampleRate uint64, ringBuffSize int, timeInterval uint64, evRate uint64) (*traceCollector, error) {
	if ringBuffSize < 1 {
		panic(errors.Errorf("Collector/ringBuffSize is %d, but should be > 1", ringBuffSize))
	}
	for _, module := range requiredKernelModules {
		ok, err := isKernelModuleLoaded(module)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to check module '%s'", module)
		}
		if !ok {
			return nil, errors.Errorf("module %s is not loaded. Please load it with 'modprobe %s'", module, module)
		}
	}

	var loadOpts *ebpf.CollectionOptions
	objs := bpfObjects{}

	queMap, err := newPerCpuQueMap(meta.GetFieldTag(&objs.bpfMaps, &objs.PerCpuQue, "ebpf"), runtime.NumCPU())
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create map in map que")
	}

	loadOpts = &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			meta.GetFieldTag(&objs.bpfMaps, &objs.PerCpuQue, "ebpf"): queMap,
		},
	}

	if err := loadBpfObjects(&objs, loadOpts); err != nil {
		return nil, errors.WithMessage(err, "failed to load bpf objects")
	}

	key := uint32(0)
	if err := objs.SampleRate.Put(key, sampleRate); err != nil {
		return nil, errors.WithMessage(err, "failed to update sample_rate map")
	}
	if timeInterval > 0 {
		if err := objs.TimeInterval.Put(key, timeInterval); err != nil {
			return nil, errors.WithMessage(err, "failed to update time interval map")
		}
	}

	return &traceCollector{
		objs:         objs,
		bufflen:      ringBuffSize,
		timeInterval: timeInterval,
		evRate:       evRate,
		stop:         make(chan struct{})}, nil
}

// Run
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

	defer func() {
		var (
			key                                                     = uint32(0)
			pktCntVal, wrWaitVal, rdWaitVal, wrTraceVal, rdTraceVal = uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)
		)

		t.objs.PktCounter.Lookup(&key, &pktCntVal)
		t.objs.WrWaitCounter.Lookup(&key, &wrWaitVal)
		t.objs.RdWaitCounter.Lookup(&key, &rdWaitVal)
		t.objs.WrTraceCounter.Lookup(&key, &wrTraceVal)
		t.objs.RdTraceCounter.Lookup(&key, &rdTraceVal)
		log.Infof("rcv pkt count: %d, wr waiting: %d, rd waiting: %d, wr traces: %d, rd traces: %d",
			pktCntVal, wrWaitVal, rdWaitVal, wrTraceVal, rdTraceVal)
	}()

	if t.timeInterval > 0 {
		cancel, err := NewPerfEventTimerPerCPUs(runtime.NumCPU(), t.objs.SendAgregatedTrace, t.evRate)
		if err != nil {
			return err
		}
		log.Debugf("start perf event timer with rate=%d events per second", t.evRate)
		defer cancel()
	}

	return t.pushTraces(ctx, callback)
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

func (t *traceCollector) pushTraces(ctx context.Context, callback func(event TraceInfo)) error {
	log := logger.FromContext(ctx)
	rd, err := newReader(t.objs.TraceEvents, t.bufflen)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()
	log.Debug("started in push mode")
	log.Infof("created map with entries=%d and buff size=%d", t.objs.TraceEvents.MaxEntries(), rd.BufferSize())

	log.Info("Waiting for events..")
	errCh := make(chan error)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		var (
			event                   bpfTraceInfo
			e                       error
			record                  = newRecord()
			lostCnt, rcvCnt, pktCnt uint64
		)
		defer func() {
			rateLost := float64(0)
			if (rcvCnt + lostCnt) > 0 {
				rateLost = float64(lostCnt) / float64(rcvCnt+lostCnt) * 100
			}
			// trace size is 120 bytes
			log.Infof("lost samples: %d (%.2f%%), expected samples: %d, agregated pkt: %d, traces size: %d",
				lostCnt, rateLost, rcvCnt+lostCnt, pktCnt, 120*rcvCnt)
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
			}
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

			event = *(*bpfTraceInfo)(unsafe.Pointer(&record.RawSample[0]))
			pktCnt += event.Counter
			rcvCnt++
			if callback != nil {
				callback(TraceInfo(event))
			}
		}
		errCh <- e
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

// Helpers

func newPerCpuQueMap(mapName string, nCPU int) (*ebpf.Map, error) {
	outerMapSpec := ebpf.MapSpec{
		Name:       mapName,
		Type:       ebpf.ArrayOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: MaxCPUs,
		Contents:   make([]ebpf.MapKV, runtime.NumCPU()),
		InnerMap: &ebpf.MapSpec{
			Name:       "inner_map",
			Type:       ebpf.Queue,
			KeySize:    0,
			ValueSize:  4,
			MaxEntries: MaxSessions, //uint32((MaxSessions + runtime.NumCPU() - 1) / runtime.NumCPU()),
			//Flags:      unix.BPF_F_INNER_MAP,
		},
	}

	for i := 0; i < nCPU; i++ {
		innerMap, err := ebpf.NewMap(outerMapSpec.InnerMap)
		if err != nil {
			return nil, errors.WithMessage(err, "inner_map")
		}
		defer innerMap.Close()
		k := uint32(i)
		outerMapSpec.Contents[i] = ebpf.MapKV{Key: k, Value: innerMap}
	}
	return ebpf.NewMap(&outerMapSpec)
}

func isKernelModuleLoaded(moduleName string) (bool, error) {
	file, err := os.Open("/proc/modules")
	if err != nil {
		return false, errors.WithMessage(err, "failed to open /proc/modules")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, moduleName+" ") {
			return true, nil
		}
	}

	if err = scanner.Err(); err != nil {
		return false, errors.WithMessage(err, "error reading /proc/modules")
	}

	return false, nil
}
