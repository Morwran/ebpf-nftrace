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

	"github.com/H-BF/corlib/logger"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type trace_info -go-package=nftrace -target amd64 bpf ./ebpf/nftrace.c -- -I./ebpf/

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(errors.WithMessage(err, "failed to remove memory limit for process"))
	}
}

type (
	TraceInfo      bpfTraceInfo
	traceCollector struct {
		objs         bpfObjects
		bufflen      int
		timeInterval uint64
		mode         string
		evRate       uint64
		onceRun      sync.Once
		onceClose    sync.Once
		stop         chan struct{}
		stopped      chan struct{}
	}
)

var (
	memReserveForGC       []byte
	requiredKernelModules = []string{"nf_tables"}
)

const (
	MaxSessions = 200000
	MaxCPUs     = 128
)

func createMapInMap() (*ebpf.Map, error) {
	outerMapSpec := ebpf.MapSpec{
		Name:       "per_cpu_que",
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

	for i := 0; i < runtime.NumCPU(); i++ {
		innerMapSpec := outerMapSpec.InnerMap.Copy()
		innerMap, err := ebpf.NewMap(innerMapSpec)
		if err != nil {
			return nil, errors.WithMessage(err, "inner_map")
		}
		defer innerMap.Close()
		outerMapSpec.Contents[i] = ebpf.MapKV{Key: uint32(i), Value: innerMap}
	}
	return ebpf.NewMap(&outerMapSpec)
}

func NewCollector(sampleRate uint64, ringBuffSize int, timeInterval uint64, mode string, evRate uint64) (*traceCollector, error) {
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

	queMap, err := createMapInMap()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create map in map que")
	}

	loadOpts = &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"per_cpu_que": queMap,
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

	memReserveForGC = make([]byte, 1<<30)

	return &traceCollector{
		objs:         objs,
		bufflen:      ringBuffSize,
		timeInterval: timeInterval,
		mode:         mode,
		evRate:       evRate,
		stop:         make(chan struct{})}, nil
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

	defer func() {
		var (
			key                             = uint32(0)
			pktCntVal, wrWaitVal, rdWaitVal = uint64(0), uint64(0), uint64(0)
		)

		t.objs.PktCounter.Lookup(&key, &pktCntVal)
		t.objs.WrWaitCounter.Lookup(&key, &wrWaitVal)
		t.objs.RdWaitCounter.Lookup(&key, &rdWaitVal)
		log.Infof("pkt count: %d, wr waiting: %d, rd waiting: %d", pktCntVal, wrWaitVal, rdWaitVal)
	}()

	fetchTrace := t.pushTraces
	if t.mode == "pull" {
		fetchTrace = t.pullTraces
	}

	if t.timeInterval > 0 {
		if t.mode == "push" {
			cancel, err := NewPerfEventTimerForAllCPUs(t.objs.SendAgregatedTrace, t.evRate)
			if err != nil {
				return err
			}
			log.Debugf("start perf event timer with rate=%d events per second", t.evRate)
			defer cancel()
		}

		return fetchTrace(ctx, callback)
	}

	return fetchTrace(ctx, callback)
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
	rd, err := newReader(t.objs.Events, t.bufflen)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()
	log.Debug("started in push mode")
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
			if (rcvCnt + lostCnt) > 0 {
				log.Infof("lost samples: %d (%.2f%%), expected samples: %d",
					lostCnt, float64(lostCnt)/float64(rcvCnt+lostCnt)*100, rcvCnt+lostCnt)
			} else {
				log.Infof("lost samples: %d, expected samples: %d",
					lostCnt, rcvCnt+lostCnt)
			}
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

				event = *(*bpfTraceInfo)(unsafe.Pointer(&record.RawSample[0]))
				rcvCnt += event.Counter
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

func (t *traceCollector) pullTraces(ctx context.Context, callback func(event TraceInfo)) (err error) {
	// 	log := logger.FromContext(ctx)
	// 	log.Info("started in pull mode")

	// 	selMap := func() func() int {
	// 		cnt := 1
	// 		return func() int {
	// 			defer func() { cnt++ }()
	// 			return cnt % 2
	// 		}
	// 	}()
	// Loop:
	// 	for err == nil {
	// 		select {
	// 		case <-ctx.Done():
	// 			log.Info("will exit cause ctx canceled")
	// 			err = ctx.Err()
	// 			break Loop
	// 		case <-t.stop:
	// 			log.Info("will exit cause it has closed")
	// 			break Loop
	// 		default:
	// 		}
	// 		key := uint32(0)
	// 		m := t.objs.TraceHolder
	// 		switch v := uint64(selMap()); v {
	// 		case 0:
	// 			m = t.objs.TraceHolder2
	// 			err = t.objs.SelectMap.Put(&key, &v)
	// 		case 1:
	// 			m = t.objs.TraceHolder
	// 			err = t.objs.SelectMap.Put(&key, &v)
	// 		}
	// 		if err != nil {
	// 			err = errors.WithMessage(err, "failed to select map")
	// 			break Loop
	// 		}
	// 		time.Sleep(100 * time.Millisecond)

	// 		err = iterateTrace(m, callback)
	// 	}

	return err
}

func iterateTrace(m *ebpf.Map, fn func(trace TraceInfo)) (err error) {
	cursor := &ebpf.MapBatchCursor{}
	batchSize := 10
	keys := make([]uint32, batchSize)
	values := make([]bpfTraceInfo, batchSize)

	for {
		var n int
		n, err = m.BatchLookupAndDelete(cursor, keys, values, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return errors.WithMessage(err, "failed to lookup")
		}

		if n > 0 {
			for _, perCPUValues := range values[:n] {
				fn(TraceInfo(perCPUValues))
			}
		}

		if errors.Is(err, ebpf.ErrKeyNotExist) {
			err = nil
			break
		}
	}

	return err
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
