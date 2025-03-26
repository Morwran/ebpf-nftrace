//go:build linux

package nftrace

import (
	"context"
	"encoding/binary"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/Morwran/ebpf-nftrace/internal/meta"
	model "github.com/Morwran/ebpf-nftrace/internal/models"
	queue "github.com/Morwran/ebpf-nftrace/internal/nftrace/trace-que"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

var (
	onceLock                sync.Once
	memLockForGC            []byte
	requiredKernelModules   = []string{"nf_tables"}
	minKernelVersionSupport = KernelVersion{5, 8, 0}
	kernelModulesFile       = "/proc/modules"
)

type (
	EbpfCollectorDeps struct {
		IfaceProvider ifaceProvider
		RuleProvider  ruleProvider
		Subj          observer.Subject
	}

	ebpfTraceCollector struct {
		EbpfCollectorDeps
		objs           bpfObjects
		bufflen        int
		useAggregation bool
		useSampling    bool
		evRate         uint64
		que            queue.CachedQueFace
		onceRun        sync.Once
		onceClose      sync.Once
		stop           chan struct{}
		stopped        chan struct{}
	}
)

var _ TraceCollector = (*ebpfTraceCollector)(nil)

func NewEbpfCollector(d EbpfCollectorDeps, sampleRate uint64, ringBuffSize int, useAggregation bool, evRate uint64, queSize int) (TraceCollector, error) {
	if ringBuffSize < 1 {
		panic(errors.Errorf("Collector/ringBuffSize is %d, but should be > 1", ringBuffSize))
	}
	if queSize <= 0 {
		panic(
			errors.Errorf("'TraceCollector/queSize' must be > 0"),
		)
	}
	if err := checkKernelVersion(minKernelVersionSupport); err != nil {
		return nil, errors.WithMessage(err, "failed to check kernel version")
	}
	if err := checkBTFKernelSupport(); err != nil {
		return nil, errors.WithMessage(err, "failed to check BTF support")
	}
	if err := checkKernelModules(requiredKernelModules...); err != nil {
		return nil, errors.WithMessage(err, "failed to check kernel modules")
	}

	if err := ensureMemlock(); err != nil {
		return nil, errors.WithMessage(err, "failed to lock memory for process")
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
		Programs: ebpf.ProgramOptions{
			LogLevel: (ebpf.LogLevelStats | ebpf.LogLevelInstruction | ebpf.LogLevelBranch),
		},
	}

	if err = loadBpfObjects(&objs, loadOpts); err != nil {
		return nil, errors.WithMessage(err, "failed to load bpf objects")
	}

	key := uint32(0)
	if err = objs.SampleRate.Put(key, sampleRate); err != nil {
		return nil, errors.WithMessage(err, "failed to update sample_rate map")
	}
	if useAggregation {
		if err = objs.UseAggregation.Put(key, uint64(1)); err != nil {
			return nil, errors.WithMessage(err, "failed to update aggregation value in ebpf map")
		}
	}

	return &ebpfTraceCollector{
		EbpfCollectorDeps: d,
		objs:              objs,
		bufflen:           ringBuffSize,
		useAggregation:    useAggregation,
		useSampling:       sampleRate > 0,
		evRate:            evRate,
		que:               queue.NewCachedQue(queSize),
		stop:              make(chan struct{}),
	}, nil
}

// Run -
func (t *ebpfTraceCollector) Run(ctx context.Context) error {
	var doRun bool

	t.onceRun.Do(func() {
		doRun = true
		t.stopped = make(chan struct{})
	})
	if !doRun {
		return errors.New("it has been run or closed yet")
	}

	log := logger.FromContext(ctx).Named("ebpf-trace-collector")

	ctx1 := logger.ToContext(ctx, log)

	defer func() {
		log.Info("stop")
		close(t.stopped)
	}()

	kp, err := link.Kprobe("nft_trace_notify", t.objs.KprobeNftTraceNotify, nil)
	if err != nil {
		return errors.WithMessage(err, "opening kprobe")
	}
	defer func() { _ = kp.Close() }()

	if t.useAggregation {
		cancel, err := newPerCpuPerfEventTimer(runtime.NumCPU(), t.objs.SendAgregatedTrace, t.evRate)
		if err != nil {
			return err
		}
		defer cancel()
	}

	tg := NewTraceGroup(t.IfaceProvider, t.RuleProvider)
	defer tg.Close()

	return t.pushTraces(ctx1, func(tr EbpfTrace) (err error) {
		if err = tg.AddTrace(tr.ToNftTrace()); err != nil {
			return err
		}
		if !t.useAggregation && !t.useSampling && !tg.GroupReady() {
			return ErrTraceDataNotReady
		}
		m, err := tg.ToModel()
		if err != nil {
			return errors.WithMessage(err, "failed to convert obtained trace into model")
		}
		tg.Reset()

		if t.useAggregation {
			err = t.que.Upsert(uint64(tr.TraceHash), m)
		} else {
			err = t.que.Enque(m)
		}
		if errors.Is(err, queue.ErrQueIsFull) {
			t.Subj.Notify(CountOverflowQueEvent{Cnt: 1})
			err = nil
		}
		return err
	})
}

// Reader
func (t *ebpfTraceCollector) Reader() <-chan model.Trace {
	return t.que.Reader()
}

// Close
func (t *ebpfTraceCollector) Close() error {
	t.onceClose.Do(func() {
		close(t.stop)
		t.onceRun.Do(func() {})
		if t.stopped != nil {
			<-t.stopped
		}
		_ = t.objs.Close()
	})
	return nil
}

func (t *ebpfTraceCollector) pushTraces(ctx context.Context, callback func(event EbpfTrace) error) error {
	log := logger.FromContext(ctx)
	rd, err := perf.NewReader(t.objs.TraceEvents, t.bufflen)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer func() { _ = rd.Close() }()

	log.Infof("start with options: cpu=%d, rcv-buffer-size=%d, use-aggregation=%v, sampling=%v, events-rate=%d",
		t.objs.TraceEvents.MaxEntries(), rd.BufferSize(), t.useAggregation, t.useSampling, t.evRate)

	errCh := make(chan error)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		var (
			trace                   bpfTraceInfo
			err                     error
			lostCnt, rcvCnt, pktCnt uint64
			record                  = new(perf.Record)
		)

		defer func() {
			rateLost := float64(0)
			if (rcvCnt + lostCnt) > 0 {
				rateLost = float64(lostCnt) / float64(rcvCnt+lostCnt) * 100
			}

			log.Infof("lost samples: %d (%.2f%%), expected samples: %d, agregated pkt: %d",
				lostCnt, rateLost, rcvCnt+lostCnt, pktCnt)

			close(errCh)
			wg.Done()
		}()

	Loop:
		for err == nil {
			select {
			case <-ctx.Done():
				return
			case <-t.stop:
				return
			default:
			}
			rd.SetDeadline(time.Now().Add(time.Second))
			err = rd.ReadInto(record)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					err = nil
					continue
				}
				err = errors.WithMessage(err, "reading trace from reader")
				goto Loop
			}
			lostCnt += record.LostSamples
			t.Subj.Notify(CountLostSampleEvent{Cnt: record.LostSamples})
			if len(record.RawSample) == 0 {
				continue
			}

			trace = *(*bpfTraceInfo)(unsafe.Pointer(&record.RawSample[0]))
			pktCnt += trace.Counter
			rcvCnt++
			t.Subj.Notify(CountRcvPktEvent{Cnt: trace.Counter})
			t.Subj.Notify(CountRcvSampleEvent{Cnt: 1})
			if callback != nil {
				if err = callback(EbpfTrace(trace)); err != nil {
					if errors.Is(err, ErrTraceDataNotReady) {
						err = nil
						continue
					}
				}
			}
		}
		errCh <- err
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

func ensureMemlock() (err error) {
	const mem1Gb = 1 << 30
	onceLock.Do(func() {
		err = rlimit.RemoveMemlock()
		if err == nil {
			memLockForGC = make([]byte, mem1Gb)
			_ = memLockForGC
		}
	})
	return err
}

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
			MaxEntries: MaxConnectionsPerSec,
		},
	}

	for i := 0; i < nCPU; i++ {
		innerMap, err := ebpf.NewMap(outerMapSpec.InnerMap)
		if err != nil {
			return nil, errors.WithMessage(err, "inner_map")
		}
		defer innerMap.Close() //nolint:errcheck
		k := uint32(i)         //nolint:gosec
		outerMapSpec.Contents[i] = ebpf.MapKV{Key: k, Value: innerMap}
	}
	return ebpf.NewMap(&outerMapSpec)
}

// newPerCpuPerfEventTimer - assign perf event program as a timer. Rate should be in range 1 ... 100 (means number of events per second)
func newPerCpuPerfEventTimer(nCPU int, program *ebpf.Program, rate uint64) (cancel func(), err error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Sample: rate,
		Wakeup: 1,
		Bits:   unix.PerfBitFreq,
	}
	attr.Size = uint32(binary.Size(&attr)) //nolint:gosec
	var (
		fds []int
		fd  int
	)

	cancel = func() {
		for i := range fds {
			_ = unix.Close(fds[i])
		}
	}

	defer func() {
		if err != nil {
			cancel()
		}
	}()

	for cpu := range nCPU {
		fd, err = unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			return cancel, errors.WithMessagef(err, "failed to create perf event for cpu %d", cpu)
		}
		fds = append(fds, fd)

		if err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, program.FD()); err != nil {
			return cancel, errors.WithMessagef(err, "failed to attach perf event fo the cpu %d", cpu)
		}

		if err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			return cancel, errors.WithMessagef(err, "failed to enable perf event for the cpu %d", cpu)
		}
	}

	return cancel, err
}
