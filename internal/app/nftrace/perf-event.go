package nftrace

import (
	"encoding/binary"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// NewPerfEventTimerPerCPUs - assign perf event program as a timer. Rate should be in range 1 ... 100 (means number of events per second)
func NewPerfEventTimerPerCPUs(nCPU int, program *ebpf.Program, rate uint64) (cancel func(), err error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Sample: rate,
		Wakeup: 1,
		Bits:   unix.PerfBitFreq,
	}
	attr.Size = uint32(binary.Size(&attr))
	var (
		fds    []int
		events []*link.RawLink
	)

	cancel = func() {
		for _, ev := range events {
			ev.Close()
		}
		for _, fd := range fds {
			unix.Close(fd)
		}
	}

	defer func() {
		if err != nil {
			cancel()
		}
	}()

	for cpu := range nCPU {
		var (
			fd int
			pe *link.RawLink
		)
		fd, err = unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to create perf event for cpu %d", cpu)
		}
		fds = append(fds, fd)

		pe, err = link.AttachRawLink(link.RawLinkOptions{Target: fd, Program: program, Attach: ebpf.AttachPerfEvent})
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to attach perf event for cpu %d", cpu)
		}
		events = append(events, pe)
	}

	return cancel, err
}
