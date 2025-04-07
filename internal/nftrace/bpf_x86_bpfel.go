// Code generated by bpf2go; DO NOT EDIT.
//go:build (386 || amd64) && linux

package nftrace

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfTraceInfo struct {
	Id          uint32
	TraceHash   uint32
	TableName   [64]uint8
	TableHandle uint64
	ChainName   [64]uint8
	ChainHandle uint64
	RuleHandle  uint64
	JumpTarget  [64]uint8
	Time        uint64
	Counter     uint64
	Verdict     uint32
	Type        uint8
	Family      uint8
	Nfproto     uint8
	Policy      uint8
	Mark        uint32
	Iif         uint32
	Oif         uint32
	IifType     uint16
	OifType     uint16
	IifName     [16]uint8
	OifName     [16]uint8
	SrcPort     uint16
	DstPort     uint16
	SrcIp       uint32
	DstIp       uint32
	SrcIp6      struct{ In6U struct{ U6Addr8 [16]uint8 } }
	DstIp6      struct{ In6U struct{ U6Addr8 [16]uint8 } }
	Len         uint16
	SrcMac      [6]uint8
	DstMac      [6]uint8
	IpProto     uint8
	IpVersion   uint8
	_           [4]byte
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	KprobeNftTraceNotify *ebpf.ProgramSpec `ebpf:"kprobe_nft_trace_notify"`
	SendAgregatedTrace   *ebpf.ProgramSpec `ebpf:"send_agregated_trace"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	PerCpuQue       *ebpf.MapSpec `ebpf:"per_cpu_que"`
	RcvTraceCounter *ebpf.MapSpec `ebpf:"rcv_trace_counter"`
	RdTraceCounter  *ebpf.MapSpec `ebpf:"rd_trace_counter"`
	RdWaitCounter   *ebpf.MapSpec `ebpf:"rd_wait_counter"`
	SampleRate      *ebpf.MapSpec `ebpf:"sample_rate"`
	TraceEvents     *ebpf.MapSpec `ebpf:"trace_events"`
	TracesPerCpu    *ebpf.MapSpec `ebpf:"traces_per_cpu"`
	UseAggregation  *ebpf.MapSpec `ebpf:"use_aggregation"`
	WrTraceCounter  *ebpf.MapSpec `ebpf:"wr_trace_counter"`
	WrWaitCounter   *ebpf.MapSpec `ebpf:"wr_wait_counter"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	PerCpuQue       *ebpf.Map `ebpf:"per_cpu_que"`
	RcvTraceCounter *ebpf.Map `ebpf:"rcv_trace_counter"`
	RdTraceCounter  *ebpf.Map `ebpf:"rd_trace_counter"`
	RdWaitCounter   *ebpf.Map `ebpf:"rd_wait_counter"`
	SampleRate      *ebpf.Map `ebpf:"sample_rate"`
	TraceEvents     *ebpf.Map `ebpf:"trace_events"`
	TracesPerCpu    *ebpf.Map `ebpf:"traces_per_cpu"`
	UseAggregation  *ebpf.Map `ebpf:"use_aggregation"`
	WrTraceCounter  *ebpf.Map `ebpf:"wr_trace_counter"`
	WrWaitCounter   *ebpf.Map `ebpf:"wr_wait_counter"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.PerCpuQue,
		m.RcvTraceCounter,
		m.RdTraceCounter,
		m.RdWaitCounter,
		m.SampleRate,
		m.TraceEvents,
		m.TracesPerCpu,
		m.UseAggregation,
		m.WrTraceCounter,
		m.WrWaitCounter,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	KprobeNftTraceNotify *ebpf.Program `ebpf:"kprobe_nft_trace_notify"`
	SendAgregatedTrace   *ebpf.Program `ebpf:"send_agregated_trace"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.KprobeNftTraceNotify,
		p.SendAgregatedTrace,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_x86_bpfel.o
var _BpfBytes []byte
