//go:build perf
// +build perf

package nftrace

import (
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

func newReader(objs *ebpf.Map) (*perf.Reader, error) {
	return perf.NewReader(objs, os.Getpagesize())
}
