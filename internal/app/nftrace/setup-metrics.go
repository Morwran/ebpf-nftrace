package nftrace

import (
	"context"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/Morwran/ebpf-nftrace/internal/app"

	"github.com/H-BF/corlib/pkg/atomic"
	"github.com/prometheus/client_golang/prometheus"
)

type AgentMetrics struct {
	onceRun           sync.Once
	traceCount        prometheus.Counter
	errNlMemCount     *prometheus.CounterVec
	rcvPktCount       prometheus.Counter
	lostTraceCount    prometheus.Counter
	rcvTraceCount     prometheus.Counter
	traceQueOvflCount prometheus.Counter
	numCPU            prometheus.Gauge
	gcEvents          prometheus.Counter
}

var agentMetricsHolder atomic.Value[*AgentMetrics]

const (
	labelUserAgent = "user_agent"
	labelHostName  = "host_name"
	nsTracer       = "tracer"
	labelSource    = "source"
)

const ( // error sources
	// ESrcIface -
	ESrcIface = "iface"

	// ESrcCollector -
	ESrcCollector = "collector"

	// ESrcRuler -
	ESrcRuler = "ruler"
)

type ( // counter sources
	Counter interface {
		isCounter()
	}
	TraceCountSrc struct {
		Counter
		Cnt int
	}
	RcvPktCountSrc struct {
		Counter
		Cnt uint64
	}
	LostTraceCountSrc struct {
		Counter
		Cnt uint64
	}
	RcvTraceCountSrc struct {
		Counter
		Cnt uint64
	}
	TraceQueOvflCountSrc struct {
		Counter
		Cnt uint64
	}
)

// SetupMetrics -
func SetupMetrics(ctx context.Context) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	labels := prometheus.Labels{
		labelHostName: hostname,
	}
	am := new(AgentMetrics)
	am.init(labels)
	metricsOpt := app.AddMetrics{
		Metrics: []prometheus.Collector{
			am.traceCount,
			am.errNlMemCount,
			am.rcvPktCount,
			am.lostTraceCount,
			am.rcvTraceCount,
			am.traceQueOvflCount,
			am.numCPU,
			am.gcEvents,
		},
	}
	err = app.SetupMetrics(metricsOpt)
	if err == nil {
		go am.monitorGC(ctx)
		agentMetricsHolder.Store(am, nil)
	}
	return err
}

// GetAgentMetrics -
func GetAgentMetrics() *AgentMetrics {
	v, _ := agentMetricsHolder.Load()
	return v
}

func (am *AgentMetrics) init(labels prometheus.Labels) {
	am.traceCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   nsTracer,
		Name:        "traces_counter",
		Help:        "count of traces send through grpc",
		ConstLabels: labels,
	})
	am.errNlMemCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   nsTracer,
		Name:        "err_nl_mem_counter",
		Help:        "count of netlink receive buffer overload",
		ConstLabels: labels,
	}, []string{labelSource})
	for _, metric := range []string{ESrcIface, ESrcCollector, ESrcRuler} {
		am.errNlMemCount.WithLabelValues(metric).Add(0)
	}

	am.rcvPktCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   nsTracer,
		Name:        "rcv_pkt_counter",
		Help:        "count of packets processed in ebpf module",
		ConstLabels: labels,
	})
	am.lostTraceCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   nsTracer,
		Name:        "lost_traces_counter",
		Help:        "count of traces lost due to receive buffer overflow",
		ConstLabels: labels,
	})
	am.rcvTraceCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   nsTracer,
		Name:        "rcv_trace_counter",
		Help:        "count of traces received from netlink or ebpf collector",
		ConstLabels: labels,
	})
	am.traceQueOvflCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   nsTracer,
		Name:        "trace_que_overflow",
		Help:        "count of overflow events in a trace queue",
		ConstLabels: labels,
	})

	am.numCPU = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   nsTracer,
		Name:        "runtime_num_cpu",
		Help:        "Number of CPU cores available",
		ConstLabels: labels,
	})
	am.numCPU.Set(float64(runtime.NumCPU()))
	am.gcEvents = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "go_gc_events_total",
			Help: "The total number of GC events that have occurred.",
		},
	)
}

// ObserveCounters -
func (am *AgentMetrics) ObserveCounters(cnt Counter) {
	switch t := cnt.(type) {
	case TraceCountSrc:
		am.traceCount.Add(float64(t.Cnt))
	case RcvPktCountSrc:
		am.rcvPktCount.Add(float64(t.Cnt))
	case LostTraceCountSrc:
		am.lostTraceCount.Add(float64(t.Cnt))
	case RcvTraceCountSrc:
		am.rcvTraceCount.Add(float64(t.Cnt))
	case TraceQueOvflCountSrc:
		am.traceQueOvflCount.Add(float64(t.Cnt))
	}
}

// ObserveErrNlMemCounter -
func (am *AgentMetrics) ObserveErrNlMemCounter(errSource string) {
	am.errNlMemCount.WithLabelValues(errSource).Inc()
}

func (am *AgentMetrics) monitorGC(ctx context.Context) {
	var (
		lastNumGC uint32
		doRun     bool
	)

	am.onceRun.Do(func() {
		doRun = true
	})
	if !doRun {
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var stats runtime.MemStats
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runtime.ReadMemStats(&stats)
			if stats.NumGC != lastNumGC {
				am.gcEvents.Add(float64(stats.NumGC - lastNumGC))
				lastNumGC = stats.NumGC
			}
		}
	}
}
