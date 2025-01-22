package nftrace

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/Morwran/ebpf-nftrace/internal/app"

	"github.com/H-BF/corlib/pkg/atomic"
	"github.com/prometheus/client_golang/prometheus"
)

type AgentMetrics struct {
	traceCount    prometheus.Counter
	errNlMemCount *prometheus.CounterVec
	numCPU        prometheus.Gauge
	gcEvents      prometheus.Counter
}

var agentMetricsHolder atomic.Value[*AgentMetrics]

const (
	labelHostName = "host_name"
	nsAgent       = "agent"
	labelSource   = "source"
)

const ( // error sources
	// ESrcIface -
	ESrcIface = "iface"

	// ESrcCollector -
	ESrcCollector = "collector"

	// ESrcRuler -
	ESrcRuler = "ruler"
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
			am.numCPU,
			am.gcEvents,
		},
	}
	err = app.SetupMetrics(metricsOpt)
	if err == nil {
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
		Namespace:   nsAgent,
		Name:        "traces_counter",
		Help:        "count of traces send through grpc",
		ConstLabels: labels,
	})
	am.errNlMemCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   nsAgent,
		Name:        "err_nl_mem_counter",
		Help:        "count of netlink receive buffer overload",
		ConstLabels: labels,
	}, []string{labelSource})
	am.numCPU = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   nsAgent,
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

// ObserveTracesCounter -
func (am *AgentMetrics) ObserveTracesCounter(cnt int) {
	am.traceCount.Add(float64(cnt))
}

// ObserveErrNlMemCounter -
func (am *AgentMetrics) ObserveErrNlMemCounter(errSource string) {
	am.errNlMemCount.WithLabelValues(errSource).Inc()
}

func (am *AgentMetrics) MonitorGC() {
	var lastNumGC uint32
	for {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)

		if stats.NumGC != lastNumGC {
			am.gcEvents.Add(float64(stats.NumGC - lastNumGC))
			lastNumGC = stats.NumGC
		}

		time.Sleep(1 * time.Second)
	}
}
