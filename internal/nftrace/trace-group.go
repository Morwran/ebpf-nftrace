package nftrace

import (
	"strings"
	"time"

	model "github.com/Morwran/ebpf-nftrace/internal/models"
	expr "github.com/Morwran/ebpf-nftrace/internal/nftables/expr-encoders"
	"github.com/Morwran/ebpf-nftrace/internal/nftables/expr-encoders/protocols"
	"github.com/Morwran/ebpf-nftrace/internal/nftables/parser"
	rl "github.com/Morwran/ebpf-nftrace/internal/providers/nfrule-provider"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type (
	TraceGroup struct {
		ifaceProvider ifaceProvider
		ruleProvider  ruleProvider
		topTrace      NftTrace
		traceCache    map[uint32][]NftTrace
	}
)

func NewTraceGroup(iface ifaceProvider, rule ruleProvider) *TraceGroup {
	return &TraceGroup{
		ifaceProvider: iface,
		ruleProvider:  rule,
		traceCache:    make(map[uint32][]NftTrace),
	}
}

func (t *TraceGroup) AddTrace(tr NftTrace) error {
	if _, ok := traceTypes[tr.Type]; !ok {
		return errors.Wrapf(ErrTraceTypeUnknown, "type=%d", tr.Type)
	}

	if tr.Type == unix.NFT_TRACETYPE_POLICY {
		tr.Verdict = tr.Policy
	}
	t.traceCache[tr.Id] = append(t.traceCache[tr.Id], tr)
	t.topTrace = tr
	return nil
}

func (t *TraceGroup) GroupReady() bool {
	if len(t.traceCache) == 0 {
		return false
	}
	v := expr.VerdictKind(t.topTrace.Verdict).String()
	return v == expr.VerdictAccept || v == expr.VerdictDrop
}

func (t *TraceGroup) Close() {
	t.traceCache = nil
	t.topTrace.Reset()
}

func (t *TraceGroup) Reset() {
	delete(t.traceCache, t.topTrace.Id)
	t.topTrace.Reset()
}

func (t *TraceGroup) ToModel() (m model.Trace, err error) {
	verdict := strings.Builder{}
	traces, ok := t.traceCache[t.topTrace.Id]
	if !ok {
		return m, ErrTraceGroupEmpty
	}
	t.topTrace.Reset()
	for i, tr := range traces {
		if tr.Type == unix.NFT_TRACETYPE_RETURN {
			continue
		}
		verdict.WriteString(traceTypes[tr.Type])
		verdict.WriteString("::")
		v := expr.VerdictKind(int32(tr.Verdict)).String() //nolint:gosec
		verdict.WriteString(v)
		if v != expr.VerdictDrop && v != expr.VerdictAccept && i < len(traces)-1 {
			verdict.WriteString("->")
		}
		if tr.Type == unix.NFT_TRACETYPE_RULE && tr.RuleHandle != 0 && t.topTrace.RuleHandle == 0 {
			t.topTrace = tr
		}
	}

	if t.topTrace.Type != unix.NFT_TRACETYPE_RULE {
		return m, errors.New("failed to find trace of rule type")
	}

	re, err := t.ruleProvider.GetRuleForTrace(rl.TraceRuleDescriptor{
		TableName:  t.topTrace.Table,
		ChainName:  t.topTrace.Chain,
		RuleHandle: t.topTrace.RuleHandle,
		Family:     t.topTrace.Family,
		TracedAt:   time.Now(),
	})
	if err != nil {
		return m, errors.WithMessagef(err, "trace data: %+v", t.topTrace)
	}

	iifname := t.topTrace.Iifname
	oifname := t.topTrace.Oifname

	if iifname == "" && t.topTrace.Iif != 0 {
		iifname, err = t.ifaceProvider.GetIface(int(t.topTrace.Iif))
		if err != nil {
			return m, errors.WithMessagef(err,
				"failed to find ifname for the ingress traffic by interface id=%d",
				int(t.topTrace.Iif))
		}
	}
	if oifname == "" && t.topTrace.Oif != 0 {
		oifname, err = t.ifaceProvider.GetIface(int(t.topTrace.Oif))
		if err != nil {
			return m, errors.WithMessagef(err,
				"failed to find ifname for the egress traffic by interface id=%d",
				int(t.topTrace.Oif))
		}
	}

	m = model.Trace{
		TrId:       t.topTrace.Id,
		Table:      t.topTrace.Table,
		Chain:      t.topTrace.Chain,
		JumpTarget: t.topTrace.JumpTarget,
		RuleHandle: t.topTrace.RuleHandle,
		Family:     parser.TableFamily(t.topTrace.Family).String(),
		Iifname:    iifname,
		Oifname:    oifname,
		SMacAddr:   t.topTrace.SMacAddr,
		DMacAddr:   t.topTrace.DMacAddr,
		SAddr:      t.topTrace.SAddr,
		DAddr:      t.topTrace.DAddr,
		SPort:      t.topTrace.SPort,
		DPort:      t.topTrace.DPort,
		Length:     t.topTrace.Length,
		IpProto:    protocols.ProtoType(t.topTrace.IpProtocol).String(),
		Verdict:    verdict.String(),
		Rule:       re.RuleStr,
		Cnt:        t.topTrace.Cnt,
		Timestamp:  time.Now(),
	}

	return m, nil
}

var traceTypes = map[uint32]string{
	unix.NFT_TRACETYPE_RULE:   "rule",
	unix.NFT_TRACETYPE_RETURN: "return",
	unix.NFT_TRACETYPE_POLICY: "policy",
}
