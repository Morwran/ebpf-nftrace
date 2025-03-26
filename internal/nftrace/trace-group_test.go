package nftrace

import (
	"testing"

	rl "github.com/Morwran/ebpf-nftrace/internal/providers/nfrule-provider"

	nfte "github.com/google/nftables/expr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	ifaceName = "eth0"
)

type (
	DepsMock struct {
		iface ifaceProvider
		rule  ruleProvider
	}
	ifaceProviderMock struct {
		mock.Mock
	}
	ruleProviderMock struct {
		mock.Mock
	}
)

func (i *ifaceProviderMock) GetIface(index int) (string, error) {
	return ifaceName, nil
}

func (r *ruleProviderMock) GetRuleForTrace(tr rl.TraceRuleDescriptor) (rl.RuleEntry, error) {
	return rl.RuleEntry{}, nil
}

func Test_TraceGroup(t *testing.T) {
	verdictGoTo := nfte.VerdictGoto
	verdictContinue := nfte.VerdictContinue
	testCases := []struct {
		name       string
		data       []NetlinkTrace
		verdict    string
		expHandle  uint64
		checkReady bool
		mock       DepsMock
	}{
		{
			name:       "single trace type of rule with accept",
			data:       []NetlinkTrace{{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 1, Verdict: uint32(nfte.VerdictAccept)}},
			verdict:    "rule::accept",
			expHandle:  1,
			checkReady: true,
			mock:       DepsMock{&ifaceProviderMock{}, &ruleProviderMock{}},
		},
		{
			name:      "single trace type of rule with goto",
			data:      []NetlinkTrace{{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 1, Verdict: uint32(verdictGoTo)}},
			verdict:   "rule::goto",
			expHandle: 1,
			mock:      DepsMock{&ifaceProviderMock{}, &ruleProviderMock{}},
		},
		{
			name: "multiple traces with return and policy accept",
			data: []NetlinkTrace{
				{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 1, Verdict: uint32(verdictGoTo)},
				{Type: unix.NFT_TRACETYPE_RETURN, RuleHandle: 2, Verdict: uint32(verdictContinue)},
				{Type: unix.NFT_TRACETYPE_POLICY, Policy: uint32(nfte.VerdictAccept)},
			},
			verdict:    "rule::goto->policy::accept",
			expHandle:  1,
			checkReady: true,
			mock:       DepsMock{&ifaceProviderMock{}, &ruleProviderMock{}},
		},
		{
			name: "multiple traces with return rule with handle 0 and policy accept",
			data: []NetlinkTrace{
				{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 1, Verdict: uint32(verdictGoTo)},
				{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 0, Verdict: uint32(verdictContinue)},
				{Type: unix.NFT_TRACETYPE_POLICY, Policy: uint32(nfte.VerdictAccept)},
			},
			verdict:    "rule::goto->rule::continue->policy::accept",
			expHandle:  1,
			checkReady: true,
			mock:       DepsMock{&ifaceProviderMock{}, &ruleProviderMock{}},
		},
		{
			name: "multiple traces with double rule accepts",
			data: []NetlinkTrace{
				{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 1, Verdict: uint32(verdictGoTo)},
				{Type: unix.NFT_TRACETYPE_RULE, RuleHandle: 2, Verdict: uint32(nfte.VerdictAccept)},
			},
			verdict:    "rule::goto->rule::accept",
			expHandle:  1,
			checkReady: true,
			mock:       DepsMock{&ifaceProviderMock{}, &ruleProviderMock{}},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tg := NewTraceGroup(tc.mock.iface, tc.mock.rule)
			for i := range tc.data {
				require.False(t, tg.GroupReady())
				require.NoError(t, tg.AddTrace(tc.data[i].ToNftTrace()))
			}
			if tc.checkReady {
				require.True(t, tg.GroupReady())
			}
			md, err := tg.ToModel()
			require.NoError(t, err)
			require.Equal(t, tc.verdict, md.Verdict)
			require.Equal(t, tc.expHandle, md.RuleHandle)
			tg.Close()
		})
	}
}
