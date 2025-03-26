package parser

import (
	"fmt"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type ruleTestSuite struct {
	suite.Suite
}

func (sui *ruleTestSuite) Test_RuleStringAndComments() {
	const (
		comment = "{`names`:[`rule1`,`rule2`],`IPv`:4}"
	)
	testCases := []struct {
		name         string
		rule         nftables.Rule
		expRuleStr   string
		expRuleNames []string
	}{
		{
			name: "rule without comments",
			rule: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Counter{},
					&expr.Log{},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
			expRuleStr: "meta l4proto tcp counter packets 0 bytes 0 log accept # handle 0",
		},
		{
			name: "rule with comments",
			rule: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpNeq,
						Register: 1,
						Data:     []byte("lo"),
					},
					&expr.Immediate{Register: 1, Data: []byte{1}},
					&expr.Meta{Key: expr.MetaKeyNFTRACE, SourceRegister: true, Register: 1},
					&expr.Verdict{
						Kind:  expr.VerdictGoto,
						Chain: "FW-OUT",
					},
				},
				UserData: userdata.AppendString([]byte(nil), userdata.TypeComment, comment),
			},
			expRuleStr:   fmt.Sprintf("oifname != lo meta nftrace set 1 goto FW-OUT comment %q # handle 0", comment),
			expRuleNames: []string{"rule1", "rule2"},
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			rl := (*Rule)(&tc.rule)
			str, err := rl.String()
			sui.Require().NoError(err)
			fmt.Println(str)
			sui.Require().Equal(tc.expRuleStr, str)
		})
	}
}

func Test_RuleTests(t *testing.T) {
	suite.Run(t, new(ruleTestSuite))
}
