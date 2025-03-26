package parser

import (
	"encoding/binary"
	"fmt"
	"strings"

	cache "github.com/Morwran/ebpf-nftrace/internal/nftables/cache"
	exprenc "github.com/Morwran/ebpf-nftrace/internal/nftables/expr-encoders"

	nftLib "github.com/google/nftables"
	"github.com/google/nftables/expr"
	userdata "github.com/google/nftables/userdata"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type (
	Rule nftLib.Rule

	RuleNames struct {
		Names []string `json:"names"`
	}
)

func (r *Rule) InitFromMsg(msg netlink.Message) error {
	fam := nftLib.TableFamily(msg.Data[0])
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian

	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_RULE_TABLE:
			r.Table = &nftLib.Table{
				Name:   ad.String(),
				Family: fam,
			}
		case unix.NFTA_RULE_CHAIN:
			r.Chain = &nftLib.Chain{Name: ad.String()}
		case unix.NFTA_RULE_EXPRESSIONS:
			ad.Do(func(b []byte) error {
				exprs, err := ParseExprMsgFunc(byte(fam), b)
				if err != nil {
					return err
				}
				r.Exprs = make([]expr.Any, len(exprs))
				for i := range exprs {
					r.Exprs[i] = exprs[i].(expr.Any)
				}
				return nil
			})
		case unix.NFTA_RULE_POSITION:
			r.Position = ad.Uint64()
		case unix.NFTA_RULE_HANDLE:
			r.Handle = ad.Uint64()
		case unix.NFTA_RULE_USERDATA:
			r.UserData = ad.Bytes()
		}
	}
	return ad.Err()
}

// JsonString - represent rule expressions as string json
func (r *Rule) JsonString() (string, error) {
	b, err := exprenc.EncodeJSON(exprenc.NewRuleExprs(r.Exprs, r.Table, cache.NewRegisters()), false)
	return string(b), err
}

// String - represent rule expressions as a string
func (r *Rule) String() (string, error) {
	sb := strings.Builder{}
	expr, err := exprenc.NewRuleExprs(r.Exprs, r.Table, cache.NewRegisters()).String()
	if err != nil {
		return "", err
	}
	if expr != "" {
		sb.WriteString(expr)
		if com := r.Comment(); com != "" {
			sb.WriteString(fmt.Sprintf(" comment %q", com))
		}
		sb.WriteString(fmt.Sprintf(" # handle %d", r.Handle))
	}
	return sb.String(), nil
}

// Comment - return a rule comment
func (r *Rule) Comment() (com string) {
	com, _ = userdata.GetString(r.UserData, userdata.TypeComment)
	return com
}
