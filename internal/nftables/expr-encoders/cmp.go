package exprenc

import (
	"bytes"
	"fmt"
	"strings"

	rb "github.com/Morwran/ebpf-nftrace/internal/nftables/bytes"
	pr "github.com/Morwran/ebpf-nftrace/internal/nftables/expr-encoders/protocols"

	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type CmpOp nfte.CmpOp

func (c CmpOp) String() string {
	switch nfte.CmpOp(c) {
	case nfte.CmpOpEq:
		return "=="
	case nfte.CmpOpNeq:
		return "!="
	case nfte.CmpOpLt:
		return "<"
	case nfte.CmpOpLte:
		return "<="
	case nfte.CmpOpGt:
		return ">"
	case nfte.CmpOpGte:
		return ">="
	}
	return ""
}

type ExprCmp struct {
	*nfte.Cmp
	reg     Register
	hdrDesc *pr.ProtoDescPtr
}

func newCmpEncoder(expr *nfte.Cmp, reg Register, hdrDesc *pr.ProtoDescPtr) *ExprCmp {
	return &ExprCmp{Cmp: expr, reg: reg, hdrDesc: hdrDesc}
}

func (expr *ExprCmp) String() (string, error) {
	sb := strings.Builder{}

	srcReg, ok := expr.reg.GetExpr(expr.Register)
	if !ok {
		return "", errors.Errorf("%T expression has no left hand side", expr.Cmp)
	}
	left := srcReg.ExprStr

	var right string
	switch t := srcReg.Expr.(type) {
	case *nfte.Meta:
		var protos pr.ProtoTypeHolder
		switch t.Key {
		case nfte.MetaKeyL4PROTO, nfte.MetaKeyPROTOCOL:
			protos = pr.Protocols[nfte.PayloadBaseTransportHeader]
		case nfte.MetaKeyNFPROTO:
			protos = pr.Protocols[nfte.PayloadBaseNetworkHeader]
		default:
			if metaExpr, ok := srcReg.Any.(*ExprMeta); ok {
				right = metaExpr.metaDataToString(expr.Data)
			}
		}
		if proto, ok := protos[pr.ProtoType(int(rb.RawBytes(expr.Data).Uint64()))]; ok { //nolint:gosec
			right = proto.Name
			*expr.hdrDesc = &proto
		}
	case *nfte.Bitwise:
		if rb.RawBytes(expr.Data).Uint64() != 0 {
			right = fmt.Sprintf("0x%s", rb.RawBytes(expr.Data).Text(rb.BaseHex))
		}
		hdrDesc := *expr.hdrDesc
		if hdrDesc != nil {
			if desc, ok := hdrDesc.Offsets[hdrDesc.CurrentOffset]; ok {
				right = desc.Desc(expr.Data)
			}
		}
	case *nfte.Ct:
		right = CtDesk[t.Key](expr.Data)
	case *nfte.Payload:
		hdrDesc := *expr.hdrDesc
		if hdrDesc != nil {
			if desc, ok := hdrDesc.Offsets[hdrDesc.CurrentOffset]; ok {
				right = desc.Desc(expr.Data)
			}
		} else if proto, ok := pr.Protocols[t.Base]; ok && t.Base == nfte.PayloadBaseNetworkHeader {
			header := proto[unix.IPPROTO_IP]
			if desc, ok := header.Offsets[pr.HeaderOffset(t.Offset).BytesToBits()]; ok {
				left = fmt.Sprintf("%s %s", header.Name, desc.Name)
				right = desc.Desc(expr.Data)
			}
		} else if proto, ok := pr.Protocols[t.Base]; ok && t.Base == nfte.PayloadBaseTransportHeader {
			header := proto[unix.IPPROTO_NONE]
			if desc, ok := header.Offsets[pr.HeaderOffset(t.Offset).BytesToBits()]; ok {
				left = fmt.Sprintf("%s %s", header.Name, desc.Name)
				right = desc.Desc(expr.Data)
			}
		}
	default:
		right = rb.RawBytes(expr.Data).Text(rb.BaseDec)
	}

	op := CmpOp(expr.Op).String()
	if expr.Op == nfte.CmpOpEq {
		op = ""
	}

	if op != "" && right != "" {
		sb.WriteString(fmt.Sprintf("%s %s %s", left, op, right))
	} else if right != "" {
		sb.WriteString(fmt.Sprintf("%s %s", left, right))
	} else {
		sb.WriteString(left)
	}

	return sb.String(), nil
}

func (expr *ExprCmp) MarshalJSON() ([]byte, error) {
	srcReg, ok := expr.reg.GetExpr(expr.Register)
	if !ok || srcReg.Any == nil {
		return nil, errors.Errorf("%T expression has no left hand side", expr.Cmp)
	}

	var right any
	switch t := srcReg.Expr.(type) {
	case *nfte.Meta:
		switch t.Key {
		case nfte.MetaKeyL4PROTO:
			switch rb.RawBytes(expr.Data).Uint64() {
			case unix.IPPROTO_TCP:
				right = "tcp"
			case unix.IPPROTO_UDP:
				right = "udp"
			default:
				right = "unknown" //nolint:goconst
			}
		case nfte.MetaKeyIIFNAME, nfte.MetaKeyOIFNAME:
			right = string(bytes.TrimRight(expr.Data, "\x00"))
		case nfte.MetaKeyNFTRACE:
			right = rb.RawBytes(expr.Data).Uint64()
		default:
			right = rb.RawBytes(expr.Data)
		}
	default:
		right = rb.RawBytes(expr.Data)
	}

	cmp := map[string]interface{}{
		"match": struct {
			Op    string `json:"op"`
			Left  any    `json:"left"`
			Right any    `json:"right"`
		}{
			Op:    CmpOp(expr.Op).String(),
			Left:  srcReg.Any,
			Right: right,
		},
	}

	return EncodeJSON(cmp, false)
}
