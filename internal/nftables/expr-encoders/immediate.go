package exprenc

import (
	"github.com/Morwran/ebpf-nftrace/internal/nftables/bytes"
	"github.com/Morwran/ebpf-nftrace/internal/nftables/cache"

	nfte "github.com/google/nftables/expr"
)

type ExprImmediate struct {
	*nfte.Immediate
	reg Register
}

func newImmediateEncoder(expr *nfte.Immediate, reg Register) *ExprImmediate {
	return &ExprImmediate{Immediate: expr, reg: reg}
}

func (expr *ExprImmediate) String() (string, error) {
	expr.reg.InsertExpr(expr.Register,
		cache.RegEntry{
			ExprStr: bytes.RawBytes((expr.Data)).String(),
			Expr:    expr.Immediate,
		})
	return "", nil
}

func (expr *ExprImmediate) MarshalJSON() ([]byte, error) {
	expr.reg.InsertExpr(expr.Register, cache.RegEntry{Any: bytes.RawBytes((expr.Data))})
	return []byte("{}"), nil
}
