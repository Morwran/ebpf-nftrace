package exprenc

import (
	"fmt"

	nfte "github.com/google/nftables/expr"
)

type VerdictKind nfte.VerdictKind

const (
	VerdictReturn   = "return"
	VerdictGoto     = "goto"
	VerdictJump     = "jump"
	VerdictBreak    = "break"
	VerdictContinue = "continue"
	VerdictDrop     = "drop"
	VerdictAccept   = "accept"
	VerdictStolen   = "storlen"
	VerdictQueue    = "queue"
	VerdictRepeat   = "repeat"
	VerdictStop     = "stop"
)

var verdictMap = map[nfte.VerdictKind]string{
	nfte.VerdictReturn:   VerdictReturn,
	nfte.VerdictGoto:     VerdictGoto,
	nfte.VerdictJump:     VerdictJump,
	nfte.VerdictBreak:    VerdictBreak,
	nfte.VerdictContinue: VerdictContinue,
	nfte.VerdictDrop:     VerdictDrop,
	nfte.VerdictAccept:   VerdictAccept,
	nfte.VerdictStolen:   VerdictStolen,
	nfte.VerdictQueue:    VerdictQueue,
	nfte.VerdictRepeat:   VerdictRepeat,
	nfte.VerdictStop:     VerdictStop,
}

func (v VerdictKind) String() (verdict string) {
	verdict, ok := verdictMap[nfte.VerdictKind(v)]
	if !ok {
		verdict = "unknown"
	}
	return verdict
}

type ExprVerdict struct {
	*nfte.Verdict
}

func newVerdictEncoder(expr *nfte.Verdict) *ExprVerdict {
	return &ExprVerdict{Verdict: expr}
}

func (expr *ExprVerdict) String() (string, error) {
	if expr.Chain == "" {
		return VerdictKind(expr.Kind).String(), nil
	}
	return fmt.Sprintf("%s %s", VerdictKind(expr.Kind).String(), expr.Chain), nil
}

func (expr *ExprVerdict) MarshalJSON() ([]byte, error) {
	if expr.Chain == "" {
		return []byte(fmt.Sprintf(`{%q:null}`, VerdictKind(expr.Kind).String())), nil
	}
	return []byte(fmt.Sprintf(`{%q:{"target":%q}}`, VerdictKind(expr.Kind).String(), expr.Chain)), nil
}
