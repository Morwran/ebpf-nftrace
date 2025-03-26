package nfrule

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Morwran/ebpf-nftrace/internal/nftables/parser"
	"github.com/Morwran/ebpf-nftrace/internal/nl"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	nftLib "github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// RuleProvider - common interface for the rule trace
type (
	RuleProvider interface {
		Run(ctx context.Context) (err error)
		GetRuleForTrace(tr TraceRuleDescriptor) (re RuleEntry, err error)
		Close() error
	}
	NetlinkWatcher interface {
		Read() <-chan nl.NlData
	}
	// Deps - dependency
	Deps struct {
		// Adapters
		AgentSubject observer.Subject
		NlWatcher    NetlinkWatcher
	}
)

type (
	ruleProviderImpl struct {
		Deps
		cache     *RuleCache
		onceRun   sync.Once
		onceClose sync.Once
		stop      chan struct{}
		stopped   chan struct{}
	}
	TraceRuleDescriptor struct {
		TableName  string
		ChainName  string
		RuleHandle uint64
		Family     byte
		TracedAt   time.Time
	}
	// CountRulerNlErrMemEvent -
	CountRulerNlErrMemEvent struct {
		observer.EventType
	}
)

var _ RuleProvider = (*ruleProviderImpl)(nil)

func NewRuleProvider(d Deps) (rt *ruleProviderImpl) {
	const ttl = 3 * time.Second
	return &ruleProviderImpl{
		Deps:  d,
		stop:  make(chan struct{}),
		cache: NewRuleCache(ttl),
	}
}

func (r *ruleProviderImpl) GetRuleForTrace(tr TraceRuleDescriptor) (re RuleEntry, err error) {
	table, chain, handle := tr.TableName, tr.ChainName, tr.RuleHandle
	re, ok := r.cache.GetRule(RuleEntryKey{table, nftLib.TableFamily(tr.Family), chain, handle})
	if !ok {
		conn, err := nftLib.New()
		if err != nil {
			return re, err
		}
		defer conn.CloseLasting() //nolint:errcheck
		rules, err := conn.GetRules(
			&nftLib.Table{
				Name:   table,
				Family: nftLib.TableFamily(tr.Family),
			},
			&nftLib.Chain{Name: chain},
		)
		if err != nil {
			return re, err
		}
		var rl *nftLib.Rule
		for _, rule := range rules {
			if rule.Handle == handle {
				rl = rule
				break
			}
		}

		if rl == nil {
			return re, ErrNotFoundRule
		}
		pr := (*parser.Rule)(rl)
		strRule, err := pr.String()
		if err != nil {
			return re, err
		}

		re = RuleEntry{
			RuleNative: rl,
			RuleStr:    strRule,
			At:         time.Now(),
		}

		r.cache.InsertRule(re)
		return re, nil
	}

	if re.removed || re.At.After(tr.TracedAt) ||
		!(re.RuleNative.Table.Name == tr.TableName &&
			re.RuleNative.Chain.Name == tr.ChainName) {
		return re, ErrExpiredTrace
	}

	return re, nil
}

func (r *ruleProviderImpl) Run(ctx context.Context) (err error) {
	var doRun bool

	r.onceRun.Do(func() {
		doRun = true
		r.stopped = make(chan struct{})
	})
	if !doRun {
		return ErrRule{Err: errors.New("it has been run or closed yet")}
	}

	err = r.cache.Refresh()
	if err != nil {
		return ErrRule{Err: fmt.Errorf("failed to refresh rule cache: %v", err)}
	}

	log := logger.FromContext(ctx).Named("rule-watcher")
	ctx1 := logger.ToContext(ctx, log)

	log.Info("start")
	defer func() {
		log.Info("stop")
		close(r.stopped)
	}()

	for {
		select {
		case <-ctx.Done():
			log.Info("will exit cause ctx canceled")
			return ctx.Err()
		case <-r.stop:
			log.Info("will exit cause it has closed")
			return nil
		case nlData, ok := <-r.NlWatcher.Read():
			if !ok {
				log.Info("will exit cause rule watcher has already closed")
				return ErrRule{Err: errors.New("rule watcher has already closed")}
			}
			err = nlData.Err
			messages := nlData.Messages

			if err != nil {
				if errors.Is(err, nl.ErrNlMem) {
					r.AgentSubject.Notify(CountRulerNlErrMemEvent{})
					continue
				}
				if errors.Is(err, nl.ErrNlDataNotReady) ||
					errors.Is(err, nl.ErrNlReadInterrupted) {
					continue
				}

				return ErrRule{Err: errors.WithMessage(err, "failed to rcv nl message")}
			}

			for _, msg := range messages {
				if err = r.handleMsg(ctx1, msg); err != nil {
					return err
				}
			}
		}
	}
}

// handleMsg - handle netlink message
func (r *ruleProviderImpl) handleMsg(ctx context.Context, msg netlink.Message) error {
	log := logger.FromContext(ctx)
	t := nl.NetlinkNfMsg(msg).MsgType()
	switch t {
	case unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:
		rule := new(parser.Rule)
		err := rule.InitFromMsg(msg)
		if err != nil {
			return errors.WithMessage(err, "failed to fetch rule from netlink message")
		}
		strRule, err := rule.String()
		if err != nil {
			return err
		}

		re := RuleEntry{
			RuleNative: (*nftLib.Rule)(rule),
			RuleStr:    strRule,
			removed:    false,
			At:         time.Now(),
		}
		dbgLog := ""
		if t == unix.NFT_MSG_DELRULE {
			re.removed = true
			dbgLog = fmt.Sprintf("removed rule=%d, expr: %s", rule.Handle, strRule)
		} else {
			dbgLog = fmt.Sprintf("added new rule=%d, expr: %s", rule.Handle, strRule)
		}
		r.cache.UpdRule(re)
		log.Debug(dbgLog)
	}
	return nil
}

// Close rule tracer
func (r *ruleProviderImpl) Close() error {
	r.onceClose.Do(func() {
		close(r.stop)
		r.onceRun.Do(func() {})
		if r.stopped != nil {
			<-r.stopped
		}
		_ = r.cache.Close()
	})
	return nil
}
