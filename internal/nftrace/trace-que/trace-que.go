package cachedque

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	model "github.com/Morwran/ebpf-nftrace/internal/models"

	llq "github.com/emirpasic/gods/queues/linkedlistqueue"
)

type (
	CachedQueFace interface {
		Close() error
		Enque(...model.Trace) error
		Len() int
		Reader() <-chan model.Trace
		Upsert(key uint64, val model.Trace) error
	}
	queData struct {
		key uint64
		val model.Trace
	}

	traceCachedQue struct {
		size        int
		cache       map[uint64]model.Trace
		que         *llq.Queue
		close       chan struct{}
		stopped     chan struct{}
		ch          chan model.Trace
		cv          *sync.Cond
		closeOnce   sync.Once
		runOnce     sync.Once
		sendPending uint32
	}
)

func NewCachedQue(size int) *traceCachedQue {
	if size < 0 {
		panic(fmt.Errorf("NewCachedQue incorrect size=%d. size must be > 0", size))
	}
	return &traceCachedQue{
		size:  size,
		que:   llq.New(),
		cache: make(map[uint64]model.Trace, size),
		close: make(chan struct{}),
		ch:    make(chan model.Trace),
		cv:    sync.NewCond(new(sync.Mutex)),
	}
}

func (cq *traceCachedQue) Upsert(key uint64, val model.Trace) error {
	cq.cv.L.Lock()
	defer cq.cv.L.Unlock()

	if item, ok := cq.cache[key]; ok {
		item.Cnt += val.Cnt
		cq.cache[key] = item
		return nil
	}
	if cq.que.Size() >= cq.size {
		return ErrQueIsFull
	}
	cq.cache[key] = val
	cq.que.Enqueue(queData{key: key, val: val})
	cq.cv.Broadcast()
	return nil
}

// Len -
func (cq *traceCachedQue) Len() int {
	cq.cv.L.Lock()
	defer cq.cv.L.Unlock()
	return cq.que.Size() + int(atomic.LoadUint32(&cq.sendPending))
}

// Reader -
func (cq *traceCachedQue) Reader() <-chan model.Trace {
	cq.runOnce.Do(func() {
		cq.stopped = make(chan struct{})
		go cq.run()
	})
	return cq.ch
}

// Enque -
func (cq *traceCachedQue) Enque(vals ...model.Trace) (err error) {
	cq.cv.L.Lock()
	defer func() {
		if len(vals) > 0 && err == nil {
			cq.cv.Broadcast()
		}
		cq.cv.L.Unlock()
	}()
	if cq.que.Size()+len(vals) > cq.size {
		return ErrQueIsFull
	}
	for _, v := range vals {
		cq.que.Enqueue(queData{val: v})
	}
	return nil
}

// Close -
func (cq *traceCachedQue) Close() error {
	cq.runOnce.Do(func() {})
	stopped := cq.stopped
	cv := cq.cv
	cl := cq.close
	ch := cq.ch
	cq.closeOnce.Do(func() {
		const waitBeforeBroadcast = 100 * time.Millisecond
		close(cl)
		defer close(ch)
		cv.L.Lock()
		cq.que.Clear()
		cv.L.Unlock()
		if stopped != nil {
		loop:
			for cv.Broadcast(); ; cv.Broadcast() {
				select {
				case <-stopped:
					break loop
				case <-time.After(waitBeforeBroadcast):
				}
			}
		}
	})
	return nil
}

func (cq *traceCachedQue) run() {
	defer close(cq.stopped)

	for closed := false; !closed; {
		if v, ok := cq.fetch(); !ok {
			break
		} else {
			atomic.StoreUint32(&cq.sendPending, 1)
			select {
			case <-cq.close:
				closed = true
			case cq.ch <- v:
			}
			atomic.StoreUint32(&cq.sendPending, 0)
		}
	}
}

func (cq *traceCachedQue) fetch() (v model.Trace, ok bool) {
	cq.cv.L.Lock()
	defer cq.cv.L.Unlock()
	var (
		data queData
		item any
	)

	que := cq.que
	for que.Size() == 0 {
		cq.cv.Wait()
	}
	if item, ok = que.Dequeue(); ok {
		data = item.(queData)
		v = data.val
		if val, exist := cq.cache[data.key]; exist {
			v = val
			delete(cq.cache, data.key)
		}
	}

	return v, ok
}

var ErrQueIsFull = errors.New("que is full")
