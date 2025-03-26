package nftrace

import "github.com/H-BF/corlib/pkg/patterns/observer"

type (
	CountOverflowQueEvent struct {
		observer.EventType
		Cnt uint64
	}
	CountRcvSampleEvent struct {
		observer.EventType
		Cnt uint64
	}
	CountCollectNlErrMemEvent struct {
		observer.EventType
	}
	CountLostSampleEvent struct {
		observer.EventType
		Cnt uint64
	}
	CountRcvPktEvent struct {
		observer.EventType
		Cnt uint64
	}
)
