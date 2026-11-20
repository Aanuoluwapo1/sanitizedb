package ws

import (
	"fmt"
	"io"
	"log/slog"
	"testing"
)

func TestProgressBroadcasterBoundedHistoryAndReplay(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := NewProgressBroadcaster(logger)

	// Publish more than maxRetainedJobIDs to verify FIFO eviction
	for i := 0; i < maxRetainedJobIDs+10; i++ {
		b.Publish(ProgressEvent{
			JobID: fmt.Sprintf("job-%d", i),
			Phase: "COMPLETED",
		})
	}

	b.mu.RLock()
	retained := len(b.history)
	b.mu.RUnlock()
	if retained != maxRetainedJobIDs {
		t.Fatalf("expected %d retained jobs, got %d", maxRetainedJobIDs, retained)
	}

	// Verify late subscriber receives replayed frames
	latestJob := fmt.Sprintf("job-%d", maxRetainedJobIDs+9)
	ch, replay := b.subscribe(latestJob)
	defer b.unsubscribe(latestJob, ch)

	if len(replay) != 1 {
		t.Fatalf("expected 1 replay frame for %s, got %d", latestJob, len(replay))
	}
}
