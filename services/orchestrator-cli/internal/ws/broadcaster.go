package ws

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ProgressEvent is the real-time telemetry frame fanned out to Web Console clients
// over WebSockets.
type ProgressEvent struct {
	JobID              string          `json:"jobId"`
	Phase              string          `json:"phase"`
	TotalRowsProcessed uint64          `json:"totalRowsProcessed"`
	TotalBytesStreamed uint64          `json:"totalBytesStreamed"`
	RowsPerSecond      float64         `json:"rowsPerSecond"`
	ETASeconds         uint64          `json:"etaSeconds"`
	DurationMs         uint64          `json:"durationMs"`
	WorkerRSSMemoryMB  float64         `json:"workerRssMemoryMb"`
	ActiveChannelDepth uint32          `json:"activeChannelDepth"`
	Tables             []TableProgress `json:"tables"`
	SaltCommitment     string          `json:"saltCommitment,omitempty"`
	CertificateSerial  string          `json:"certificateSerial,omitempty"`
	ErrorDetail        string          `json:"errorDetail,omitempty"`
	EmittedAt          time.Time       `json:"emittedAt"`
}

type TableProgress struct {
	QualifiedName      string `json:"qualifiedName"`
	RowsProcessed      uint64 `json:"rowsProcessed"`
	EstimatedTotalRows uint64 `json:"estimatedTotalRows"`
	DurationMs         uint64 `json:"durationMs"`
	Completed          bool   `json:"completed"`
}

// ProgressBroadcaster maintains per-job WebSocket subscriber pools and a bounded
// replay buffer so late-subscribing browser tabs still receive fast-completing runs.
type ProgressBroadcaster struct {
	mu           sync.RWMutex
	subscribers  map[string]map[chan []byte]struct{}
	history      map[string][][]byte
	historyOrder []string
	upgrader     websocket.Upgrader
	logger       *slog.Logger
}

const (
	maxFramesPerJob   = 64
	maxRetainedJobIDs = 256
)

func NewProgressBroadcaster(logger *slog.Logger) *ProgressBroadcaster {
	return &ProgressBroadcaster{
		subscribers:  make(map[string]map[chan []byte]struct{}),
		history:      make(map[string][][]byte),
		historyOrder: make([]string, 0, maxRetainedJobIDs),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 4096,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		logger: logger,
	}
}

// Publish serializes a ProgressEvent once, appends to the bounded per-job replay
// history, and fans it out non-blockingly to all clients watching jobID.
func (b *ProgressBroadcaster) Publish(event ProgressEvent) {
	if event.EmittedAt.IsZero() {
		event.EmittedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(event)
	if err != nil {
		b.logger.Error("failed to marshal progress event", "job_id", event.JobID, "err", err)
		return
	}

	b.mu.Lock()
	if _, exists := b.history[event.JobID]; !exists {
		b.historyOrder = append(b.historyOrder, event.JobID)
		if len(b.historyOrder) > maxRetainedJobIDs {
			evictID := b.historyOrder[0]
			b.historyOrder = b.historyOrder[1:]
			delete(b.history, evictID)
		}
	}
	hist := append(b.history[event.JobID], payload)
	if len(hist) > maxFramesPerJob {
		hist = hist[len(hist)-maxFramesPerJob:]
	}
	b.history[event.JobID] = hist

	clients := b.subscribers[event.JobID]
	for ch := range clients {
		select {
		case ch <- payload:
		default:
			// Drop frame for slow browser tab to protect pipeline latency.
		}
	}
	b.mu.Unlock()
}

func (b *ProgressBroadcaster) subscribe(jobID string) (chan []byte, [][]byte) {
	ch := make(chan []byte, 64)
	b.mu.Lock()
	if _, ok := b.subscribers[jobID]; !ok {
		b.subscribers[jobID] = make(map[chan []byte]struct{})
	}
	b.subscribers[jobID][ch] = struct{}{}
	replay := append([][]byte(nil), b.history[jobID]...)
	b.mu.Unlock()
	return ch, replay
}

func (b *ProgressBroadcaster) unsubscribe(jobID string, ch chan []byte) {
	b.mu.Lock()
	if clients, ok := b.subscribers[jobID]; ok {
		delete(clients, ch)
		if len(clients) == 0 {
			delete(b.subscribers, jobID)
		}
	}
	b.mu.Unlock()
	close(ch)
}

// ServeWS upgrades HTTP requests at `/ws/jobs/{jobId}` to a live telemetry stream.
func (b *ProgressBroadcaster) ServeWS(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("jobId")
	if jobID == "" {
		http.Error(w, "missing jobId path parameter", http.StatusBadRequest)
		return
	}

	conn, err := b.upgrader.Upgrade(w, r, nil)
	if err != nil {
		b.logger.Warn("websocket upgrade failed", "job_id", jobID, "err", err)
		return
	}
	defer conn.Close()

	ch, replay := b.subscribe(jobID)
	defer b.unsubscribe(jobID, ch)

	// Replay any frames emitted before the browser completed WS handshake.
	for _, frame := range replay {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, frame); err != nil {
			return
		}
	}

	pingTicker := time.NewTicker(25 * time.Second)
	defer pingTicker.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			return
		case <-r.Context().Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-pingTicker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
