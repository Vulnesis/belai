package analytics

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRecorderWritesToSQLite(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, DriverSQLite, filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	rec := NewRecorder(st, Options{BatchSize: 2, FlushInterval: 10 * time.Millisecond})
	for i := range 5 {
		rec.Record(Record{Time: time.Now(), Route: "chat", Model: "Qwen/Qwen3 <b>", Status: 200, PromptTok: int64(i)})
	}
	db := st.DB()
	var n int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := db.QueryRow(`SELECT COUNT(*) FROM broker_requests`).Scan(&n); err == nil && n == 5 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n != 5 {
		t.Fatalf("rows = %d", n)
	}
	var model string
	if err := db.QueryRow(`SELECT model FROM broker_requests LIMIT 1`).Scan(&model); err != nil || model != "Qwen/Qwen3b" {
		t.Fatalf("model = %q %v", model, err)
	}
	if err := rec.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

type blockingStore struct {
	release chan struct{}
}

func (b *blockingStore) Insert(ctx context.Context, _ []Record) error {
	<-b.release
	return nil
}
func (b *blockingStore) Close() error { return nil }

// A stuck database must never slow Record: rows past the buffer are dropped.
func TestRecordNeverBlocks(t *testing.T) {
	bs := &blockingStore{release: make(chan struct{})}
	rec := NewRecorder(bs, Options{Buffer: 4, BatchSize: 1, FlushInterval: time.Hour})
	start := time.Now()
	for range 1000 {
		rec.Record(Record{})
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("Record blocked")
	}
	if _, dropped, _ := rec.Stats(); dropped == 0 {
		t.Fatal("expected drops")
	}
	close(bs.release)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rec.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
