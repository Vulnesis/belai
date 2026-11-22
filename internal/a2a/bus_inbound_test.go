package a2a

import (
	"testing"
	"time"
)

// A relay runs in the session's own process: an envelope it delivers must
// reach that process's node, while the node's own sends are not read back.
func TestBusInboundReachesThisProcess(t *testing.T) {
	b, err := OpenBus(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	own := Envelope{MessageID: NewMessageID(time.Now()), Kind: KindBroadcast, TS: time.Now().UnixMilli(),
		Agent: AgentCard{ID: "h1:s1", HostID: "h1", SessionID: "s1"}}
	if _, err := b.Append(own); err != nil {
		t.Fatal(err)
	}
	in := Envelope{MessageID: NewMessageID(time.Now()), Kind: KindMessage, TS: time.Now().UnixMilli(), To: "h1:s1",
		Agent: AgentCard{ID: "h2:s2", HostID: "h2", SessionID: "s2"}, Parts: []Part{{Text: "hi"}}}
	if ok, err := b.Inbound(in); !ok || err != nil {
		t.Fatal(ok, err)
	}
	got, err := b.Poll()
	if err != nil || len(got) != 1 || got[0].MessageID != in.MessageID {
		t.Fatalf("%+v %v", got, err)
	}
	if again, _ := b.Inbound(in); again {
		t.Fatal("a duplicate was appended")
	}
}
