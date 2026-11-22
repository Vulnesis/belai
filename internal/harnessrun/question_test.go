package harnessrun

import (
	"bufio"
	"os"
	"testing"

	"github.com/vulnetix/belai/internal/agentstore"
)

// lastReply is the final assistant text of a recorded native transcript and
// whether the transcript marks the turn's end, read through the same pick
// functions the tail uses.
func lastReply(t *testing.T, f agentstore.Format, path string) (string, bool) {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	var reply string
	end := false
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		r, ok := agentstore.PickLine(f, sc.Bytes())
		if !ok {
			continue
		}
		if r.Role == "assistant" && r.Text != "" {
			reply = r.Text
		}
		end = end || r.TurnEnd
	}
	return reply, end
}

func TestQuestionFromRecordedTranscripts(t *testing.T) {
	for _, c := range []struct {
		f    agentstore.Format
		path string
		want string
	}{
		{agentstore.FormatJSONLClaude, "testdata/claude-question.jsonl", "Should I merge them into one, or keep both and only sort the keys?"},
		{agentstore.FormatJSONLCodex, "testdata/codex-question.jsonl", "Which would you prefer?"},
	} {
		reply, end := lastReply(t, c.f, c.path)
		if !end {
			t.Fatalf("%s: no turn end", c.path)
		}
		if got := replyQuestion(reply); got != c.want {
			t.Errorf("%s: %q", c.path, got)
		}
	}
}

func TestReplyQuestionIsConservative(t *testing.T) {
	for _, s := range []string{
		"Done. I created hello.txt.",
		"Should I also add tests? I went ahead and added them.\n\nAll tests pass.",
		"```go\nif x == nil { // why?\n```",
		"",
		"Here is the plan:\n- step one\n- step two",
	} {
		if q := replyQuestion(s); q != "" {
			t.Errorf("%q read as a question: %q", s, q)
		}
	}
	for _, s := range []string{
		"I found two options.\n\nWould you like me to apply the first one (A), or the second?",
		"Do you want me to push the branch?",
		"Let me know which file to start with?",
	} {
		if q := replyQuestion(s); q == "" {
			t.Errorf("%q not read as a question", s)
		}
	}
}
