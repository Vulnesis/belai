package rc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/vulnetix/belai/internal/agentprofile"
	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/knowledge"
	"github.com/vulnetix/belai/internal/sanitize"
)

// The knowledge index across hosts (keleustes belai-counterparts row 49).
//
//   - Dispatch "knowledge_reindex": options scope ("profile" or "project") and
//     key (a stored profile's id) or root (a directory this daemon offers).
//     The host re-runs its own ingestion, `belai agent knowledge -index -json`,
//     which admits every new chunk through the security classifier exactly as
//     the agent's own indexing does, then advertises its catalogue again.
//   - Job "knowledge_search": a KnowledgeSearchRequest answered from the
//     indexes on disk, read only, with no model call. Every chunk in an index
//     was classified when it was ingested (AGENTS.md, Knowledge), so a hit's
//     passage rides back as one cleaned line, as Grep's kb+ rows do.

// jobKindKnowledgeSearch is the job kind of a knowledge search.
const jobKindKnowledgeSearch = "knowledge_search"

// Search bounds.
const (
	maxKnowledgeQuery   = 512
	maxKnowledgeHits    = 50
	defKnowledgeHits    = 10
	maxKnowledgeSnippet = 320
)

// knowledgeReindexKeys are the options a knowledge_reindex dispatch carries.
var knowledgeReindexKeys = []string{"scope", "key", "root"}

// dispatchOptions are the options checkFactoryOptions holds a dispatch to:
// a knowledge_reindex's own keys are its parameters, not session settings,
// and are checked by factoryReindex instead.
func dispatchOptions(fd *nodev1.Dispatch) map[string]string {
	opts := fd.GetOptions()
	if fd.GetKind() != "knowledge_reindex" {
		return opts
	}
	out := map[string]string{}
	for k, v := range opts {
		if !slices.Contains(knowledgeReindexKeys, k) {
			out[k] = v
		}
	}
	return out
}

// reindexTarget is a checked knowledge_reindex.
type reindexTarget struct {
	scope, profile, root string
}

// parseReindex checks a knowledge_reindex against what this host has.
func (d *Daemon) parseReindex(fd *nodev1.Dispatch) (reindexTarget, string) {
	opts := fd.GetOptions()
	t := reindexTarget{scope: opts["scope"]}
	switch t.scope {
	case knowledge.ScopeProfile:
		key := opts["key"]
		if !agentprofile.ValidID(key) {
			return t, "a profile reindex names a profile id"
		}
		list, _ := agentprofile.List()
		for _, p := range list {
			if p.ID == key && !p.Builtin {
				t.profile = p.Name
			}
		}
		if t.profile == "" {
			return t, "this host has no stored profile with that id"
		}
		for _, offered := range d.dirs() {
			if offered.Source == SourceTrusted {
				t.root = offered.Path
				break
			}
		}
		if t.root == "" {
			return t, "this host offers no trusted directory to index from"
		}
	case knowledge.ScopeProject:
		// root names an offered directory; key its project key (the id part
		// of the advertised "knowledge" inventory row).
		root, key := opts["root"], opts["key"]
		for _, offered := range d.dirs() {
			if root != "" && offered.Path == root {
				t.root = offered.Path
			}
			if root == "" && key != "" {
				if pk, err := knowledge.ProjectKey(offered.Path); err == nil && pk == key {
					t.root = offered.Path
				}
			}
		}
		if t.root == "" {
			return t, "that directory is not one this host offers"
		}
	default:
		return t, `a knowledge reindex names the scope "profile" or "project"`
	}
	return t, ""
}

// factoryReindex runs a knowledge_reindex. It returns factoryStart's values.
func (d *Daemon) factoryReindex(ctx context.Context, fd *nodev1.Dispatch) (sid, report, why string, failed bool) {
	t, why := d.parseReindex(fd)
	if why != "" {
		return "", "", why, false
	}
	ictx, cancel := context.WithTimeout(ctx, indexTimeout)
	defer cancel()
	var out string
	var err error
	if t.scope == knowledge.ScopeProfile {
		out, err = d.o.Index(ictx, d.o.Exe, t.root, t.profile)
	} else {
		out, err = d.o.IndexProject(ictx, d.o.Exe, t.root)
	}
	status := "ok"
	if err != nil {
		status = "failed"
	}
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorWeb,
		Data: map[string]string{"dispatch": "knowledge_reindex", "scope": t.scope, "status": status, "via": "keleustes"}})
	if err != nil {
		return "", "", "could not reindex (" + reason(err.Error()) + ")", true
	}
	// The catalogue changed: advertise it again.
	d.kickAdvert()
	report = "reindexed the " + t.scope + " knowledge" + out
	d.logf("keleustes %s", report)
	return "", report, "", false
}

// runProjectIndex indexes the project rooted at root by running
// `belai agent knowledge -index -json` there; that command does the trust
// check and runs each chunk through the security classifier. The clause it
// returns carries a count only.
func runProjectIndex(ctx context.Context, exe, root string) (string, error) {
	cmd := exec.CommandContext(ctx, exe, "agent", "knowledge", "-index", "-json")
	cmd.Dir = root
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		text := strings.TrimSpace(errOut.String())
		if text == "" {
			text = err.Error()
		}
		return "", startError(clip(text))
	}
	var rep struct {
		Indexes []struct {
			Documents []json.RawMessage `json:"documents"`
		} `json:"indexes"`
	}
	n := 0
	if json.Unmarshal(out.Bytes(), &rep) == nil {
		for _, ix := range rep.Indexes {
			n += len(ix.Documents)
		}
	}
	return " (" + strconv.Itoa(n) + " document" + plural(n, "", "s") + ")", nil
}

// kickAdvert asks the link to send the advert again (non-blocking).
func (d *Daemon) kickAdvert() {
	select {
	case d.readvertCh() <- struct{}{}:
	default:
	}
}

// readvertCh is the channel runFactory hands the link as RCHooks.Readvert.
func (d *Daemon) readvertCh() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.readvert == nil {
		d.readvert = make(chan struct{}, 1)
	}
	return d.readvert
}

// parseKnowledgeSearch reads a knowledge_search payload (proto3 JSON).
func parseKnowledgeSearch(payload string) (*nodev1.KnowledgeSearchRequest, string) {
	if len(payload) > 8<<10 {
		return nil, "the search is too large"
	}
	var req nodev1.KnowledgeSearchRequest
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal([]byte(payload), &req); err != nil {
		return nil, "the search is not a KnowledgeSearchRequest"
	}
	req.Query = sanitize.Line(req.GetQuery(), maxKnowledgeQuery)
	if strings.TrimSpace(req.Query) == "" {
		return nil, "the search has no query"
	}
	switch req.GetScope() {
	case "", knowledge.ScopeProfile, knowledge.ScopeProject:
	default:
		return nil, `a search scope is "", "profile" or "project"`
	}
	if k := req.GetKey(); len(k) > 512 || sanitize.Line(k, 512) != k {
		return nil, "the search key is not a key"
	}
	switch l := req.GetLimit(); {
	case l == 0:
		req.Limit = defKnowledgeHits
	case l > maxKnowledgeHits:
		req.Limit = maxKnowledgeHits
	}
	return &req, ""
}

// knowledgeIndexes are the indexes a search reads: the stored profiles' and
// the offered directories', narrowed to scope and key.
func (d *Daemon) knowledgeIndexes(scope, key string) []knowledge.IndexInfo {
	var out []knowledge.IndexInfo
	if scope == "" || scope == knowledge.ScopeProfile {
		if list, err := agentprofile.List(); err == nil {
			for _, p := range list {
				if p.Builtin || !agentprofile.ValidID(p.ID) || (key != "" && key != p.ID) {
					continue
				}
				if info := knowledge.LoadProfile(p.ID, p.Name); info.Err == nil && info.Index != nil {
					out = append(out, info)
				}
			}
		}
	}
	if scope == "" || scope == knowledge.ScopeProject {
		for _, dir := range d.dirs() {
			if key != "" && key != dir.Path {
				if pk, err := knowledge.ProjectKey(dir.Path); err != nil || pk != key {
					continue
				}
			}
			if info := knowledge.LoadProject(dir.Path); info.Err == nil && info.Index != nil {
				out = append(out, info)
			}
		}
	}
	return out
}

// knowledgeSearch answers a knowledge_search job from this host's indexes.
func (d *Daemon) knowledgeSearch(req *nodev1.KnowledgeSearchRequest) (json.RawMessage, string, error) {
	res := &nodev1.KnowledgeSearchResult{}
	limit := int(req.GetLimit())
	for _, info := range d.knowledgeIndexes(req.GetScope(), req.GetKey()) {
		shas := map[string]string{}
		for _, doc := range info.Index.Docs() {
			shas[doc.Address] = doc.SHA
		}
		label := info.Scope + ":" + info.Key
		if info.Scope == knowledge.ScopeProject && info.Root != "" {
			label = info.Scope + ":" + info.Root
		}
		for _, h := range info.Index.Search(req.GetQuery(), limit) {
			if h.Label || !knowledge.IsAddress(h.Address) {
				continue
			}
			sha := shas[h.Address]
			if !knowledgeSHARE.MatchString(sha) {
				sum := sha256.Sum256([]byte(h.Text))
				sha = hex.EncodeToString(sum[:])
			}
			res.Hits = append(res.Hits, &nodev1.KnowledgeHit{Address: sanitize.Line(h.Address, 512),
				Index: sanitize.Line(label, 600), Score: h.Score, Snippet: snippet(h.Text), Sha256: sha})
		}
	}
	sortHits(res.Hits)
	if len(res.Hits) > limit {
		res.Hits, res.Partial = res.Hits[:limit], true
	}
	out, err := protojson.Marshal(res)
	if err != nil {
		return nil, "", errors.New("the result could not be encoded")
	}
	return out, "", nil
}

// snippet is a passage as one cleaned line of at most maxKnowledgeSnippet bytes.
func snippet(s string) string {
	s = sanitize.Line(s, maxKnowledgeSnippet)
	for len(s) > maxKnowledgeSnippet {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}

// sortHits orders hits best first, then by address.
func sortHits(h []*nodev1.KnowledgeHit) {
	sort.SliceStable(h, func(i, j int) bool {
		if h[i].Score != h[j].Score {
			return h[i].Score > h[j].Score
		}
		return h[i].Address < h[j].Address
	})
}

// runKnowledgeSearchJob is the job's runner; parse errors are refusals.
func (d *Daemon) runKnowledgeSearchJob(payload string) (func(context.Context) (json.RawMessage, string, error), string) {
	req, why := parseKnowledgeSearch(payload)
	if why != "" {
		return nil, why
	}
	return func(context.Context) (json.RawMessage, string, error) { return d.knowledgeSearch(req) }, ""
}
