package teleport

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/agentprofile"
	"github.com/vulnetix/belai/internal/forge"
	"github.com/vulnetix/belai/internal/gitinfo"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/version"
)

// A teleport through Keleustes (docs/teleport.md#keleustes) has no website to
// hold the transcript, the git facts and the code while the target reads
// them, so the origin puts them in one bundle: the session's own lines from
// this host's store, its repository facts, and its code as a replay. Keleustes
// stores the bundle and hands it to the target node, which checks and applies
// it with exactly the code a website teleport uses: verify and build for the
// transcript, prepareCode and replayPlan for the code, and the replay with its
// KindTeleport attachment for what git cannot apply. No profile, crew,
// provider, credential or setting travels.

// BundleFormat names the bundle's layout. A bundle of any other format is
// refused.
const BundleFormat = "belai.teleport.v1"

// maxBundleJSON bounds the decompressed bundle: the largest transcript a
// teleport takes, plus the code and headroom. A bundle that inflates past it
// is refused before it is decoded. A variable only so a test can lower it.
var maxBundleJSON = maxTotalBytes + 8<<20

// Bundle is what the origin uploads. Every field is untrusted on the target.
type Bundle struct {
	Format    string `json:"format"`
	SessionID string `json:"sessionId"`
	Title     string `json:"title,omitempty"`
	CreatedAt int64  `json:"createdAt"`
	// Git is the origin's repository facts (the website's originGit shape).
	Git json.RawMessage `json:"git,omitempty"`
	// Entries are the session's lines, seq 0..n-1.
	Entries []sessionsync.Entry `json:"entries"`
	// Code is the session's uncommitted and unpushed changes as a replay, or
	// none with the reason.
	Code *sessionsync.TeleportCode `json:"code,omitempty"`
}

// sessionIDShape is a session id the origin looks up: Belai writes UUIDs.
var sessionIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ErrNotHere is a session this host's store does not hold.
var ErrNotHere = errors.New("that session did not run on this host")

// BundleOptions build an origin's bundle.
type BundleOptions struct {
	Store *session.Store
	// SessionID is the session's full id.
	SessionID string
	// Allowed checks the session's working directory and returns the form to
	// read, or false to refuse (the daemon offers only its own directories).
	// Nil accepts any existing directory.
	Allowed func(dir string) (string, bool)
	// Code reads the directory's changes; nil sends none.
	Code func(ctx context.Context, dir string) sessionsync.TeleportCode
	// Git runs the read-only git calls for the facts (hardened default).
	Git forge.Runner
}

// NewBundle reads the session from this host's store and builds its bundle.
// It returns the directory the session ran in. A session this store does not
// hold is ErrNotHere.
func NewBundle(ctx context.Context, o BundleOptions) (Bundle, string, error) {
	if o.Store == nil {
		return Bundle{}, "", errors.New("no session store")
	}
	if !sessionIDShape.MatchString(o.SessionID) {
		return Bundle{}, "", errors.New("that is not a session id")
	}
	entries, err := findSession(o.Store, o.SessionID)
	if err != nil {
		return Bundle{}, "", err
	}
	if len(entries) == 0 {
		return Bundle{}, "", errors.New("that session has no lines yet")
	}
	if len(entries) > maxEntries {
		return Bundle{}, "", errors.New("the session is longer than a teleport takes")
	}
	meta, _ := session.LatestMeta(entries)
	dir := meta.Cwd
	if dir == "" {
		return Bundle{}, "", errors.New("the session does not record the directory it ran in")
	}
	if o.Allowed != nil {
		d, ok := o.Allowed(dir)
		if !ok {
			return Bundle{}, "", errors.New("this host does not offer the directory that session ran in")
		}
		dir = d
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return Bundle{}, "", errors.New("the directory that session ran in is gone")
	}
	b := Bundle{Format: BundleFormat, SessionID: o.SessionID, Title: session.DisplayName(entries, o.SessionID),
		CreatedAt: time.Now().UnixMilli()}
	for i, e := range entries {
		se := sessionsync.Entry{Seq: int64(i), ID: e.ID, ParentID: e.ParentID, Type: e.Type, Role: e.Role,
			Content: e.Content, Timestamp: e.Timestamp, SubagentID: e.SubagentID}
		if len(e.Meta) > 0 {
			raw, err := json.Marshal(e.Meta)
			if err != nil {
				return Bundle{}, "", fmt.Errorf("line %d: %w", i, err)
			}
			se.Meta = raw
		}
		b.Entries = append(b.Entries, se)
	}
	run := o.Git
	if run == nil {
		run = forge.HardenedGit("", "")
	}
	b.Git = originFacts(ctx, run, dir)
	if o.Code != nil {
		c := o.Code(ctx, dir)
		b.Code = &c
	}
	return b, dir, nil
}

// findSession reads the session with this full id from whichever project of
// the store holds it.
func findSession(store *session.Store, id string) ([]session.Entry, error) {
	keys, err := store.Keys()
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if _, err := os.Stat(store.SessionPath(k, id)); err != nil {
			continue
		}
		return store.ReadFrom(k, id)
	}
	return nil, ErrNotHere
}

// originFacts is the origin's repository facts in the shape the target reads
// (originGit). Facts that cannot be read are left out, which the target
// reports as such.
func originFacts(ctx context.Context, run forge.Runner, dir string) json.RawMessage {
	info, ok := gitinfo.Detect(dir)
	if !ok {
		return nil
	}
	g := originGit{Branch: info.Branch, Detached: info.Detached}
	if r, ok := forge.ParseRemote(gitinfo.OriginURL(info.Root)); ok {
		g.Remote, g.Host = r.Slug(), r.Host
	}
	gctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if out, err := run(gctx, info.Root, "git", "rev-parse", "HEAD"); err == nil {
		g.Head = strings.TrimSpace(string(out))
	}
	if out, err := run(gctx, info.Root, "git", "status", "--porcelain", "--untracked-files=normal"); err == nil {
		g.Dirty = strings.TrimSpace(string(out)) != ""
	}
	raw, _ := json.Marshal(g)
	return raw
}

// EncodeBundle is the bundle's bytes: gzip-compressed JSON.
func EncodeBundle(b Bundle) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeBundle reads a bundle another host made. It bounds what it inflates,
// and refuses any format but BundleFormat; the content is checked by the
// caller exactly as a website teleport's is.
func DecodeBundle(data []byte) (Bundle, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return Bundle{}, errors.New("the teleport bundle is not a Belai bundle")
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, int64(maxBundleJSON)+1))
	if err != nil {
		return Bundle{}, errors.New("the teleport bundle is damaged")
	}
	if len(raw) > maxBundleJSON {
		return Bundle{}, errors.New("the teleport bundle is larger than a teleport takes")
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bundle{}, errors.New("the teleport bundle is not a Belai bundle")
	}
	if b.Format != BundleFormat {
		return Bundle{}, errors.New("the teleport bundle was made by a Belai this one does not understand; update Belai on both hosts")
	}
	return b, nil
}

// Fetched is a bundle Keleustes delivered, with what its header said.
type Fetched struct {
	TeleportID string
	// SessionID is the header's session id, which must be the bundle's own.
	SessionID string
	Data      []byte
}

// RunBundle continues, on this host, the session a Keleustes teleport carries.
// fetch downloads the bundle (after the directory is checked, so a user in the
// wrong place hears it before anything is fetched). The bundle is untrusted
// content from another host: its transcript is verified line by line and
// cleaned, its git facts parsed and shape-checked, and its code turned into a
// replay plan, by the same functions a website teleport uses. Nothing is
// acknowledged: Keleustes records the delivery itself.
func RunBundle(ctx context.Context, o Options, fetch func(ctx context.Context) (Fetched, error)) (res Result, err error) {
	o = o.withDefaults()
	say := o.say
	if o.Store == nil || fetch == nil {
		return res, errors.New("teleport: missing store or bundle")
	}
	newID := o.NewID()
	p := plan{workdir: o.Workdir, override: o.RefOverride, newID: newID, run: o.Git, worktree: o.WorktreesDir, progress: say}
	if err := p.requireRepo(); err != nil {
		return res, err
	}
	say("downloading the teleport from Keleustes")
	f, err := fetch(ctx)
	if err != nil {
		return res, err
	}
	b, err := DecodeBundle(f.Data)
	if err != nil {
		return res, err
	}
	if !sessionIDShape.MatchString(b.SessionID) || (f.SessionID != "" && f.SessionID != b.SessionID) {
		return res, errors.New("the teleport bundle names another session than Keleustes said it carries")
	}
	res.TeleportID, res.OriginID = f.TeleportID, b.SessionID

	var made madeThings
	defer func() {
		if err != nil {
			o.undo(&made, p)
		}
	}()

	say("checking the transcript")
	entries := b.Entries
	if err := verify(entries, int64(len(entries))-1); err != nil {
		return res, err
	}
	og := parseOriginGit(b.Git)
	st := sessionsync.TeleportState{Code: b.Code}
	// asked is true: there is no backend to ask for a replay, so a branch the
	// bundle names that cannot be fetched is a refusal.
	co, rp, err := o.prepareCode(ctx, sessionsync.Teleport{ID: f.TeleportID, OriginSessionID: b.SessionID}, st, p, og, true)
	if err != nil {
		return res, err
	}
	if co.Worktree {
		made.worktree, made.root = co.Dir, co.Root
		say("created a worktree at the commit the session was at")
	}
	res.Notices = append(res.Notices, co.Notices...)
	if rp != nil {
		res.Replay = &Replay{Dir: co.Dir, Plan: *rp}
		say(rp.Notice())
	}

	key, err := session.KeyFor(co.Dir)
	if err != nil {
		return res, err
	}
	built, written, err := build(entries, session.Meta{
		Schema: session.SchemaVersion, Cwd: co.Dir, Version: version.Version, TeleportedFrom: b.SessionID,
	}, func(name string) bool {
		_, err := agentprofile.Load(name)
		return err == nil
	})
	if err != nil {
		return res, err
	}
	if prof := bundleProfile(entries); prof != "" && written.ActiveProfile == "" {
		res.Notices = append(res.Notices, "the agent profile "+sanitize.Line(prof, 60)+" is not installed here, and a teleport through Keleustes carries no profile, so the session continues under the default agent")
	}
	if err := o.Store.Import(key, newID, built); err != nil {
		return res, err
	}
	made.session, made.key = newID, key

	if co.Worktree && o.Trust != nil {
		if err := o.Trust(co.Dir); err != nil {
			return res, fmt.Errorf("trust the worktree: %w", err)
		}
	}
	say("opened session " + newID[:8])
	res.Workdir, res.Key, res.SessionID = co.Dir, key, newID
	return res, nil
}

// bundleProfile is the agent profile the origin session last ran under, read
// from its session_meta lines; only for the notice, and only as a name.
func bundleProfile(entries []sessionsync.Entry) string {
	name := ""
	for _, e := range entries {
		if e.Type != session.EntryTypeSessionMeta {
			continue
		}
		var m struct {
			ActiveProfile string `json:"activeProfile"`
		}
		if json.Unmarshal([]byte(e.Content), &m) == nil && m.ActiveProfile != "" {
			name = m.ActiveProfile
		}
	}
	return sanitize.Ident(name, 64)
}
