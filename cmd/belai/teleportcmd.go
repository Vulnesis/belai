package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	"google.golang.org/grpc/status"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/rc"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/teleport"
	"github.com/vulnetix/belai/internal/trustgate"
	"github.com/vulnetix/belai/internal/tui"
	"github.com/vulnetix/belai/internal/version"
)

// runTeleport continues a session of the account on this host (docs/teleport.md):
// it asks the backend, writes the new session and returns the TUI's options for
// it. workdir is a trusted directory. The session runs there, or in a worktree
// at the commit it was at, which this host trusts because it lies inside a
// repository the user already trusted. A host joined to Keleustes teleports
// through Keleustes instead (runTeleportKeleustes): ref is then a teleport id.
func runTeleport(ctx context.Context, workdir, ref, override string, push bool, providerFlag, modelFlag string, stderr io.Writer) (teleport.Result, *tui.Teleported, error) {
	if _, p := rcKeleustes(); p != nil {
		return runTeleportKeleustes(ctx, p, workdir, ref, override, push, providerFlag, modelFlag, stderr)
	}
	client, err := rcClient(workdir)
	if err != nil {
		return teleport.Result{}, nil, fmt.Errorf("teleport: %w", err)
	}
	dir, err := config.GlobalDir()
	if err != nil {
		return teleport.Result{}, nil, fmt.Errorf("teleport: %w", err)
	}
	hostID, err := sessionsync.HostID(dir)
	if err != nil {
		return teleport.Result{}, nil, fmt.Errorf("teleport: %w", err)
	}
	store, err := session.NewStore()
	if err != nil {
		return teleport.Result{}, nil, fmt.Errorf("teleport: %w", err)
	}
	// The user's agreement that the origin host may push a teleport branch is the
	// flag, or their own teleport.push setting here. The origin host decides for
	// itself by its own setting too (docs/teleport.md).
	if settings, serr := config.LoadMerged(workdir); serr == nil && settings.TeleportPushPolicy() == config.TeleportPushAllow {
		push = true
	}
	res, err := teleport.Run(ctx, teleport.Options{
		Ref:         ref,
		Push:        push,
		RefOverride: override,
		Workdir:     workdir,
		API:         client,
		HostID:      hostID,
		Host:        sessionsync.Host{Hostname: sessionsync.Hostname(), OS: runtime.GOOS, BelaiVersion: version.Version},
		Store:       store,
		Trust:       func(dir string) error { return trustgate.Grant(dir, nil) },
		Progress:    func(s string) { fmt.Fprintln(stderr, "teleport:", s) },
	})
	if err != nil {
		return res, nil, fmt.Errorf("teleport: %w", err)
	}
	return finishTeleport(ctx, res, providerFlag, modelFlag, stderr)
}

// finishTeleport replays the code the forge could not carry before the
// terminal UI opens, so the session starts on the finished checkout. The
// outcome is a notice, never a failure: the teleported session exists either
// way.
func finishTeleport(ctx context.Context, res teleport.Result, providerFlag, modelFlag string, stderr io.Writer) (teleport.Result, *tui.Teleported, error) {
	if res.Replay != nil {
		out := runTeleportReplay(ctx, res.Replay, providerFlag, modelFlag, stderr)
		res.Notices = append(res.Notices, out.Summary)
	}
	return res, &tui.Teleported{OriginID: res.OriginID, SessionID: res.SessionID, Notices: res.Notices}, nil
}

// runTeleportKeleustes is `belai -teleport <teleport-id>` on a host joined to
// Keleustes (docs/teleport.md#keleustes): it downloads the bundle Keleustes
// holds for this node and continues the session exactly as a website teleport
// does. The bundle is another host's content and is checked the same way.
func runTeleportKeleustes(ctx context.Context, p *factorylink.Profile, workdir, ref, override string, push bool, providerFlag, modelFlag string, stderr io.Writer) (teleport.Result, *tui.Teleported, error) {
	if !factorylink.ValidTeleportID(ref) {
		return teleport.Result{}, nil, errors.New("teleport: this host is joined to Keleustes, so -teleport takes the teleport id Keleustes shows (the origin host prints it with -teleport-to)")
	}
	c, err := factorylink.NewClient(p)
	if err != nil {
		return teleport.Result{}, nil, fmt.Errorf("teleport: %w", err)
	}
	defer c.Close()
	store, err := session.NewStore()
	if err != nil {
		return teleport.Result{}, nil, fmt.Errorf("teleport: %w", err)
	}
	say := func(s string) { fmt.Fprintln(stderr, "teleport:", s) }
	if push {
		say("-teleport-push has no effect through Keleustes: the bundle carries the changes, and nothing goes to the forge")
	}
	res, err := teleport.RunBundle(ctx, teleport.Options{
		RefOverride: override,
		Workdir:     workdir,
		Store:       store,
		Trust:       func(dir string) error { return trustgate.Grant(dir, nil) },
		Progress:    say,
	}, func(ctx context.Context) (teleport.Fetched, error) {
		b, err := c.DownloadTeleport(ctx, ref)
		if err != nil {
			return teleport.Fetched{}, fmt.Errorf("keleustes did not hand over teleport %s: %s", sanitize.Ident(ref, 64), keleustesWhy(err))
		}
		return teleport.Fetched{TeleportID: b.TeleportID, SessionID: b.SessionID, Data: b.Data}, nil
	})
	if err != nil {
		return res, nil, fmt.Errorf("teleport: %w", err)
	}
	return finishTeleport(ctx, res, providerFlag, modelFlag, stderr)
}

// runTeleportSend is `belai -teleport <session-id> -teleport-to <node-id>` on
// the origin host: it bundles a session of this host (its lines, its
// repository facts, and its uncommitted and unpushed changes as a replay) and
// uploads it through Keleustes for the named node. The session's directory
// must be one the user trusted, since its working tree is read and its patch
// handed to this host's own model for the hand-over. It returns the teleport
// id the target runs `belai -teleport` with.
func runTeleportSend(ctx context.Context, workdir, ref, toNode string, stderr io.Writer) (string, error) {
	_, p := rcKeleustes()
	if p == nil {
		return "", errors.New("-teleport-to sends a session through Keleustes, and this host has not joined a Keleustes server (run belai connect <token>)")
	}
	c, err := factorylink.NewClient(p)
	if err != nil {
		return "", err
	}
	defer c.Close()
	toNode, err = resolveTeleportNode(ctx, c, toNode)
	if err != nil {
		return "", err
	}
	store, err := session.NewStore()
	if err != nil {
		return "", err
	}
	key, _ := session.KeyFor(workdir)
	_, id, err := store.ResolveAnywhere(key, ref)
	if err != nil {
		return "", err
	}
	say := func(s string) { fmt.Fprintln(stderr, "teleport:", s) }
	say("bundling session " + id[:min(8, len(id))])
	b, _, err := teleport.NewBundle(ctx, teleport.BundleOptions{
		Store: store, SessionID: id,
		Allowed: func(dir string) (string, bool) {
			st, err := trustgate.Check(dir)
			return dir, err == nil && st.Trusted
		},
		Code: func(ctx context.Context, dir string) sessionsync.TeleportCode {
			return rc.KeleustesCode(ctx, nil, dir, rcDistill(dir))
		},
	})
	if err != nil {
		return "", err
	}
	if rc.HarnessSession(b) {
		audit.Emit(audit.Fact{Kind: audit.HostTeleport, ActorKind: audit.ActorHuman, SessionID: id, Outcome: "refused",
			Data: map[string]string{"to": toNode, "via": "keleustes", "reason": rc.HarnessTeleportRefusal}})
		return "", errors.New(rc.HarnessTeleportRefusal)
	}
	needs := rc.TeleportNeeds(b)
	for _, n := range needs {
		say("the target needs " + n.Kind + " " + sanitize.Line(n.Name, 64) + "; Keleustes backs it up from this host")
	}
	if b.Code != nil && b.Code.Mode == sessionsync.CodeReplay {
		say(fmt.Sprintf("the bundle carries %d changed file%s as a replay", len(b.Code.Files), map[bool]string{true: "", false: "s"}[len(b.Code.Files) == 1]))
	} else if b.Code != nil && b.Code.Reason != "" {
		say("no changes travel: " + b.Code.Reason)
	}
	data, err := teleport.EncodeBundle(b)
	if err != nil {
		return "", err
	}
	say(fmt.Sprintf("uploading %d bytes to Keleustes %q for node %s", len(data), p.ServerName, toNode))
	tid, err := c.UploadTeleport(ctx, factorylink.TeleportUpload{SessionID: id, ToNode: toNode, Title: sanitize.Line(b.Title, 300), Needs: needs}, data)
	if err != nil {
		return "", fmt.Errorf("keleustes did not take the bundle: %s", keleustesWhy(err))
	}
	return tid, nil
}

// keleustesWhy is a Keleustes error as the user reads it: the server's own
// message, cleaned.
func keleustesWhy(err error) string {
	if s, ok := status.FromError(err); ok {
		return sanitize.Line(s.Message(), 200)
	}
	return sanitize.Line(err.Error(), 200)
}

// teleportNodeCandidate is a node -teleport-to may name.
type teleportNodeCandidate struct {
	ID, Name string
	Online   bool
}

// teleportCandidates are the Fleet.Nodes rows, cleaned (another host's
// names are Keleustes's content and untrusted).
func teleportCandidates(nodes []*nodev1.NodeSummary, self string) []teleportNodeCandidate {
	var out []teleportNodeCandidate
	for _, n := range nodes {
		id := n.GetNodeId()
		if !factorylink.ValidNodeID(id) || id == self {
			continue
		}
		out = append(out, teleportNodeCandidate{ID: id, Name: sanitize.Line(n.GetName(), 64), Online: n.GetOnline()})
	}
	return out
}

// matchTeleportNode completes a -teleport-to value against the candidates:
// an exact id or name wins; otherwise a unique id or name prefix (case
// folded). It returns the id, or the candidates that fit (all of them when
// none does).
func matchTeleportNode(cands []teleportNodeCandidate, v string) (string, []teleportNodeCandidate) {
	v = strings.TrimSpace(v)
	for _, c := range cands {
		if c.ID == v || strings.EqualFold(c.Name, v) {
			return c.ID, nil
		}
	}
	var fit []teleportNodeCandidate
	lv := strings.ToLower(v)
	for _, c := range cands {
		if lv != "" && (strings.HasPrefix(strings.ToLower(c.ID), lv) || strings.HasPrefix(strings.ToLower(c.Name), lv)) {
			fit = append(fit, c)
		}
	}
	if len(fit) == 1 {
		return fit[0].ID, nil
	}
	if len(fit) == 0 {
		return "", cands
	}
	return "", fit
}

// formatTeleportNodes lists candidates one per line: id, name, online.
func formatTeleportNodes(cands []teleportNodeCandidate) string {
	var b strings.Builder
	for _, c := range cands {
		state := "offline"
		if c.Online {
			state = "online"
		}
		fmt.Fprintf(&b, "  %s  %s  %s\n", c.ID, c.Name, state)
	}
	return b.String()
}

// resolveTeleportNode completes v from Fleet.Nodes (#42). A node id passes
// as is when Keleustes does not share its directory; an unknown or ambiguous
// value is refused with the nodes that fit.
func resolveTeleportNode(ctx context.Context, c *factorylink.Client, v string) (string, error) {
	nodes, err := c.FleetNodes(ctx)
	if err != nil {
		if factorylink.ValidNodeID(v) {
			return v, nil
		}
		return "", fmt.Errorf("-teleport-to: keleustes did not list its nodes: %s", keleustesWhy(err))
	}
	cands := teleportCandidates(nodes, c.NodeID())
	id, fit := matchTeleportNode(cands, v)
	if id != "" {
		return id, nil
	}
	if len(cands) == 0 {
		return "", errors.New("-teleport-to: keleustes lists no other node this host may address")
	}
	what := "no node matches"
	if len(fit) < len(cands) {
		what = "more than one node matches"
	}
	return "", fmt.Errorf("-teleport-to %q: %s; the nodes:\n%s", sanitize.Line(v, 64), what, strings.TrimRight(formatTeleportNodes(fit), "\n"))
}

// runTeleportNodes is `belai -teleport-to ?`: it prints the nodes this host
// may send a session to.
func runTeleportNodes(ctx context.Context, w io.Writer) error {
	_, p := rcKeleustes()
	if p == nil {
		return errors.New("-teleport-to sends a session through Keleustes, and this host has not joined a Keleustes server (run belai connect <token>)")
	}
	c, err := factorylink.NewClient(p)
	if err != nil {
		return err
	}
	defer c.Close()
	nodes, err := c.FleetNodes(ctx)
	if err != nil {
		return fmt.Errorf("keleustes did not list its nodes: %s", keleustesWhy(err))
	}
	cands := teleportCandidates(nodes, c.NodeID())
	if len(cands) == 0 {
		fmt.Fprintln(w, "no other node")
		return nil
	}
	fmt.Fprint(w, formatTeleportNodes(cands))
	return nil
}
