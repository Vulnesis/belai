package rc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/vulnetix/belai/internal/agentprofile"
	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/libinstall"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/teleport"
)

// A Keleustes `teleport` job (docs/teleport.md#keleustes) asks this host, the
// origin of a session, to bundle it for another node: Keleustes has no copy of
// the code and no website to coordinate through, so the origin uploads the
// session's lines from its own store, its repository facts and its changes as
// a replay, with Teleport.Upload under the teleport id the job names.
//
// The payload carries identifiers only. The session must be in this host's
// store and must have run in a directory this daemon offers, exactly the rule
// a website teleport_code request follows; the host reads its own working
// tree and decides for itself what may leave (internal/teleport/changes).
// Nothing is pushed to the forge: the bundle carries the patch.

// teleportJob is a checked teleport job payload.
type teleportJob struct {
	TeleportID string `json:"teleportId"`
	SessionID  string `json:"sessionId"`
	ToNode     string `json:"toNode"`
}

// parseTeleportJob reads a teleport job's payload and checks every field's
// shape. It returns the refusal reason when one does not fit.
func parseTeleportJob(payload string) (teleportJob, string) {
	var p struct {
		Task string `json:"task"`
		teleportJob
	}
	if len(payload) > 4<<10 || json.Unmarshal([]byte(payload), &p) != nil {
		return teleportJob{}, "the teleport job's payload is not a JSON object"
	}
	if p.Task != "teleport_upload" {
		return teleportJob{}, "this Belai does not run that teleport task; update Belai on the host"
	}
	switch {
	case !factorylink.ValidTeleportID(p.TeleportID):
		return teleportJob{}, "the teleport job names no teleport"
	case sanitize.Ident(p.SessionID, 64) != p.SessionID || p.SessionID == "":
		return teleportJob{}, "the teleport job names no session"
	case !factorylink.ValidNodeID(p.ToNode):
		return teleportJob{}, "the teleport job names no target node"
	}
	return p.teleportJob, ""
}

// teleportUpload answers a teleport job: it bundles the session and uploads
// it. A session this host does not hold, or one in a directory it does not
// offer, is refused; a bundle Keleustes would not take fails the job.
func (d *Daemon) teleportUpload(ctx context.Context, req teleportJob) (json.RawMessage, string, error) {
	store := d.o.Sessions
	if store == nil {
		s, err := session.NewStore()
		if err != nil {
			return nil, "", err
		}
		store = s
	}
	b, _, err := teleport.NewBundle(ctx, teleport.BundleOptions{
		Store: store, SessionID: req.SessionID,
		Allowed: func(cwd string) (string, bool) { return Allowed(d.dirs(), cwd) },
		Code: func(ctx context.Context, dir string) sessionsync.TeleportCode {
			cctx, cancel := context.WithTimeout(ctx, teleportCodeTimeout)
			defer cancel()
			return KeleustesCode(cctx, d.o.TeleportGit, dir, d.o.Distill)
		},
	})
	switch {
	case errors.Is(err, teleport.ErrNotHere):
		return nil, "that session did not run on this host", nil
	case err != nil:
		return nil, sanitize.Line(err.Error(), 200), nil
	}
	if HarnessSession(b) {
		audit.Emit(audit.Fact{Kind: audit.HostTeleport, ActorKind: audit.ActorWeb, SessionID: req.SessionID, Outcome: "refused",
			Data: map[string]string{"teleport": req.TeleportID, "to": req.ToNode, "via": "keleustes", "reason": HarnessTeleportRefusal}})
		return nil, HarnessTeleportRefusal, nil
	}
	data, err := teleport.EncodeBundle(b)
	if err != nil {
		return nil, "", err
	}
	if len(data) > factorylink.TeleportMaxBytes {
		return nil, "the session's bundle is larger than Keleustes takes", nil
	}
	id, err := d.o.Factory.UploadTeleport(ctx, factorylink.TeleportUpload{
		TeleportID: req.TeleportID, SessionID: req.SessionID, ToNode: req.ToNode, Title: sanitize.Line(b.Title, 300),
		Needs: TeleportNeeds(b),
	}, data)
	if err != nil {
		return nil, "", fmt.Errorf("keleustes did not take the bundle: %s", sanitize.Line(err.Error(), 200))
	}
	mode := sessionsync.CodeNone
	if b.Code != nil {
		mode = b.Code.Mode
	}
	d.logf("teleport: sent session %s to node %s as teleport %s (%d bytes, changes as %s)",
		short(req.SessionID), sanitize.Ident(req.ToNode, 64), short(id), len(data), mode)
	audit.Emit(audit.Fact{Kind: audit.HostTeleport, ActorKind: audit.ActorWeb, SessionID: req.SessionID, Outcome: "uploaded",
		Data: map[string]string{"teleport": id, "to": req.ToNode, "via": "keleustes"}})
	out, err := json.Marshal(map[string]any{"teleportId": id, "size": len(data), "code": mode, "lines": len(b.Entries)})
	return out, "", err
}

// HarnessTeleportRefusal is why a third-party harness session never
// teleports (keleustes docs/gaps/harnesses.md C4.7): its transcript and state
// live in the harness's own files, which a bundle does not carry. Keleustes
// refuses with the same words.
const HarnessTeleportRefusal = "a third-party harness session cannot be teleported: its transcript and state live in the harness's own files on its host"

// HarnessSession reports whether a bundle's session ran a third-party
// harness: a line the harness runner wrote carries the "harness" meta key.
func HarnessSession(b teleport.Bundle) bool {
	for _, e := range b.Entries {
		if len(e.Meta) == 0 {
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(e.Meta, &m) == nil {
			if _, ok := m["harness"]; ok {
				return true
			}
		}
	}
	return false
}

// TeleportNeeds are the profile and crews a bundle's session needs on the
// target (docs/teleport.md step 5): the session's last active agent profile
// when it is not a built-in, and every stored crew that lists it. Names only;
// Keleustes backs them up from this host and resolves them in its library.
func TeleportNeeds(b teleport.Bundle) []factorylink.TeleportNeed {
	profile := ""
	for i := len(b.Entries) - 1; i >= 0; i-- {
		e := b.Entries[i]
		if e.Type != session.EntryTypeSessionMeta {
			continue
		}
		var m session.Meta
		if json.Unmarshal([]byte(e.Content), &m) == nil && m.ActiveProfile != "" {
			profile = m.ActiveProfile
			break
		}
	}
	return needsFor(profile, agentprofile.StoredCrews())
}

// needsFor is TeleportNeeds for a profile and the host's crews.
func needsFor(profile string, crews []agentprofile.Crew) []factorylink.TeleportNeed {
	if profile == "" || agentprofile.IsBuiltin(profile) {
		return nil
	}
	out := []factorylink.TeleportNeed{{Kind: "profile", Name: profile}}
	for _, c := range crews {
		if crewLists(c, profile) && !agentprofile.IsBuiltin(c.Name) {
			out = append(out, factorylink.TeleportNeed{Kind: "crew", Name: c.Name})
		}
	}
	return factorylink.CleanTeleportNeeds(out)
}

// TeleportFetcher reads one document a teleport needs
// (factorylink.Client.LibraryFetchTeleport).
type TeleportFetcher func(ctx context.Context, teleportID string, ref *nodev1.LibraryRef) (*nodev1.LibraryDoc, error)

// InstallTeleportNeeds puts on this host, the teleport's target, the
// profiles and crews the session needs that it lacks (docs/teleport.md step
// 5): each one is fetched from Keleustes with Library.Fetch(teleport id) and
// validated as its kind exactly as a library_install dispatch validates it,
// profiles before crews so a crew's members exist. A need this host already
// holds is left as it is (never overwritten), and one the library lacks (no
// id in the header) is only named. Every outcome is audited; the notices are
// for the user, one per need.
func InstallTeleportNeeds(ctx context.Context, fetch TeleportFetcher, teleportID string, needs []factorylink.TeleportNeed) []string {
	needs = factorylink.CleanTeleportNeeds(needs)
	sort.SliceStable(needs, func(a, b int) bool { return needs[a].Kind == "profile" && needs[b].Kind != "profile" })
	ctx, cancel := context.WithTimeout(ctx, libraryTimeout)
	defer cancel()
	var notes []string
	for _, n := range needs {
		what := n.Kind + " " + sanitize.Line(n.Name, 64)
		status, why := installTeleportNeed(ctx, fetch, teleportID, n)
		audit.Emit(audit.Fact{Kind: audit.HostTeleport, ActorKind: audit.ActorWeb, ItemID: sanitize.Ident(teleportID, 64), Outcome: "need_" + status,
			Data: map[string]string{"kind": n.Kind, "profile": sanitize.Line(n.Name, 64), "status": status, "reason": why}})
		switch status {
		case "present":
			notes = append(notes, what+" is already on this host")
		case "missing":
			notes = append(notes, what+" is not in the Keleustes library; the session runs without it")
		case "installed":
			notes = append(notes, why)
		default:
			notes = append(notes, what+" was not installed: "+why)
		}
	}
	return notes
}

// installTeleportNeed is one need: its status ("present", "missing",
// "installed", "refused") and, when installed, what was done, otherwise why
// not.
func installTeleportNeed(ctx context.Context, fetch TeleportFetcher, teleportID string, n factorylink.TeleportNeed) (string, string) {
	if n.Kind == "profile" {
		if _, err := agentprofile.Load(n.Name); err == nil {
			return "present", ""
		}
	} else if _, err := agentprofile.LoadCrew(n.Name); err == nil {
		return "present", ""
	}
	if n.ID == "" {
		return "missing", ""
	}
	doc, err := fetch(ctx, teleportID, &nodev1.LibraryRef{Kind: n.Kind, Id: n.ID, Name: n.Name, Version: n.Version})
	if err != nil {
		return "refused", "could not read it from Keleustes: " + reason(err.Error())
	}
	if want := n.SHA256; want != "" && doc.GetRef().GetSha256() != "" && !strings.EqualFold(doc.GetRef().GetSha256(), want) {
		return "refused", "it is not the version the teleport named"
	}
	var what, why string
	if n.Kind == "profile" {
		what, why = installProfileDoc(doc, false, teleportID)
	} else {
		what, why = installCrewDoc(libinstall.Installer{}, doc.GetDoc(), n.Name, false)
	}
	if why != "" {
		return "refused", why
	}
	return "installed", what
}
