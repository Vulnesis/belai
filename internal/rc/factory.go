package rc

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/fleet"
	"github.com/vulnetix/belai/internal/proc"
	"github.com/vulnetix/belai/internal/repomemory"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/sessionctl"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/vaultenv"
)

// Factory is a Keleustes server (the desktop Software Factory) the daemon
// takes dispatches from instead of the Vulnetix website. *factorylink.RC is
// the real one. See docs/keleustes.md#remote-control.
type Factory interface {
	// Name is the server's name, for the log.
	Name() string
	// Serve owns the host's node link until ctx ends.
	Serve(ctx context.Context, h factorylink.RCHooks) error
	// Complete reports a dispatch's outcome (job_id = dispatch id).
	Complete(ctx context.Context, r *nodev1.JobResult) error
	// UploadTeleport uploads a session bundle with Teleport.Upload and
	// returns the teleport id it was stored under (factoryteleport.go).
	UploadTeleport(ctx context.Context, u factorylink.TeleportUpload, data []byte) (string, error)
	// Attention asks the Keleustes owner for something (factoryattention.go)
	// and returns the request id.
	Attention(ctx context.Context, kind, reason, subject string) (string, error)
	// LibraryFetch and LibraryBackup move library documents for a
	// library_install or library_backup dispatch (factorylibrary.go).
	LibraryFetch(ctx context.Context, dispatchID string, ref *nodev1.LibraryRef) (*nodev1.LibraryDoc, error)
	LibraryBackup(ctx context.Context, doc *nodev1.LibraryDoc) (*nodev1.LibraryRef, error)
	// FileForge files a worker's forge request (forgerelay.go); a request
	// Keleustes will never take is factorylink.ErrForgeRefused.
	FileForge(ctx context.Context, r sessionsync.ForgeRequest) (bool, error)
	// LibraryScanReport sends a library_scan's findings (factorylibrary.go).
	LibraryScanReport(ctx context.Context, r *nodev1.LibraryScanReport) error
}

// Job outcomes Keleustes reads.
const (
	jobOK      = "ok"
	jobFailed  = "failed"
	jobRefused = "refused"
)

// completeRetries is how often an outcome is retried before it is dropped.
var completeRetries = []time.Duration{time.Second, 5 * time.Second, 30 * time.Second}

// runFactory serves Keleustes until ctx ends: the node link (with the
// daemon advertised as remote control) and each dispatch it delivers.
// Nothing of the website runs: no registration, heartbeat, library sync or
// credential watch, and no Vulnetix login is needed. The local scheduler,
// the audit stream, memory replication and the library reconcile (by
// hashes, autosync.go) run against Keleustes.
func (d *Daemon) runFactory(ctx context.Context) error {
	f := d.o.Factory
	d.writeRecord()
	audit.Emit(audit.Fact{Kind: audit.HostRCOnline, ActorKind: audit.ActorHarness,
		Data: map[string]string{"version": d.o.Host.BelaiVersion}})
	d.logf("remote control on · Keleustes %q · %d director%s offered · up to %d sessions",
		f.Name(), len(d.dirs()), plural(len(d.dirs()), "y", "ies"), d.o.Max)
	go proc.ReapOrphans(ctx, 10*time.Second, d.logf)
	// The daemon's own loops run in factory mode too (WP-C): its audit
	// stream and the shared memory go to Keleustes, and local schedules keep
	// firing (which also re-adopts crew runs).
	if dir, err := config.GlobalDir(); err == nil {
		if a, err := factorylink.ActiveAudit(dir); err == nil {
			if s := sessionsync.StartAuditOn(context.Background(), a, d.o.HostID, d.o.Host, dir); s != nil {
				defer s.Close(5 * time.Second)
			}
			defer a.Close()
		}
		if m, err := factorylink.ActiveMemory(dir); err == nil {
			repl := sessionsync.NewMemoryReplicator(m, d.o.HostID, repomemory.Root(dir))
			repl.UseStateFile(m.StateName())
			repl.Start(ctx)
			defer m.Close()
		}
	}
	if d.o.Schedules != nil {
		d.wg.Add(1)
		go d.scheduler(ctx)
	}
	// Third-party harnesses: detected now and kept current; a change is
	// advertised again at once.
	readvert := d.readvertCh()
	// The forge relay files spooled worker requests with Keleustes (WP-H).
	d.wg.Add(1)
	go d.forgeRelay(ctx)
	// The automatic library sync, by hashes (WP-E, autosync.go).
	if rec, ok := f.(libraryReconciler); ok {
		d.wg.Add(1)
		go d.factoryReconcileLoop(ctx, rec)
	}
	if d.o.HarnessDetect {
		go d.watchHarnesses(ctx, func() {
			select {
			case readvert <- struct{}{}:
			default:
			}
		})
	}
	if d.o.HostManage != nil {
		go d.o.HostManage(ctx, d.hostHooks())
	}
	go proc.ReapOrphans(ctx, 10*time.Second, d.logf)
	go func() {
		// The record's beat says the daemon is alive.
		t := time.NewTicker(d.o.HeartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				d.writeRecord()
			}
		}
	}()
	var last factorylink.State
	err := f.Serve(ctx, factorylink.RCHooks{
		Advert:    d.factoryAdvert,
		Dispatch:  d.handleFactory,
		Job:       d.handleFactoryJob,
		Control:   d.setFactoryControl,
		Attention: d.factoryDecided,
		Readvert:  readvert,
		Status: func() *nodev1.HostStatus {
			inv := d.o.Inventory()
			return d.withPlanLimits(factorylink.HostStatusOf(d.running(), inv.Workers, inv.Runs))
		},
		State: func(st factorylink.NodeStatus) {
			online := st.Owner && st.State == factorylink.StateOnline
			var why error
			switch {
			case online:
			case !st.Owner && st.OwnerPID > 0:
				why = fmt.Errorf("waiting for belai (pid %d) to hand over the Keleustes link", st.OwnerPID)
			case st.LastError != "":
				why = fmt.Errorf("%s", st.LastError)
			case st.State == factorylink.StateRevoked:
				why = fmt.Errorf("this node was revoked by Keleustes: %s", st.RevokedWhy)
			default:
				why = fmt.Errorf("keleustes link %s", st.State)
			}
			d.setOnline(why)
			if st.State != last {
				last = st.State
				if why != nil {
					d.logf("keleustes: %v", why)
				} else {
					d.logf("keleustes: online at %s", st.Addr)
				}
			}
			d.writeRecord()
		},
	})
	d.shutdown()
	return err
}

// factoryAdvert is the daemon's part of the host advert.
func (d *Daemon) factoryAdvert() factorylink.HostOptions {
	o := factorylink.HostOptions{RemoteControl: true, MaxSessions: d.o.Max,
		DispatchKinds: factoryDispatchKinds, JobKinds: factoryJobKinds, DispatchFeatures: factoryDispatchFeatures,
		CanClone: d.canClone()}
	for _, dir := range d.dirs() {
		o.TrustedDirs = append(o.TrustedDirs, dir.Path)
	}
	if m := d.o.Models(); m != nil {
		for _, p := range m.Providers {
			o.Providers = append(o.Providers, p.Name)
			o.Models = append(o.Models, &nodev1.ProviderModels{Provider: p.Name, Models: p.Models})
		}
	}
	inv := d.o.Inventory()
	for _, a := range inv.Agents {
		o.Agents = append(o.Agents, a.Name)
	}
	for _, c := range inv.Crews {
		o.Crews = append(o.Crews, c.Name)
	}
	for _, p := range inv.Profiles {
		o.Routes = append(o.Routes, &nodev1.AgentRoute{Name: p.Name, Mode: "worker", Lists: p.Lists, Labels: p.Labels})
	}
	o.Harnesses, o.HarnessSessions = harnessAdvert()
	o.Inventory = libraryInventory(inv)
	return o
}

// handleFactory applies one Keleustes dispatch and reports its outcome in
// the background. Every field is untrusted: a session dispatch becomes the
// same start request a website dispatch is, checked by the same start.
func (d *Daemon) handleFactory(ctx context.Context, fd *nodev1.Dispatch) {
	if fd.GetClone() != nil || fd.GetKind() == "library_scan" || fd.GetKind() == "library_import" || fd.GetKind() == "knowledge_reindex" {
		// A clone or a library scan can take minutes: it runs beside the link, and the
		// outcome is reported when it is done.
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.applyFactory(ctx, fd)
		}()
		return
	}
	d.applyFactory(ctx, fd)
}

// applyFactory is handleFactory's body.
func (d *Daemon) applyFactory(ctx context.Context, fd *nodev1.Dispatch) {
	res := &nodev1.JobResult{JobId: fd.GetId()}
	grant := factorylink.GrantFrom(fd.GetVault(), time.Now())
	if grant != nil {
		vaultenv.Protect()
	}
	sid, report, why, failed := d.factoryStart(ctx, fd, grant)
	// A started session took its own copy over its pipe; nothing else keeps
	// the grant.
	grant.Drop()
	switch {
	case why == "":
		res.Status, res.SessionId = jobOK, sid
		if report != "" {
			out, _ := json.Marshal(map[string]string{"report": report})
			res.OutputJson = string(out)
		}
	case failed:
		res.Status, res.Error = jobFailed, why
		d.logf("keleustes dispatch %s failed: %s", short(sanitizeName(fd.GetId())), why)
	default:
		res.Status, res.Error = jobRefused, why
		d.logf("refused keleustes dispatch %s in %s: %s", short(sanitizeName(fd.GetId())), sanitize.Line(fd.GetCwd(), 200), why)
	}
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorWeb,
		Data: map[string]string{"dispatch": factoryKindWord(fd.GetKind()), "status": res.Status, "via": "keleustes"}})
	if res.JobId == "" {
		return // nothing to report against
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.complete(ctx, res)
	}()
}

// complete reports an outcome, retrying a few times: the dispatch is already
// acked on the link, so a lost outcome only leaves Keleustes waiting.
func (d *Daemon) complete(ctx context.Context, res *nodev1.JobResult) {
	var err error
	for i := 0; ; i++ {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		err = d.o.Factory.Complete(cctx, res)
		cancel()
		if err == nil || i >= len(completeRetries) {
			break
		}
		if !sleepCtx(ctx, completeRetries[i]) {
			break
		}
	}
	if err != nil {
		d.logf("report keleustes dispatch %s: %v", short(sanitizeName(res.JobId)), err)
	}
}

// factoryDispatchKinds are the Keleustes dispatch kinds this daemon takes,
// advertised in Capabilities.dispatch_kinds so Keleustes offers no other.
var factoryDispatchKinds = []string{"session", "worker", "crew", "stop", "pause", "resume", "crew_control", "project_prefs",
	"library_install", "library_backup", "steer", "library_scan", "library_import", "budget_update", "knowledge_reindex"}

// factoryRequest maps a Keleustes dispatch onto the website's request shape,
// so the same checks run on it. Every field stays untrusted: start,
// startWorkers, PauseWorker and CrewControl validate what they use, and the
// trigger is cleaned before it becomes a provenance line.
func factoryRequest(fd *nodev1.Dispatch) sessionsync.Dispatch {
	r := sessionsync.Dispatch{ID: fd.GetId(), Kind: fd.GetKind(), Cwd: fd.GetCwd(), Prompt: fd.GetPrompt(),
		Provider: fd.GetProvider(), Model: fd.GetModel(), Effort: fd.GetEffort(), Profile: fd.GetAgent(),
		Crew: fd.GetCrew(), Dirs: fd.GetDirs(), Branch: fd.GetBranch(), Workspace: fd.GetWorkspace(),
		Fill: fd.GetFill(), Stay: fd.GetStay(), StayIdleMax: int(fd.GetStayIdleMaxS()),
		Worker: fd.GetWorkerId(), SessionID: fd.GetSessionId(), MemberModels: fd.GetMemberModels(),
		Trigger: factoryTrigger(fd.GetTrigger()), Budget: factoryBudget(fd.GetBudget())}
	for k, v := range fd.GetPrefsSet() {
		if r.PrefsSet == nil {
			r.PrefsSet = map[string]any{}
		}
		r.PrefsSet[k] = prefValue(v)
	}
	r.PrefsUnset = fd.GetPrefsUnset()
	if opts := fd.GetOptions(); len(opts) > 0 {
		r.Options = map[string]string{}
		for k, v := range opts {
			if k == "crew_lease_ms" {
				// A worker's claim lease rides on its budget (fleet.Limits).
				if ms, err := strconv.ParseInt(v, 10, 64); err == nil && ms > 0 {
					if r.Budget == nil {
						r.Budget = &sessionsync.WorkerBudget{}
					}
					r.Budget.Lease = (time.Duration(ms) * time.Millisecond).String()
				}
				continue
			}
			r.Options[k] = v
		}
	}
	if fd.GitSync != nil {
		v := fd.GetGitSync()
		r.GitSync = &v
	}
	if fd.Ask != nil {
		v := fd.GetAsk()
		r.Ask = &v
	}
	if c := fd.GetClone(); c != nil {
		r.Clone = &sessionsync.DispatchClone{Repo: c.GetOwner() + "/" + c.GetName(), Ref: c.GetBranch()}
	}
	if c := fd.GetControl(); c != nil {
		r.Control = &sessionsync.RCCrewControl{Run: c.GetRun(), Op: c.GetOp(), Worker: c.GetWorker(), Dir: c.GetDir(),
			Profile: c.GetProfile(), Weight: int(c.GetWeight()), Paused: c.GetPaused(), Replicas: int(c.GetReplicas())}
	}
	factorySessionExtras(fd, &r)
	return r
}

// factoryTrigger maps Keleustes provenance onto belai's trigger. Unknown
// sources become none (no provenance line rather than a wrong one).
func factoryTrigger(t *nodev1.Trigger) *sessionsync.Trigger {
	if t == nil {
		return nil
	}
	out := &sessionsync.Trigger{RunID: t.GetRunId(), WorkflowID: t.GetWorkflowId(), WorkflowName: t.GetWorkflowName(),
		Subject: t.GetSubject()}
	switch t.GetSource() {
	case "console":
		out.Source = "keleustes"
	case "card":
		out.Source, out.Subject = "keleustes", "card "+t.GetCardId()
	case "workflow":
		out.Source, out.Via = "workflow", "manual"
	case "schedule":
		out.Source, out.Via = "workflow", "cron"
	case "node":
		out.Source = "node"
		who := t.GetOriginName()
		if who == "" {
			who = t.GetOriginNode()
		}
		out.Note = "node " + who
		if s := t.GetOriginSession(); s != "" {
			out.Note += ", session " + s
		}
	default:
		return nil
	}
	return out.Clean()
}

// factoryBudget maps a Keleustes per-item budget; Clean on the worker side
// clamps every value.
func factoryBudget(b *nodev1.WorkerBudget) *sessionsync.WorkerBudget {
	if b == nil {
		return nil
	}
	out := &sessionsync.WorkerBudget{MaxCostUSD: b.GetMaxCostUsd(), FinalizeAt: b.GetFinalizeAt(),
		MaxContinuations: int(b.GetMaxContinuations()), MaxAttempts: int(b.GetMaxAttempts()), MaxWall: b.GetMaxWall(),
		MaxPasses: int(b.GetMaxPasses()), MaxTokens: int(b.GetMaxTokens()), MaxIterations: int(b.GetMaxIterations())}
	if b.GetPriceInputPerMtok() > 0 || b.GetPriceOutputPerMtok() > 0 {
		out.Price = &sessionsync.WorkerPrice{Input: b.GetPriceInputPerMtok(), Output: b.GetPriceOutputPerMtok()}
	}
	return out
}

// factoryStart runs a Keleustes dispatch through the website's code: a
// session through start, a worker or a crew through startWorkers, and the
// lifecycle kinds through the same calls the website's requests use. It
// returns the session id (sessions only) or a report, or the reason and
// whether the host failed (rather than refused). grant, when set, is the
// work's provider keys; a session takes it on an inherited pipe, and workers
// and crews run on the host's own configuration.
func (d *Daemon) factoryStart(ctx context.Context, fd *nodev1.Dispatch, grant *factorylink.Grant) (sid, report, why string, failed bool) {
	id := fd.GetId()
	if id == "" || sanitize.Ident(id, 64) != id {
		return "", "", "the dispatch id is not an identifier", false
	}
	kind := fd.GetKind()
	if kind == "" {
		kind = "session"
	}
	if !slices.Contains(factoryDispatchKinds, kind) {
		return "", "", "this Belai does not understand that dispatch; update Belai on the host", false
	}
	// The kill switch stops new work; stopping and pausing still go through.
	if c := d.factoryControl(); c.Stopped && kind != "stop" && kind != "pause" {
		return "", "", factorylink.StoppedReason(c), false
	}
	if d.draining.Load() && kind != "stop" && kind != "pause" {
		return "", "", restartingReason, false
	}
	if dl := fd.GetDeadlineMs(); dl > 0 && time.Now().UnixMilli() > dl {
		return "", "", "the dispatch's deadline passed before it arrived", false
	}
	switch fd.GetTier() {
	case "":
	case "fast":
		if fd.GetModel() == "" {
			return "", "", "a fast-tier dispatch names the model to run", false
		}
	default:
		return "", "", fmt.Sprintf("unknown model tier %q", sanitize.Ident(fd.GetTier(), 32)), false
	}
	if why := checkFactoryOptions(dispatchOptions(fd), d.o.Controls); why != "" {
		return "", "", why, false
	}
	if why := checkFactoryExtras(fd, kind); why != "" {
		return "", "", why, false
	}
	r := factoryRequest(fd)
	switch kind {
	case "stop":
		if r.SessionID == "" || sanitize.Ident(r.SessionID, 64) != r.SessionID {
			return "", "", "a stop names a session id", false
		}
		if !d.stop(r.SessionID) {
			return "", "", "that session is not running under belai rc on this host", false
		}
		return r.SessionID, "stopping", "", false
	case "pause", "resume":
		if !fleet.ValidID(r.Worker) {
			return "", "", "that is not a worker id", false
		}
		if d.o.PauseWorker == nil {
			return "", "", "this host cannot pause workers", false
		}
		if err := d.o.PauseWorker(r.Worker, kind == "pause"); err != nil {
			return "", "", clip(err.Error()), false
		}
		return "", r.Worker + " " + kind + "d", "", false
	case "steer":
		// The forge coordinator's answer: checked field by field here and
		// again by the worker, which takes it only for the item it holds and
		// a request it filed.
		spec := fleet.CoordSpec{Worker: fd.GetWorkerId(), Item: fd.GetCardId(), Request: fd.GetSteerRequest(),
			Event: fd.GetSteerEvent(), PR: int(fd.GetSteerPr()), PRURL: fd.GetSteerPrUrl(), Until: fd.GetSteerUntilMs(),
			Reason: fd.GetSteerReason()}
		if err := spec.Validate(); err != nil {
			return "", "", clip(err.Error()), false
		}
		if d.o.SteerWorker == nil {
			return "", "", "this host cannot steer workers", false
		}
		if err := d.o.SteerWorker(spec); err != nil {
			return "", "", clip(err.Error()), false
		}
		return "", spec.Worker + " told " + spec.Event, "", false
	case "budget_update":
		return d.factoryBudgetUpdate(fd)
	case "knowledge_reindex":
		return d.factoryReindex(ctx, fd)
	case "library_scan":
		report, why := d.factoryScan(ctx, fd)
		return "", report, why, false
	case "library_import":
		report, why := d.factoryImport(ctx, fd)
		return "", report, why, false
	case "library_install", "library_backup":
		report, why := d.factoryLibrary(context.Background(), fd)
		return "", report, why, false
	case "project_prefs":
		// Gated by --web-project-settings and checked key by key there.
		report, why := d.setProjectPrefs(r)
		return "", report, why, false
	case "crew_control":
		if d.o.CrewControl == nil || r.Control == nil {
			return "", "", "this host cannot change crew runs", false
		}
		rep, err := d.o.CrewControl(r.Control)
		if err != nil {
			return "", "", clip(err.Error()), false
		}
		return "", clip(rep), "", false
	case "worker", "crew":
		if kind == "crew" && r.Crew == "" {
			r.Crew, r.Profile = fd.GetAgent(), ""
		}
		if kind == "worker" {
			r.Crew = ""
		}
		chose := ""
		if r.Clone != nil {
			cwd, c, reason := d.cloneDir(ctx, r.Clone, r.Cwd)
			if reason != "" {
				return "", "", reason, false
			}
			r.Cwd, chose = cwd, c+"\n"
		}
		if grant != nil && runtime.GOOS == "windows" {
			return "", "", "this host cannot pass a vault grant to a worker on Windows", false
		}
		// A worker takes the grant on its pipe (WP-F); a crew start does not.
		if kind == "crew" {
			grant = nil
		}
		report, why = d.startWorkersGrant(r, false, grant)
		return "", clip(chose + report), why, false
	}
	if grant != nil && runtime.GOOS == "windows" {
		return "", "", "this host cannot pass a vault grant to a session on Windows", false
	}
	r.Kind = "start"
	if h := fd.GetHarness(); h != "" {
		sid, why = d.startHarness(r, HarnessStart{ID: h, Mode: fd.GetHarnessMode(),
			Resume: fd.GetHarnessResume(), Keys: fd.GetHarnessKeys()}, grant)
		return sid, "", why, strings.HasPrefix(why, "could not start Belai")
	}
	switch r.Mode = fd.GetMode(); r.Mode {
	case "auto":
		r.Mode = ""
	case "", "agent", "plan", "goal", "code":
	default:
		return "", "", fmt.Sprintf("unknown mode %q", sanitize.Ident(r.Mode, 32)), false
	}
	// Row 53: the first prompt's attachments, read and hash-checked here and
	// admitted by startGrant before the child starts.
	raw, why := d.factoryAttachments(ctx, fd)
	if why != "" {
		return "", "", why, false
	}
	r.Attachments = raw
	sid, why = d.startGrant(r, grant)
	failed = strings.HasPrefix(why, "could not start Belai") || strings.HasPrefix(why, "could not mint")
	return sid, "", why, failed
}

// factoryKindWord is the dispatch kind for the audit log: a known word, or
// "unknown" (the kind is Keleustes's, so only a recognised word is kept).
func factoryKindWord(k string) string {
	if k == "" {
		return "session"
	}
	if slices.Contains(factoryDispatchKinds, k) {
		return k
	}
	return "unknown"
}

// prefValue reads a Keleustes preference value: a boolean or a number when
// it is one, else the word itself. config.ProjectPrefs checks it either way.
func prefValue(v string) any {
	switch v {
	case "true":
		return true
	case "false":
		return false
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return f
	}
	return v
}

// checkFactoryOptions refuses a dispatch whose options this host would not
// apply (ApplyFactoryOptions with the daemon's own --web-controls), so
// nothing is half applied in the session later.
func checkFactoryOptions(opts map[string]string, controls bool) string {
	st := sessionctl.State{Guardrails: true}
	if err := ApplyFactoryOptions(&st, opts, controls); err != nil {
		return err.Error()
	}
	return ""
}
