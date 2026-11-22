package rc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vulnetix/belai/internal/agentfiles"
	"github.com/vulnetix/belai/internal/agentimport"
	"github.com/vulnetix/belai/internal/agentprofile"
	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/knowledge"
	"github.com/vulnetix/belai/internal/libinstall"
	"github.com/vulnetix/belai/internal/libitem"
	"github.com/vulnetix/belai/internal/libscan"
	"github.com/vulnetix/belai/internal/libstore"
	"github.com/vulnetix/belai/internal/plugins"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// Keleustes library distribution (WP-E). A dispatch names items by
// reference; each document is fetched for that dispatch and validated by the
// same code a website install uses: a profile as a profile
// (agentprofile.ParseMarkdown, Validate, libinstall.Conflict), an item by
// its kind's libstore adapter behind the kind's sync switch. A hook or MCP
// server arrives only through such an explicit install, never a sync.

// libraryTimeout bounds one dispatch's fetches and writes.
const libraryTimeout = 2 * time.Minute

// keleustesAgent is Keleustes's agent JSON (vault::agent_to_library). A
// profile this host backed up keeps its full markdown in meta.belaiMarkdown.
type keleustesAgent struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Description string   `json:"description"`
	Prompt      string   `json:"prompt"`
	Provider    string   `json:"provider"`
	Model       string   `json:"model"`
	Tools       []string `json:"tools"`
	Meta        struct {
		BelaiMarkdown string `json:"belaiMarkdown"`
	} `json:"meta"`
	// Files are the files the agent carries (Keleustes agent files): their
	// listed paths, hashes and sizes; the bytes arrive as LibraryDoc.files.
	Files []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"files,omitempty"`
}

// profileFromDoc reads a fetched profile document: belai markdown, or
// Keleustes's agent JSON (with the host's own markdown inside when it came
// from a backup). Either way the result is validated as a profile.
func profileFromDoc(doc []byte) (agentprofile.AgentProfile, error) {
	text := strings.TrimSpace(string(doc))
	if strings.HasPrefix(text, "---") {
		return agentprofile.ParseMarkdown(doc)
	}
	var a keleustesAgent
	if err := json.Unmarshal(doc, &a); err != nil {
		return agentprofile.AgentProfile{}, errors.New("the document is neither a profile nor an agent")
	}
	if a.Meta.BelaiMarkdown != "" {
		return agentprofile.ParseMarkdown([]byte(a.Meta.BelaiMarkdown))
	}
	p := agentprofile.AgentProfile{Name: a.Name, DisplayName: a.DisplayName, Description: a.Description,
		SystemPrompt: a.Prompt, Provider: a.Provider, Model: a.Model, Tools: a.Tools, Mode: agentprofile.ModeSingle}
	// A Keleustes agent's files are documents it may search: their paths are
	// its knowledge paths, resolved to the owned copies (agentfiles.Install).
	for _, f := range a.Files {
		if p.Knowledge == nil {
			p.Knowledge = &agentprofile.KnowledgeSpec{}
		}
		p.Knowledge.Paths = append(p.Knowledge.Paths, f.Path)
	}
	return p, p.Validate()
}

// profileDoc is a host profile as Keleustes's agent JSON, carrying the full
// markdown so another host installs it exactly.
func profileDoc(p agentprofile.AgentProfile) ([]byte, error) {
	md, err := agentprofile.MarshalMarkdown(p)
	if err != nil {
		return nil, err
	}
	a := keleustesAgent{Name: p.Name, DisplayName: p.DisplayName, Description: p.Description, Prompt: p.SystemPrompt,
		Provider: p.Provider, Model: p.Model, Tools: p.Tools}
	a.Meta.BelaiMarkdown = string(md)
	return json.Marshal(a)
}

// factoryLibrary installs or backs up each item a library dispatch names.
// It stops at the first refusal, saying which item and why.
func (d *Daemon) factoryLibrary(ctx context.Context, fd *nodev1.Dispatch) (string, string) {
	ctx, cancel := context.WithTimeout(ctx, libraryTimeout)
	defer cancel()
	var done []string
	// Profiles first: a crew is written only once its members are profiles here.
	refs := append([]*nodev1.LibraryRef(nil), fd.GetLibrary()...)
	sort.SliceStable(refs, func(a, b int) bool {
		return refs[a].GetKind() == "profile" && refs[b].GetKind() != "profile"
	})
	for _, ref := range refs {
		var what, why string
		if fd.GetKind() == "library_install" {
			what, why = d.libraryInstall(ctx, fd, ref)
		} else {
			what, why = d.libraryBackup(ctx, fd, ref)
		}
		if why != "" {
			return "", fmt.Sprintf("%s %s: %s", sanitize.Ident(ref.GetKind(), 24), sanitize.Line(ref.GetName(), 64), why)
		}
		done = append(done, what)
	}
	return strings.Join(done, "; "), ""
}

func (d *Daemon) libraryInstall(ctx context.Context, fd *nodev1.Dispatch, ref *nodev1.LibraryRef) (string, string) {
	if ref.GetKind() != "profile" && ref.GetKind() != "crew" {
		// Check the kind and its sync switch before fetching anything.
		if _, why := d.libraryKind(ref.GetKind()); why != "" {
			return "", why
		}
	}
	doc, err := d.o.Factory.LibraryFetch(ctx, fd.GetId(), ref)
	if err != nil {
		return "", "could not read it from Keleustes: " + reason(err.Error())
	}
	body := doc.GetDoc()
	if ref.GetKind() == "profile" {
		p, err := profileFromDoc(body)
		if err != nil {
			return "", "the profile is not valid here: " + reason(err.Error())
		}
		// The files the agent carries are checked whole before anything is
		// saved, and written into the profile's own directory after.
		files, why := profileFiles(doc.GetFiles())
		if why != "" {
			return "", why
		}
		if why := libinstall.Conflict(p, fd.GetOverwrite()); why != "" {
			return "", why
		}
		if _, err := agentprofile.SaveReplacing(p); err != nil {
			return "", "could not save the profile: " + reason(err.Error())
		}
		if len(files) == 0 {
			return "installed profile " + sanitize.Line(p.Name, 64), ""
		}
		saved, err := agentprofile.Load(p.Name)
		if err != nil {
			return "", "could not read the saved profile: " + reason(err.Error())
		}
		if err := agentfiles.Install(saved.ID, files); err != nil {
			return "", "the profile's files are not ones this host will write: " + reason(err.Error())
		}
		auditProfileFiles(fd.GetId(), p.Name, files)
		return fmt.Sprintf("installed profile %s, with %d file%s", sanitize.Line(p.Name, 64), len(files), plural(len(files), "", "s")), ""
	}
	if ref.GetKind() == "crew" {
		c, err := crewFromDoc(body)
		if err != nil {
			return "", reason(err.Error())
		}
		if c.Name != strings.TrimSpace(ref.GetName()) {
			return "", "the crew is not the one the dispatch named"
		}
		// The shared installer; it tells the automatic sync what it wrote.
		in := libinstall.Installer{}
		if d.libsync != nil {
			in.Saved = d.markSynced
		}
		return in.SaveCrew(c, fd.GetOverwrite())
	}
	kind, _ := d.libraryKind(ref.GetKind())
	// A hook bundle carries its scripts: each file must come with the hash
	// Keleustes listed, and libstore checks every one and the whole bundle the
	// way the loader reads it before anything is written.
	var files []libstore.BundleFile
	for _, f := range doc.GetFiles() {
		if f.GetSha256() == "" {
			return "", "a bundle file arrived without its hash"
		}
		files = append(files, libstore.BundleFile{Path: f.GetPath(), Data: f.GetData(), SHA256: f.GetSha256()})
	}
	res, err := libstore.InstallBundle(kind, body, files, libstore.InstallOptions{Overwrite: fd.GetOverwrite(), Name: ref.GetName()})
	if errors.Is(err, libstore.ErrExists) {
		return "", fmt.Sprintf("this host already has that %s; send it with overwrite to replace it", kind)
	}
	if err != nil {
		return "", reason(err.Error())
	}
	verb := "installed"
	if res.Replaced {
		verb = "replaced"
	}
	return fmt.Sprintf("%s %s %s", verb, kind, sanitize.Line(ref.GetName(), 64)), ""
}

func (d *Daemon) libraryBackup(ctx context.Context, fd *nodev1.Dispatch, ref *nodev1.LibraryRef) (string, string) {
	name := strings.TrimSpace(ref.GetName())
	var doc []byte
	if ref.GetKind() == "crew" {
		c, ok := libinstall.StoredCrew(name)
		if !ok {
			return "", "this host has no crew " + sanitize.Line(name, 64)
		}
		var why string
		if doc, why = keleustesCrewDoc(c); why != "" {
			return "", why
		}
	} else if ref.GetKind() == "profile" {
		if agentprofile.IsBuiltin(name) {
			return "", "built-in profiles ship with Belai"
		}
		p, err := agentprofile.Load(name)
		if err != nil {
			return "", "this host has no profile " + sanitize.Line(name, 64)
		}
		if doc, err = profileDoc(p); err != nil {
			return "", "could not export the profile: " + reason(err.Error())
		}
	} else {
		kind, why := d.libraryKind(ref.GetKind())
		if why != "" {
			return "", why
		}
		if kind.InstallOnly() {
			return "", fmt.Sprintf("a %s is installed from the library and never backed up from a host", kind)
		}
		it, err := libstore.Get(kind, name)
		if err != nil {
			return "", fmt.Sprintf("this host has no %s %s", kind, sanitize.Line(name, 64))
		}
		doc = it.Doc
	}
	stored, err := d.o.Factory.LibraryBackup(ctx, &nodev1.LibraryDoc{DispatchId: fd.GetId(), Ref: ref, Doc: doc})
	if err != nil {
		return "", "Keleustes did not take it: " + reason(err.Error())
	}
	return fmt.Sprintf("backed up %s %s as version %d", sanitize.Ident(ref.GetKind(), 24), sanitize.Line(name, 64), stored.GetVersion()), ""
}

// libraryKind is an item kind this host stores and syncs.
func (d *Daemon) libraryKind(k string) (libitem.Kind, string) {
	kind, ok := libitem.Parse(strings.TrimSpace(k))
	if !ok {
		return "", "that is not a library item kind"
	}
	if !libstore.Supported(kind) {
		return "", fmt.Sprintf("this Belai does not store %s items; update Belai on the host", kind)
	}
	if !d.o.SyncItem(kind) {
		return "", fmt.Sprintf("sync.%s is off on this host, so it takes no %s requests", kind.Segment(), kind)
	}
	return kind, ""
}

// libraryInventory is the advert's inventory: profiles and items by name and
// hash, never a document.
func libraryInventory(inv Inventory) []*nodev1.LibraryRef {
	var out []*nodev1.LibraryRef
	for _, p := range inv.Profiles {
		if p.Builtin {
			continue
		}
		out = append(out, &nodev1.LibraryRef{Kind: "profile", Id: p.ID, Name: p.Name, Sha256: p.SHA256})
	}
	// A crew's hash is its canonical JSON's (crewDocument), present only while
	// sync.profiles is on, like a profile's.
	for _, c := range inv.Crews {
		if c.Builtin {
			continue
		}
		out = append(out, &nodev1.LibraryRef{Kind: "crew", Id: c.ID, Name: c.Name, Sha256: c.SHA256})
	}
	for _, it := range inv.Items {
		out = append(out, &nodev1.LibraryRef{Kind: it.Kind, Name: it.Name, Sha256: it.SHA256})
	}
	// The knowledge catalogue: one entry per index (version is its document
	// count), its documents' addresses and hashes folded into one hash.
	// Facts only, never a passage.
	for _, k := range inv.Knowledge {
		id := k.Scope + ":" + k.Key
		if k.Key == "" {
			id = k.Scope + ":" + k.Root
		}
		out = append(out, &nodev1.LibraryRef{Kind: "knowledge", Id: sanitize.Line(id, 512), Name: sanitize.Line(k.Name, 128),
			Version: int64(len(k.Docs)), Sha256: knowledgeHash(k)})
	}
	// Installed plugins: the name, the commit it was installed at (id), on or
	// off (version 1 or 0), and a hash of that record.
	for _, p := range inv.Plugins {
		out = append(out, &nodev1.LibraryRef{Kind: "plugin", Id: p.Commit, Name: p.Name, Version: p.Enabled, Sha256: p.SHA256})
	}
	return out
}

// knowledgeHash folds an index's document addresses and hashes, in order.
func knowledgeHash(k sessionsync.RCKnowledge) string {
	h := sha256.New()
	for _, d := range k.Docs {
		h.Write([]byte(d.Address))
		h.Write([]byte{0})
		h.Write([]byte(d.SHA256))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// InvPlugin is one installed plugin the advert lists.
type InvPlugin struct {
	Name, Commit, SHA256 string
	// Enabled is 1 for a plugin that is on, 0 for one that is off.
	Enabled int64
}

// maxInvPlugins bounds the plugins one advert lists.
const maxInvPlugins = 64

// localPlugins reads the plugin registry: names and commits, never a file.
func localPlugins() []InvPlugin {
	recs, err := plugins.List()
	if err != nil {
		return nil
	}
	var out []InvPlugin
	for _, r := range recs {
		if len(out) >= maxInvPlugins {
			break
		}
		if !plugins.ValidName(r.Name) {
			continue
		}
		commit := sanitize.Ident(r.Commit, 64)
		sum := sha256.Sum256([]byte(r.Name + "\x00" + commit + "\x00" + sanitize.Line(r.Version, 64)))
		on := int64(0)
		if r.Enabled {
			on = 1
		}
		out = append(out, InvPlugin{Name: r.Name, Commit: commit, SHA256: hex.EncodeToString(sum[:]), Enabled: on})
	}
	return out
}

// keleustesCrew is Keleustes's crew JSON (workforce::crew_to_library). A crew
// a host backed up keeps its canonical JSON in meta.belaiCrew, so another
// host installs it exactly, id included.
type keleustesCrew struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Members     []struct {
		Agent string `json:"agent"`
		Count int    `json:"count"`
	} `json:"members"`
	Meta struct {
		BelaiCrew string `json:"belaiCrew"`
	} `json:"meta"`
}

// crewFromDoc reads a fetched crew: a host's canonical form inside
// meta.belaiCrew (strict: an unknown key is refused), or a crew Keleustes
// wrote, whose members are agent names and counts. A crew without an id
// takes the id of this host's crew of that name, or a new one.
func crewFromDoc(doc []byte) (agentprofile.Crew, error) {
	var k keleustesCrew
	if err := json.Unmarshal(doc, &k); err != nil {
		return agentprofile.Crew{}, errors.New("the document is not a crew")
	}
	var c agentprofile.Crew
	if k.Meta.BelaiCrew != "" {
		dec := json.NewDecoder(bytes.NewReader([]byte(k.Meta.BelaiCrew)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return agentprofile.Crew{}, fmt.Errorf("the crew is not valid here: %s", reason(err.Error()))
		}
		if c.Name != k.Name {
			return agentprofile.Crew{}, errors.New("the crew's two names differ")
		}
	} else {
		c = agentprofile.Crew{Name: k.Name, Description: k.Description}
		if len(k.Members) > agentprofile.MaxCrewMembers {
			return agentprofile.Crew{}, fmt.Errorf("a crew has 1 to %d members", agentprofile.MaxCrewMembers)
		}
		for _, m := range k.Members {
			c.Members = append(c.Members, agentprofile.Member{Profile: m.Agent, Replicas: max(m.Count, 0)})
		}
	}
	c.Builtin = false
	if c.ID == "" {
		if have, ok := libinstall.StoredCrew(c.Name); ok && agentprofile.ValidID(have.ID) {
			c.ID = have.ID
		} else {
			id, err := agentprofile.NewID()
			if err != nil {
				return agentprofile.Crew{}, err
			}
			c.ID = id
		}
	}
	return c, nil
}

// keleustesCrewDoc is a host crew as Keleustes's crew JSON with its canonical form
// inside: the bytes whose meta.belaiCrew hash the advert carries.
func keleustesCrewDoc(c agentprofile.Crew) ([]byte, string) {
	js, ok := crewDocument(c)
	if !ok {
		return nil, "that crew is built in, has no id yet, or is too large to back up"
	}
	members := []map[string]any{}
	for _, m := range c.Members {
		members = append(members, map[string]any{"agent": m.Profile, "role": "", "count": m.Count()})
	}
	doc, err := json.Marshal(map[string]any{"name": c.Name, "description": c.Description, "process": "parallel",
		"members": members, "meta": map[string]string{"belaiCrew": string(js)}})
	if err != nil {
		return nil, "could not encode the crew"
	}
	return doc, ""
}

// factoryScan runs a library_scan for Keleustes (WP-K): the same scan the
// website asks for, reported as names, paths, hashes and verdicts only. One
// scan runs at a time.
func (d *Daemon) factoryScan(ctx context.Context, fd *nodev1.Dispatch) (string, string) {
	kinds, err := libscan.KindSet(fd.GetItemKind())
	if err != nil {
		return "", reason(err.Error())
	}
	select {
	case d.scanSlot <- struct{}{}:
	default:
		return "", "this host is already scanning; try again in a moment"
	}
	sctx, cancel := context.WithTimeout(ctx, scanBudget)
	rep := libscan.Scan(sctx, libscan.Options{Kinds: kinds})
	cancel()
	<-d.scanSlot
	out := &nodev1.LibraryScanReport{DispatchId: fd.GetId(), Partial: rep.Partial}
	for _, it := range rep.Items {
		out.Found = append(out.Found, &nodev1.LibraryRef{Kind: it.Kind, Name: it.Name, Sha256: it.SHA256})
		out.Paths = append(out.Paths, it.Path)
		out.Harnesses = append(out.Harnesses, it.Harness)
		out.Verdicts = append(out.Verdicts, it.Verdict)
	}
	actx, acancel := context.WithTimeout(context.WithoutCancel(ctx), ackTimeout)
	defer acancel()
	if err := d.o.Factory.LibraryScanReport(actx, out); err != nil {
		return "", "Keleustes did not take the scan report: " + reason(err.Error())
	}
	return rep.Summary(), ""
}

// factoryImport re-reads an item a scan reported, through the same checks,
// and uploads it with Library.Backup naming this import and the scan's
// hash. A profile goes as Keleustes's agent JSON with its markdown.
func (d *Daemon) factoryImport(ctx context.Context, fd *nodev1.Dispatch) (string, string) {
	d.importMu.Lock()
	defer d.importMu.Unlock()
	r := sessionsync.Dispatch{ID: fd.GetId(), ItemKind: fd.GetItemKind(), Path: fd.GetPath(), SHA256: fd.GetSha256(), Target: fd.GetTarget()}
	kind, item, body, harness, why := resolveImport(r)
	if why != "" {
		return "", why
	}
	var doc []byte
	switch b := body.(type) {
	case string:
		doc = []byte(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			return "", "could not encode the item"
		}
		doc = data
	}
	refKind := string(kind)
	if kind == agentimport.KindAgent {
		p, err := agentprofile.ParseMarkdown(item.Doc)
		if err != nil {
			return "", "the agent is not valid here: " + reason(err.Error())
		}
		if doc, err = profileDoc(p); err != nil {
			return "", reason(err.Error())
		}
		refKind = "profile"
	}
	ref := &nodev1.LibraryRef{Kind: refKind, Name: item.Name, Sha256: item.SHA256}
	ictx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ackTimeout)
	defer cancel()
	stored, err := d.o.Factory.LibraryBackup(ictx, &nodev1.LibraryDoc{DispatchId: fd.GetId(), Ref: ref, Doc: doc})
	if err != nil {
		return "", "Keleustes did not take the " + string(kind) + ": " + reason(err.Error())
	}
	return fmt.Sprintf("imported %s %s from %s as version %d", kind, sanitize.Line(item.Name, 64), sanitize.Ident(harness, 40), stored.GetVersion()), ""
}

// profileFiles checks the files a profile document carries (Keleustes agent
// files): each must come with its hash and match it, keep inside the
// profile's own directory, be bounded text and hold no private key or known
// token, within agentfiles' limits. One bad file refuses them all.
func profileFiles(in []*nodev1.LibraryFile) ([]agentfiles.File, string) {
	if len(in) == 0 {
		return nil, ""
	}
	if len(in) > agentfiles.MaxFiles {
		return nil, fmt.Sprintf("the profile carries more than %d files", agentfiles.MaxFiles)
	}
	total := 0
	out := make([]agentfiles.File, 0, len(in))
	for _, f := range in {
		data := f.GetData()
		switch {
		case f.GetSha256() == "" || agentfiles.Sum(data) != f.GetSha256():
			return nil, "a profile file does not match its hash"
		case len(data) == 0 || len(data) > agentfiles.MaxFileBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0:
			return nil, "a profile file is not bounded text"
		case agentfiles.HoldsSecret(data):
			return nil, "a profile file holds a private key or a token"
		}
		if _, ok := knowledge.OwnedRelPath(f.GetPath()); !ok {
			return nil, "a profile file's path is not one this host keeps"
		}
		if total += len(data); total > agentfiles.MaxTotalBytes {
			return nil, fmt.Sprintf("the profile's files are over %d bytes", agentfiles.MaxTotalBytes)
		}
		out = append(out, agentfiles.File{Path: f.GetPath(), Content: data, SHA256: f.GetSha256()})
	}
	return out, ""
}

// auditProfileFiles records the files an install wrote: paths' count and
// each hash prefix, never a byte of them.
func auditProfileFiles(dispatch, profile string, files []agentfiles.File) {
	hashes := make([]string, 0, len(files))
	for _, f := range files {
		hashes = append(hashes, f.SHA256[:16])
	}
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorWeb, Outcome: "profile_files",
		Data: map[string]string{"dispatch": "library_install", "status": "profile_files", "profile": sanitize.Line(profile, 64),
			"files": fmt.Sprint(len(files)), "hashes": strings.Join(hashes, ","), "via": sanitize.Ident(dispatch, 64)}})
}
