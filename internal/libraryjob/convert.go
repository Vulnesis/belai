// Package libraryjob runs Keleustes' `library` job: convert a foreign agent
// definition (Hermes, Claws/OpenClaw, Nemoclaw, mini-SWE) into a Belai profile
// with internal/agentimport, for the desktop library's import preview
// (keleustes docs/gaps/library-proto-request.md, WP9).
//
// Keleustes sends file contents only. The host checks every path and size
// before anything is written, stages the files in a fresh private directory,
// runs agentimport.ImportItem on it (which reads, never executes), removes the
// directory, and answers the canonical profile, its hash, the import notes and
// the skills found beside it. Nothing is installed: Keleustes reviews and
// imports the answer like any other preview.
package libraryjob

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/vulnetix/belai/internal/agentimport"
	"github.com/vulnetix/belai/internal/libitem"
	"github.com/vulnetix/belai/internal/sanitize"
)

// Kind is the job kind, advertised in Capabilities.job_kinds.
const Kind = "library"

// TaskConvert is the one task.
const TaskConvert = "convert"

// MaxPayload bounds the job's JSON: 8 MiB of files in base64 plus room.
const MaxPayload = 12 << 20

// Request is a checked convert job.
type Request struct {
	Format agentimport.Format
	Name   string
	// Files maps a clean relative slash path to its bytes.
	Files map[string][]byte
}

// Note is one line of belai's import report.
type Note struct {
	Kind  string `json:"kind"`
	Field string `json:"field"`
	Text  string `json:"text"`
}

// Skill is a skill found beside the definition.
type Skill struct {
	Name   string `json:"name"`
	Doc    string `json:"doc"`
	SHA256 string `json:"sha256"`
}

// Result is the job answer.
type Result struct {
	Doc    string  `json:"doc"`
	SHA256 string  `json:"sha256"`
	Name   string  `json:"name"`
	Format string  `json:"format"`
	Notes  []Note  `json:"notes"`
	Skills []Skill `json:"skills"`
}

// formats are the four the job reads; Keleustes converts every other format itself.
var formats = map[string]agentimport.Format{
	"hermes": agentimport.Hermes, "claws": agentimport.Claws, "nemoclaw": agentimport.Nemoclaw,
	"mini-swe": agentimport.MiniSWE,
}

// Parse reads and checks a library job's payload. The reason is harness text.
func Parse(payload string) (Request, string) {
	if len(payload) > MaxPayload {
		return Request{}, "the library job's payload is too large"
	}
	var p struct {
		Task   string            `json:"task"`
		Kind   string            `json:"kind"`
		Format string            `json:"format"`
		Name   string            `json:"name"`
		Files  map[string]string `json:"files"`
	}
	if json.Unmarshal([]byte(payload), &p) != nil {
		return Request{}, "the library job's payload is not a JSON object"
	}
	if p.Task != TaskConvert {
		return Request{}, "this Belai does not run that library task; update Belai on the host"
	}
	if p.Kind != "agent" {
		return Request{}, "a library convert job converts an agent"
	}
	f, ok := formats[p.Format]
	if !ok {
		return Request{}, "a library convert job reads hermes, claws, nemoclaw or mini-swe"
	}
	r := Request{Format: f, Files: map[string][]byte{}}
	if p.Name != "" {
		if sanitize.Ident(p.Name, 64) != p.Name {
			return Request{}, "the suggested name is not an identifier"
		}
		r.Name = p.Name
	}
	if len(p.Files) == 0 {
		return Request{}, "a library convert job carries the definition's files"
	}
	if len(p.Files) > agentimport.MaxFiles {
		return Request{}, fmt.Sprintf("a library convert job carries at most %d files", agentimport.MaxFiles)
	}
	total := 0
	for name, b64 := range p.Files {
		if why := checkPath(name); why != "" {
			return Request{}, why
		}
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return Request{}, "a file of the library job is not base64"
		}
		if len(data) > agentimport.MaxFileBytes {
			return Request{}, fmt.Sprintf("a file of the library job is over %d bytes", agentimport.MaxFileBytes)
		}
		total += len(data)
		if total > agentimport.MaxTotalBytes {
			return Request{}, fmt.Sprintf("the library job's files are over %d bytes in all", agentimport.MaxTotalBytes)
		}
		r.Files[name] = data
	}
	// A file may not also be a directory of another ("a" and "a/b").
	for name := range r.Files {
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			if _, clash := r.Files[dir]; clash {
				return Request{}, "a path of the library job is both a file and a directory"
			}
		}
	}
	return r, ""
}

// checkPath refuses a name that is not a clean relative path inside the staging
// directory, is too deep, or names a credential file.
func checkPath(name string) string {
	if name == "" || len(name) > 512 || path.Clean(name) != name || path.IsAbs(name) ||
		strings.ContainsAny(name, `\:`) || strings.IndexFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}) >= 0 {
		return "a path of the library job is not a clean relative path"
	}
	segs := strings.Split(name, "/")
	if len(segs) > agentimport.MaxDepth {
		return fmt.Sprintf("a path of the library job is deeper than %d", agentimport.MaxDepth)
	}
	for _, s := range segs {
		if s == ".." || s == "." || s == ".git" {
			return "a path of the library job names a parent or a git directory"
		}
	}
	if agentimport.SecretName(name) {
		return "the library job carries a credential file, which is never read"
	}
	return ""
}

// Convert stages the files, runs the importer and answers its result. A
// definition the importer refuses is a refusal (the reason), not a failure.
func Convert(r Request) (json.RawMessage, string, error) {
	dir, err := os.MkdirTemp("", "belai-library-job-")
	if err != nil {
		return nil, "", errors.New("could not make the staging directory")
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, "", errors.New("could not make the staging directory private")
	}
	// The directory's name is where the importer takes a name from when the
	// definition names none.
	base := r.Name
	if base == "" {
		base = "imported"
	}
	root := filepath.Join(dir, base)
	if err := os.Mkdir(root, 0o700); err != nil {
		return nil, "", errors.New("could not make the staging directory")
	}
	for name, data := range r.Files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, "", errors.New("could not stage the files")
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, "", errors.New("could not stage the files")
		}
		_, werr := f.Write(data)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return nil, "", errors.New("could not stage the files")
		}
	}
	res, err := agentimport.ImportItem(root, agentimport.KindAgent, r.Format, agentimport.Options{Name: r.Name})
	if err != nil {
		return nil, sanitize.Line(err.Error(), 300), nil
	}
	out := Result{Doc: string(res.Doc), SHA256: res.SHA256, Name: res.Name, Format: string(res.Format),
		Notes: []Note{}, Skills: []Skill{}}
	for _, n := range res.Notes {
		out.Notes = append(out.Notes, Note{Kind: string(n.Kind), Field: n.Field, Text: n.Text})
	}
	for _, s := range res.Skills {
		out.Skills = append(out.Skills, Skill{Name: s.Name, Doc: string(s.Doc), SHA256: libitem.Hash(s.Doc)})
	}
	b, err := json.Marshal(out)
	return b, "", err
}
