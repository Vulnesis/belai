package hostmgmt

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/version"
	"github.com/vulnetix/belai/internal/vulnetixcli"
)

// belai_upgrade and rc_restart (docs/gaps/host-management.md §5.5).

func planBelaiUpgrade(_ context.Context, c *call) (*Plan, string) {
	m := c.m
	exe := m.o.Exe
	if exe == "" {
		return nil, "this daemon does not know its own binary"
	}
	ver := c.p["version"]
	method, _ := vulnetixcli.DetectInstall(exe, nil)
	pl := &Plan{Params: map[string]string{"version": ver, "method": string(method)}}
	switch method {
	case vulnetixcli.InstallBrew:
		pl.Steps = []Step{{Argv: []string{"brew", "upgrade", "belai"}}}
	case vulnetixcli.InstallScoop:
		pl.Steps = []Step{{Argv: []string{"scoop", "update", "belai"}}}
	case vulnetixcli.InstallGo:
		if ver == "" {
			return nil, "a go install names the version to pin"
		}
		pl.Steps = []Step{{Argv: []string{"go", "install", "github.com/vulnetix/belai/cmd/belai@" + ver}}}
	default:
		if ver == "" {
			return nil, "a direct upgrade names the release version to pin"
		}
		name := "belai"
		if version.Variant != "" {
			name += "-" + version.Variant
		}
		asset := m.assetName(name)
		base := strings.TrimRight(m.o.BelaiReleases, "/") + "/" + ver + "/"
		pl.Steps = []Step{{Download: &Download{URL: base + asset, Checksums: base + "checksums.txt", Asset: asset, To: exe},
			Backup: filepath.Join(filepath.Dir(exe), "belai.prev")}}
		pl.Params["method"] = "direct"
	}
	pl.Notes = []string{"the running daemon keeps the old binary until rc_restart"}
	return pl, ""
}

// backup copies the binary about to be replaced to its backup path.
func backup(from, to string) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(to+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	return os.Rename(to+".tmp", to)
}

func planRCRestart(_ context.Context, c *call) (*Plan, string) {
	if c.m.o.Hooks.Drain == nil || c.m.o.Hooks.Reexec == nil {
		return nil, "this daemon cannot restart itself"
	}
	force := c.p["force_after_s"]
	if force == "" {
		force = "300"
	}
	argv := append([]string{c.m.o.Exe}, c.m.o.Args...)
	params := map[string]string{"force_after_s": force}
	if v := c.p["expect_version"]; v != "" {
		params["expect_version"] = v
	}
	return &Plan{Params: params, Steps: []Step{{Argv: argv}},
		Notes: []string{"new dispatches are refused while it drains; it re-execs once sessions and workers reach 0 or force_after_s passes"}}, ""
}

// runRCRestart drains, then re-execs. The update before the re-exec leaves
// the action running; the new process settles it done when it starts
// (queue.recover), and Keleustes checks the new link's version.
func runRCRestart(ctx context.Context, c *call, pl *Plan) result {
	secs, _ := strconv.Atoi(pl.Params["force_after_s"])
	c.line(ctx, "draining: new dispatches are refused")
	c.m.update(ctx, c, &nodev1.HostActionUpdate{State: stateRunning, Step: "drain"}, "")
	forced := c.m.o.Hooks.Drain(ctx, time.Duration(secs)*time.Second)
	if forced {
		c.line(ctx, "force_after_s passed with work still running")
	}
	c.line(ctx, "re-exec "+strings.Join(displayArgv(c.m.o.UserHome, pl.Steps[0].Argv), " "))
	c.m.update(ctx, c, &nodev1.HostActionUpdate{State: stateRunning, Step: "reexec", Pct: 90}, "")
	mk := restartMarker{ActionID: c.a.GetId(), Expect: pl.Params["expect_version"], Exe: c.m.o.Exe}
	if prev := filepath.Join(filepath.Dir(c.m.o.Exe), "belai.prev"); fileExists(prev) {
		mk.Prev = prev
	}
	if err := c.m.writeMarker(mk); err != nil {
		return failed("the restart marker could not be written; not restarting")
	}
	err := c.m.o.Hooks.Reexec()
	if err != nil {
		_ = os.Remove(c.m.markerPath())
	}
	if c.m.o.Hooks.Undrain != nil {
		c.m.o.Hooks.Undrain()
	}
	if err != nil {
		return failed("the re-exec failed; the daemon keeps running the old process")
	}
	return done("")
}
