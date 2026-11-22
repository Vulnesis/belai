//go:build windows

package vllm

import (
	"os"
	"os/exec"
)

func setGroup(*exec.Cmd) {}

func terminate(pid int) { kill(pid) }

func kill(pid int) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}
