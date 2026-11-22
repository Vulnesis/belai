//go:build !windows

package vllm

import (
	"os/exec"
	"syscall"
)

// setGroup starts the server as the leader of its own process group, so
// terminate and kill reach the engine and tokenizer workers vLLM forks; they
// hold GPU memory and must not outlive it.
func setGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func terminate(pid int) { _ = syscall.Kill(-pid, syscall.SIGTERM) }
func kill(pid int)      { _ = syscall.Kill(-pid, syscall.SIGKILL) }
