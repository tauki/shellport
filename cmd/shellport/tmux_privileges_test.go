package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTmuxPrivilegeCLIRejectsMisplacedOptions(t *testing.T) {
	for _, args := range [][]string{
		{"serve", "--tmux-privileges", "account"},
		{"init", "--tmux-privileges", "restricted"},
		{"init", "--local-shell", "--tmux-privileges="},
	} {
		cmd := cliProcess(t, args...)
		out, err := cmd.CombinedOutput()
		if err == nil || !bytes.Contains(out, []byte("--tmux-privileges")) {
			t.Fatal("invalid policy context accepted", args, err, string(out))
		}
		if _, err := os.Stat(filepath.Join(cmd.Dir, ".data")); !os.IsNotExist(err) {
			t.Fatal("invalid policy initialized credentials")
		}
	}
}

func TestTmuxPrivilegeCLIPreviewDoesNotInstall(t *testing.T) {
	tmux, err := exec.LookPath("tmux")
	if err != nil {
		t.Skip("tmux preview requires executable")
	}
	for _, policy := range []string{"account", "restricted"} {
		cmd := cliProcess(t, "init", "--local-shell", "--dry-run", "--tmux-bin", tmux, "--tmux-privileges", policy)
		out, err := cmd.CombinedOutput()
		if runtime.GOOS == "linux" {
			if err != nil || !strings.Contains(string(out), `"privilegePolicy": "`+policy+`"`) {
				t.Fatal(err, string(out))
			}
		} else if err == nil || !strings.Contains(string(out), "only to independent tmux services on Linux") {
			t.Fatal("unsupported policy did not fail explicitly", err, string(out))
		}
		if _, err := os.Stat(filepath.Join(cmd.Dir, ".data")); !os.IsNotExist(err) {
			t.Fatal("preview created installation data")
		}
	}
}
