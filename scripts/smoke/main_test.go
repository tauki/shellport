package main

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"shellport/internal/shellport"
)

func TestResizeProofWaitsForActualRemoteDimensions(t *testing.T) {
	for _, delayed := range []bool{true, false} {
		t.Run(map[bool]string{true: "delayed-resize", false: "no-resize"}[delayed], func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "sampled")
			// Command substitutions run in subshells, as they do on a real target;
			// the file makes the delayed size change visible to the next sample.
			fixture := "shellport_resize_test_state=$1\nsleep() { :; }\nstty() { printf '23 84\\n'; }\n"
			if delayed {
				fixture += "stty() { if [ -e \"$shellport_resize_test_state\" ]; then printf '31 96\\n'; else : > \"$shellport_resize_test_state\"; printf '23 84\\n'; fi; }\n"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, "/bin/sh", "-c", fixture+resizedSizeCommand("__RESIZED=", 31, 96), "resize-test", state).CombinedOutput()
			if err != nil {
				t.Fatal("resize proof failed", err, string(output))
			}
			if delayed && string(output) != "__RESIZED=31 96\n" || !delayed && len(output) != 0 {
				t.Fatal("resize proof accepted stale dimensions or missed the change", string(output))
			}
		})
	}
}

func TestHostChoiceRequiresAnExplicitUnambiguousVerifiedComputer(t *testing.T) {
	hosts := []host{{ID: "one", Name: "Server", Auth: "local"}, {ID: "two", Name: "Server", Auth: "key"}}
	for _, choice := range [][2]string{{"", ""}, {"one", "Server"}, {"", "Server"}, {"missing", ""}, {"two", ""}} {
		if _, err := chooseHost(hosts, choice[0], choice[1]); err == nil {
			t.Fatal("Unsafe or ambiguous host choice accepted", choice)
		}
	}
	chosen, err := chooseHost(hosts, "one", "")
	if err != nil || chosen.ID != "one" {
		t.Fatal("Explicit local computer refused", err)
	}
}

func TestProofPatternsIgnoreCommandEchoAndAcceptDifferentArchitectures(t *testing.T) {
	arch := architecturePattern("__ARCH=")
	size := sizePattern("__SIZE=")
	echo := "printf '__ARCH='; uname -m; printf '__SIZE='; stty size\r\n"
	if arch.MatchString(echo) || size.MatchString(echo) {
		t.Fatal("Command echo was mistaken for actual terminal output")
	}
	for _, architecture := range []string{"x86_64", "aarch64", "arm64", "armv7l"} {
		output := echo + "__ARCH=" + architecture + "\r\n__SIZE=22 84\r\n"
		if got := arch.FindStringSubmatch(output); len(got) != 2 || got[1] != architecture {
			t.Fatal("Actual architecture was not parsed", architecture)
		}
		if !size.MatchString(output) {
			t.Fatal("Actual terminal size was not parsed")
		}
	}
}

func TestSmokePreservesSavedComputerAndCleansUpOnSuccessAndFailure(t *testing.T) {
	for _, test := range []struct {
		name                         string
		persistent, failArchitecture bool
	}{{"direct", false, false}, {"persistent", true, false}, {"failed-check", true, true}} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			data := filepath.Join(directory, "data")
			const password = "synthetic-smoke-password"
			if err := shellport.Initialize(data, password, []string{"http://127.0.0.1"}, ""); err != nil {
				t.Fatal(err)
			}
			store, err := shellport.OpenStore(data)
			if err != nil {
				t.Fatal(err)
			}
			store.Config.AllowLocalShell = true
			var tmux, socket string
			if test.persistent {
				tmux, err = exec.LookPath("tmux")
				if err != nil {
					t.Skip("tmux integration requires tmux")
				}
				socketDir, err := os.MkdirTemp("/tmp", "sp-smoke-")
				if err != nil {
					t.Fatal(err)
				}
				socket = filepath.Join(socketDir, "tmux.sock")
				t.Cleanup(func() {
					_ = exec.Command(tmux, "-S", socket, "kill-server").Run()
					_ = os.RemoveAll(socketDir)
				})
				quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
				wrapper := filepath.Join(directory, "tmux")
				if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec "+quote(tmux)+" -S "+quote(socket)+" -f /dev/null \"$@\"\n"), 0700); err != nil {
					t.Fatal(err)
				}
				store.Config.TmuxExecutable = wrapper
				if output, err := exec.Command(tmux, "-S", socket, "-f", "/dev/null", "new-session", "-d", "-s", "existing-work").CombinedOutput(); err != nil {
					t.Fatal("Could not create unrelated work fixture", string(output), err)
				}
				if output, err := exec.Command(tmux, "-S", socket, "set-option", "-g", "status", "2").CombinedOutput(); err != nil {
					t.Fatal("Could not configure two-row status fixture", string(output), err)
				}
			}
			target, err := store.SaveHost(shellport.Host{Name: "Test computer", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: test.persistent})
			if err != nil {
				t.Fatal(err)
			}
			if test.persistent {
				if err := store.RememberSession(target, "existing-work", "@17"); err != nil {
					t.Fatal(err)
				}
			}
			before := store.Hosts()
			server := httptest.NewUnstartedServer(nil)
			store.Config.Origins = []string{"http://" + server.Listener.Addr().String()}
			app := shellport.NewServer(store, nil)
			server.Config.Handler = app
			server.Start()
			defer server.Close()
			defer app.Close()
			passwordFile := filepath.Join(directory, "password")
			if err := os.WriteFile(passwordFile, []byte(password+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			arguments := options{origin: server.URL, passwordFile: passwordFile, hostID: target.ID}
			if test.failArchitecture {
				arguments.expectArch = "unexpected-test-architecture"
			}
			receipt, err := run(arguments)
			if test.failArchitecture {
				if err == nil || !strings.Contains(err.Error(), "differs from --expect-arch") {
					t.Fatal("Architecture mismatch was not reported", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				architecture, err := exec.Command("uname", "-m").Output()
				if err != nil || receipt["architecture"] != strings.TrimSpace(string(architecture)) || receipt["tmuxResume"] != test.persistent || receipt["temporaryResourcesRemoved"] != true {
					t.Fatal("Smoke receipt differs from actual checks", receipt, err)
				}
			}
			if after := store.Hosts(); !reflect.DeepEqual(before, after) {
				t.Fatal("Smoke altered an existing computer or left a temporary one", before, after)
			}
			if test.persistent {
				if output, err := exec.Command(tmux, "-S", socket, "list-sessions", "-F", "#{session_name}").CombinedOutput(); err != nil || strings.TrimSpace(string(output)) != "existing-work" {
					t.Fatal("Temporary session remains or unrelated work ended", string(output), err)
				}
			}
		})
	}
}
