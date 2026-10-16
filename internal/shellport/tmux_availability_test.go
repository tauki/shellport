package shellport

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTmuxAvailabilityWithNonPOSIXLoginShell(t *testing.T) {
	shell, err := exec.LookPath("tcsh")
	if err != nil {
		t.Skip("non-POSIX SSH integration requires tcsh on PATH")
	}
	for _, scenario := range []string{"available", "missing", "permission"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			f.login(t)
			root := filepath.Join(t.TempDir(), "account's tools")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			if scenario == "available" {
				root = filepath.Dir(testTmux(t))
			} else if scenario == "permission" {
				if err := os.WriteFile(filepath.Join(root, "tmux"), []byte("#!/bin/sh\nexit 0\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			remote := serveTestSSHWithShell(t, f.store, []string{shell, "-f", "-c"}, root, root)
			address, port, _ := net.SplitHostPort(remote.listener.Addr().String())
			number, _ := strconv.Atoi(port)
			host, err := f.store.SaveHost(Host{Name: "Non-POSIX fixture", Address: address, Port: number, Username: "tester", Auth: "key", Tmux: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := f.store.TrustHost(host.ID, host.Address, host.Port, remote.key); err != nil {
				t.Fatal(err)
			}
			var result struct {
				Available bool
				Reason    string
				Error     string
				Sessions  []TmuxSession
			}
			code := f.call(t, "POST", "/api/hosts/"+host.ID+"/tmux-sessions", map[string]any{}, &result)
			switch scenario {
			case "available":
				if code != 200 || !result.Available || result.Sessions == nil {
					t.Fatal("tmux discovery failed under a non-POSIX login shell", code, result)
				}
			case "missing":
				if code != 200 || result.Available || result.Reason == "" || result.Sessions == nil {
					t.Fatal("missing tmux was not discovered under a non-POSIX login shell", code, result)
				}
			case "permission":
				if code != 502 || !strings.Contains(result.Error, "cannot execute") || result.Reason != "" {
					t.Fatal("execution failure was lost or misreported as missing tmux", code, result)
				}
			}
		})
	}
}

func TestTmuxAvailabilitySeparatesMissingFromFailures(t *testing.T) {
	for _, scenario := range []string{"local-missing", "local-permission", "local-command-failure", "local-disabled", "ssh-missing", "ssh-permission", "ssh-command-failure", "ssh-loader-failure", "ssh-command-denied"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("SHELL", "/bin/sh")
			f := newFixture(t)
			f.login(t)
			h := Host{Name: "Fixture", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local"}
			root := t.TempDir()
			binary := filepath.Join(root, "tmux")
			missing := strings.HasSuffix(scenario, "missing")
			if !missing {
				status := "126"
				if scenario == "ssh-loader-failure" {
					status = "127"
				}
				if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf 'synthetic tmux command failure\\n' >&2\nexit "+status+"\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "ssh-permission" {
				if err := os.Chmod(binary, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(scenario, "ssh-") {
				var remote *sshFixture
				if scenario == "ssh-command-denied" {
					remote = serveTestSSH(t, f.store)
				} else {
					remote = serveTestSSH(t, f.store, root, root)
				}
				address, port, _ := net.SplitHostPort(remote.listener.Addr().String())
				h.Address, h.Auth = address, "key"
				h.Port, _ = strconv.Atoi(port)
				saved, err := f.store.SaveHost(h)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.store.TrustHost(saved.ID, saved.Address, saved.Port, remote.key); err != nil {
					t.Fatal(err)
				}
				h, _ = f.store.Host(saved.ID)
			} else {
				f.store.Config.AllowLocalShell = scenario != "local-disabled"
				f.store.Config.TmuxExecutable = binary
				if scenario == "local-permission" {
					if err := os.Chmod(binary, 0600); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				h, err = f.store.SaveHost(h)
				if err != nil {
					t.Fatal(err)
				}
			}
			var result struct {
				Available bool
				Reason    string
				Error     string
				Sessions  []TmuxSession
			}
			code := f.call(t, "POST", "/api/hosts/"+h.ID+"/tmux-sessions", map[string]any{}, &result)
			if missing {
				if code != 200 || result.Available || result.Reason == "" || result.Sessions == nil {
					t.Fatal("missing executable was not a confirmed unavailable capability", code, result)
				}
				ws, reply := connectShellTab(t, f, h, map[string]any{"direct": true})
				if reply.Tmux {
					t.Fatal("missing tmux prevented a direct shell")
				}
				marker := "DIRECT_ready\r\n"
				if strings.HasPrefix(scenario, "ssh-") {
					marker = "DIRECT_ready\n"
				}
				terminalCommand(t, ws, "printf 'DIRECT_%s\\n' ready", marker)
			} else if code != 502 || result.Error == "" || result.Reason != "" {
				t.Fatal("execution/access failure was misreported as missing tmux", code, result)
			}
			if strings.Contains(scenario, "command-failure") || scenario == "ssh-loader-failure" {
				if !strings.Contains(result.Error, "synthetic tmux command failure") {
					t.Fatal("tmux diagnostic was lost", result.Error)
				}
			}
		})
	}
}

func TestLegacyDirectComputerCanUseAndManageSavedSessions(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	f.store.Config.AllowLocalShell = true
	f.store.Config.TmuxExecutable = testTmux(t)
	h, err := f.store.SaveHost(Host{Name: "Legacy direct preference", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: false})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/hosts/" + h.ID
	var directory struct{ Available bool }
	if code := f.call(t, "POST", path+"/tmux-sessions", map[string]any{}, &directory); code != 200 || !directory.Available {
		t.Fatal("legacy preference hid the computer's capability", code)
	}
	ws, saved := connectShellTab(t, f, h, map[string]any{"create": true, "session": "work"})
	terminalCommand(t, ws, "VALUE=kept; printf 'START_%s\\n' \"$VALUE\"", "START_kept\r\n")
	if !saved.Tmux || saved.Host.Tmux {
		t.Fatal("effective saved mode changed the legacy preference", saved)
	}
	before, _ := f.store.Host(h.ID)
	var edited Host
	if code := f.call(t, "PUT", path, map[string]any{"name": "Renamed computer", "address": h.Address, "port": h.Port, "username": h.Username, "auth": h.Auth}, &edited); code != 200 || edited.Tmux || edited.LastSessionRef != before.LastSessionRef {
		t.Fatal("editing connection details without a checkbox lost preference or Continue", code, edited)
	}
	choice := map[string]any{"session": saved.Session, "ref": saved.SessionRef, "window": saved.Window.ID, "name": "named tab"}
	if code := f.call(t, "POST", path+"/tmux-windows/rename", choice, nil); code != 200 {
		t.Fatal("legacy preference blocked renaming a saved tab", code)
	}
	if code := f.call(t, "POST", path+"/tmux-sessions/rename", map[string]any{"session": saved.Session, "ref": saved.SessionRef, "name": "renamed"}, nil); code != 200 {
		t.Fatal("legacy preference blocked renaming a saved session", code)
	}
	choice["session"], choice["confirm"] = "renamed", true
	if code := f.call(t, "POST", path+"/tmux-windows/close", choice, nil); code != 200 {
		t.Fatal("legacy preference blocked closing a saved tab", code)
	}
	after, _ := f.store.Host(h.ID)
	if after.Tmux || after.LastSessionRef != "" {
		t.Fatal("closing the last saved tab did not clear only Continue", after)
	}
}
