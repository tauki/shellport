package shellport

import (
	"context"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type tabReply struct {
	ID, Session, SessionRef string
	Error                   string
	Window                  TmuxWindow
	Host                    Host
	Tmux                    bool
}

func connectShellTab(t *testing.T, f *fixture, h Host, choice map[string]any) (*websocket.Conn, tabReply) {
	t.Helper()
	choice["cols"], choice["rows"] = 80, 24
	if _, explicit := choice["direct"]; !explicit {
		choice["direct"] = false
	}
	var reply tabReply
	if code := f.call(t, "POST", "/api/hosts/"+h.ID+"/connect", choice, &reply); code != 200 {
		t.Fatalf("shell tab connect returned HTTP %d: %s", code, reply.Error)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.http.URL, "http")+"/api/terminals/"+reply.ID+"/terminal", &websocket.DialOptions{HTTPClient: f.client, HTTPHeader: http.Header{"Origin": {f.http.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.CloseNow() })
	return ws, reply
}

func TestSessionManagementLocalAndSSH(t *testing.T) {
	for _, remote := range []bool{false, true} {
		name := "local"
		if remote {
			name = "SSH"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.login(t)
			wrapper := testTmux(t)
			host := Host{Name: "Fixture", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: true}
			if remote {
				ssh := serveTestSSH(t, f.store, filepath.Dir(wrapper))
				address, port, _ := net.SplitHostPort(ssh.listener.Addr().String())
				host.Address = address
				host.Port, _ = strconv.Atoi(port)
				host.Auth = "key"
				saved, err := f.store.SaveHost(host)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.store.TrustHost(saved.ID, saved.Address, saved.Port, ssh.key); err != nil {
					t.Fatal(err)
				}
				host, _ = f.store.Host(saved.ID)
			} else {
				f.store.Config.AllowLocalShell = true
				f.store.Config.TmuxExecutable = wrapper
				var err error
				host, err = f.store.SaveHost(host)
				if err != nil {
					t.Fatal(err)
				}
			}
			first, a := connectShellTab(t, f, host, map[string]any{"create": true})
			if !regexp.MustCompile(`^[a-f0-9]{6}$`).MatchString(a.Session) || a.SessionRef == "" || a.Window.ID == "" {
				t.Fatal("blank name was not generated on the server")
			}
			terminalCommand(t, first, "TAB_PROOF=first; printf 'FIRST_%s\\n' \"$TAB_PROOF\"", "FIRST_first\r\n")
			second, b := connectShellTab(t, f, host, map[string]any{"session": a.Session, "sessionRef": a.SessionRef, "newWindow": true})
			if a.Session != b.Session || a.SessionRef != b.SessionRef || a.Window.ID == b.Window.ID {
				t.Fatal("new tab did not share the session with its own window")
			}
			terminalCommand(t, second, "printf 'EMPTY_%s\\n' \"${TAB_PROOF-unset}\"; TAB_PROOF=second", "EMPTY_unset\r\n")
			terminalCommand(t, first, "printf 'STILL_%s\\n' \"$TAB_PROOF\"", "STILL_first\r\n")
			terminalCommand(t, second, "printf 'SECOND_%s\\n' \"$TAB_PROOF\"", "SECOND_second\r\n")
			// Recovery can finish after the user has selected another tab. It
			// attaches to its exact shell without overwriting that selection.
			recovery, recovered := connectShellTab(t, f, host, map[string]any{"session": a.Session, "sessionRef": a.SessionRef, "window": a.Window.ID, "remember": false})
			terminalCommand(t, recovery, "printf 'AUTO_%s\\n' \"$TAB_PROOF\"", "AUTO_first\r\n")
			remembered, _ := f.store.Host(host.ID)
			if remembered.LastWindow != b.Window.ID {
				t.Fatal("automatic recovery overwrote the user's selected tab")
			}
			f.call(t, "DELETE", "/api/terminals/"+recovered.ID, nil, nil)
			var directory struct {
				Sessions    []TmuxSession
				LastSession string
			}
			path := "/api/hosts/" + host.ID
			if code := f.call(t, "POST", path+"/tmux-sessions", map[string]any{}, &directory); code != 200 || len(directory.Sessions) != 1 || directory.Sessions[0].Windows != 2 || directory.Sessions[0].Attached != 2 {
				t.Fatal("internal client views leaked into session directory", code, directory)
			}
			var windowList struct {
				Windows    []TmuxWindow
				LastWindow string
			}
			if code := f.call(t, "POST", path+"/tmux-windows", map[string]any{"session": a.Session, "ref": a.SessionRef}, &windowList); code != 200 || len(windowList.Windows) != 2 || windowList.LastWindow != b.Window.ID {
				t.Fatal("tab directory or remembered tab mismatch", code)
			}
			if code := f.call(t, "POST", "/api/terminals/"+a.ID+"/select", map[string]any{}, nil); code != 200 {
				t.Fatal("focusing an existing tab was not remembered", code)
			}
			selected, _ := f.store.Host(host.ID)
			if selected.LastWindow != a.Window.ID {
				t.Fatal("Continue did not follow the selected existing tab")
			}
			f.call(t, "DELETE", "/api/terminals/"+a.ID, nil, nil)
			secondDevice := *f
			jar, _ := cookiejar.New(nil)
			secondDevice.client = &http.Client{Jar: jar, Timeout: 20 * time.Second}
			secondDevice.login(t)
			resumed, resume := connectShellTab(t, &secondDevice, host, map[string]any{"session": a.Session, "sessionRef": a.SessionRef, "window": a.Window.ID})
			terminalCommand(t, resumed, "printf 'RESUMED_%s\\n' \"$TAB_PROOF\"", "RESUMED_first\r\n")
			f.call(t, "DELETE", "/api/terminals/"+b.ID, nil, nil)
			secondDevice.call(t, "DELETE", "/api/terminals/"+resume.ID, nil, nil)
			unrelated, other := connectShellTab(t, f, host, map[string]any{"create": true})
			if other.Session == a.Session {
				t.Fatal("generated names collided")
			}
			terminalCommand(t, unrelated, "printf 'OTHER_%s\\n' ok", "OTHER_ok\r\n")
			victim, v := connectShellTab(t, &secondDevice, host, map[string]any{"session": a.Session, "sessionRef": a.SessionRef, "window": b.Window.ID})
			terminalCommand(t, victim, "printf 'VICTIM_%s\\n' \"$TAB_PROOF\"", "VICTIM_second\r\n")
			del := map[string]any{"session": a.Session, "ref": a.SessionRef, "confirm": false}
			if code := f.call(t, "POST", path+"/tmux-sessions/delete", del, nil); code != 400 {
				t.Fatal("deletion did not require confirmation", code)
			}
			del["confirm"] = true
			del["session"] = "session"
			if code := f.call(t, "POST", path+"/tmux-sessions/delete", del, nil); code != 409 {
				t.Fatal("prefix deletion was accepted", code)
			}
			del["session"] = a.Session
			del["ref"] = strings.Repeat("0", 64)
			if code := f.call(t, "POST", path+"/tmux-sessions/delete", del, nil); code != 409 {
				t.Fatal("stale session reference was accepted", code)
			}
			del["ref"] = a.SessionRef
			if code := f.call(t, "POST", path+"/tmux-sessions/delete", del, nil); code != 200 {
				t.Fatal("confirmed deletion failed", code)
			}
			if code := f.call(t, "POST", path+"/tmux-sessions", map[string]any{}, &directory); code != 200 || len(directory.Sessions) != 1 || directory.Sessions[0].Name != other.Session || directory.LastSession != "" {
				t.Fatal("delete removed unrelated work or retained deleted Continue choice", code, directory)
			}
			if exec.Command(wrapper, "has-session", "-t", "="+a.Session).Run() == nil {
				t.Fatal("deleted session remains on computer")
			}
			terminalCommand(t, unrelated, "printf 'SAFE_%s\\n' ok", "SAFE_ok\r\n")
			if code := secondDevice.call(t, "POST", path+"/connect", map[string]any{"session": a.Session, "sessionRef": a.SessionRef, "window": v.Window.ID, "cols": 80, "rows": 24}, nil); code != 409 {
				t.Fatal("deleted session was recreated by reconnect", code)
			}
			f.call(t, "DELETE", "/api/terminals/"+other.ID, nil, nil)
			raw, err := rawTmuxSessions(context.Background(), localTmuxRunner(Config{TmuxExecutable: wrapper}, wrapper))
			if err != nil {
				t.Fatal(err)
			}
			for _, session := range raw {
				if managedView(session) {
					t.Fatal("temporary client view survived detach")
				}
			}
		})
	}
}

func TestSessionDeletionRefDoesNotDeleteReplacement(t *testing.T) {
	wrapper := testTmux(t)
	run := localTmuxRunner(Config{TmuxExecutable: wrapper}, wrapper)
	ctx := context.Background()
	original, err := chooseTmux(ctx, run, Host{ID: "fixture"}, tmuxChoice{Name: "work", Create: true}, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if err = exec.Command(wrapper, "kill-session", "-t", original.id).Run(); err != nil {
		t.Fatal(err)
	}
	_, err = chooseTmux(ctx, run, Host{ID: "fixture"}, tmuxChoice{Name: "work", Create: true}, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if err = deleteTmuxSession(ctx, run, "work", original.Ref, func() error { return nil }); err == nil {
		t.Fatal("stale delete accepted replacement")
	}
	if err = exec.Command(wrapper, "has-session", "-t", "=work").Run(); err != nil {
		t.Fatal("replacement session was deleted")
	}
}

func TestTmuxViewPreparation(t *testing.T) {
	wrapper := testTmux(t)
	base := localTmuxRunner(Config{TmuxExecutable: wrapper}, wrapper)
	run := func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		out, diag, err := base(ctx, args...)
		if err != nil {
			t.Logf("fixture tmux %q: %s", args, diag)
		}
		return out, diag, err
	}
	ctx := context.Background()
	session, err := chooseTmux(ctx, run, Host{ID: "fixture"}, tmuxChoice{Name: "work", Create: true}, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	window, err := chooseTmuxWindow(ctx, run, Host{}, session, tmuxChoice{})
	if err != nil {
		t.Fatal(err)
	}
	_, cleanup, err := createTmuxView(ctx, run, session, window)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if err = exec.Command(wrapper, "has-session", "-t", "=work").Run(); err != nil {
		t.Fatal("view cleanup removed the persistent session")
	}
}
