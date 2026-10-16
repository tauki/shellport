package shellport

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func expectSessionRename(t *testing.T, ws *websocket.Conn, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		kind, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatal("connected device did not receive rename", err)
		}
		if kind != websocket.MessageText {
			continue
		}
		var message struct{ Type, Session string }
		if err := json.Unmarshal(data, &message); err != nil {
			t.Fatal(err)
		}
		if message.Type == "session-renamed" {
			if message.Session != name {
				t.Fatal("wrong rename notification", message.Session)
			}
			return
		}
	}
}

func TestSessionRenameLocalAndSSH(t *testing.T) {
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
				host.Address, host.Auth = address, "key"
				host.Port, _ = strconv.Atoi(port)
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
			first, a := connectShellTab(t, f, host, map[string]any{"session": "work", "create": true})
			terminalCommand(t, first, "RENAME_PROOF=first; printf 'SET_%s\\n' \"$RENAME_PROOF\"", "SET_first\r\n")
			second, b := connectShellTab(t, f, host, map[string]any{"session": a.Session, "sessionRef": a.SessionRef, "newWindow": true})
			terminalCommand(t, second, "RENAME_PROOF=second; printf 'SET_%s\\n' \"$RENAME_PROOF\"", "SET_second\r\n")
			otherDevice := *f
			jar, _ := cookiejar.New(nil)
			otherDevice.client = &http.Client{Jar: jar, Timeout: 20 * time.Second}
			otherDevice.login(t)
			watcher, _ := connectShellTab(t, &otherDevice, host, map[string]any{"session": a.Session, "sessionRef": a.SessionRef, "window": a.Window.ID})
			if err := exec.Command(wrapper, "new-session", "-d", "-s", "taken").Run(); err != nil {
				t.Fatal(err)
			}
			path := "/api/hosts/" + host.ID
			request := map[string]any{"session": a.Session, "ref": a.SessionRef, "name": "taken"}
			if code := f.call(t, "POST", path+"/tmux-sessions/rename", request, nil); code != 409 {
				t.Fatal("duplicate rename accepted", code)
			}
			for _, invalid := range []string{"", "bad.name", "$(touch nope)", "__shellport_view_bad", strings.Repeat("a", 65)} {
				request["name"] = invalid
				if code := f.call(t, "POST", path+"/tmux-sessions/rename", request, nil); code != 400 {
					t.Fatal("invalid rename accepted", invalid, code)
				}
			}
			request["name"], request["ref"] = "-renamed work", strings.Repeat("0", 64)
			if code := f.call(t, "POST", path+"/tmux-sessions/rename", request, nil); code != 409 {
				t.Fatal("stale rename accepted", code)
			}
			request["ref"] = a.SessionRef
			var renamed struct {
				Session TmuxSession
				Host    Host
				Error   string
			}
			if code := f.call(t, "POST", path+"/tmux-sessions/rename", request, &renamed); code != 200 {
				t.Fatal("rename failed", code, renamed.Error)
			}
			if renamed.Session.Ref != a.SessionRef || renamed.Session.Name != "-renamed work" || renamed.Session.Windows != 2 || renamed.Host.LastSession != renamed.Session.Name || renamed.Host.LastWindow != a.Window.ID {
				t.Fatal("rename changed identity, windows or Continue", renamed)
			}
			expectSessionRename(t, first, renamed.Session.Name)
			expectSessionRename(t, second, renamed.Session.Name)
			expectSessionRename(t, watcher, renamed.Session.Name)
			terminalCommand(t, first, "printf 'ALIVE_%s\\n' \"$RENAME_PROOF\"", "ALIVE_first\r\n")
			terminalCommand(t, second, "printf 'ALIVE_%s\\n' \"$RENAME_PROOF\"", "ALIVE_second\r\n")
			if exec.Command(wrapper, "has-session", "-t", "="+a.Session).Run() == nil {
				t.Fatal("old session name still exists")
			}
			if err := exec.Command(wrapper, "has-session", "-t", "="+renamed.Session.Name).Run(); err != nil {
				t.Fatal("remote rename not applied", err)
			}
			// Reusing the old name must never redirect a disconnected device's ref.
			if err := exec.Command(wrapper, "new-session", "-d", "-s", a.Session).Run(); err != nil {
				t.Fatal(err)
			}
			resumed, reply := connectShellTab(t, &otherDevice, host, map[string]any{"session": a.Session, "sessionRef": a.SessionRef, "window": b.Window.ID})
			if reply.Session != renamed.Session.Name || reply.SessionRef != a.SessionRef || reply.Window.ID != b.Window.ID {
				t.Fatal("reconnect followed replacement name instead of original session", reply)
			}
			terminalCommand(t, resumed, "printf 'RESUME_%s\\n' \"$RENAME_PROOF\"", "RESUME_second\r\n")
			if code := f.call(t, "POST", "/api/terminals/"+a.ID+"/select", map[string]any{}, nil); code != 200 {
				t.Fatal("original terminal selection failed", code)
			}
			var windows struct {
				LastWindow string
				Windows    []TmuxWindow
			}
			if code := f.call(t, "POST", path+"/tmux-windows", map[string]any{"session": a.Session, "ref": a.SessionRef}, &windows); code != 200 || len(windows.Windows) != 2 || windows.LastWindow != a.Window.ID {
				t.Fatal("stale device could not browse original tabs", code, windows)
			}
			reopened, err := OpenStore(f.store.Dir)
			if err != nil {
				t.Fatal(err)
			}
			selected, _ := reopened.Host(host.ID)
			if selected.LastSession != renamed.Session.Name || selected.LastWindow != a.Window.ID {
				t.Fatal("renamed selection was not persisted", selected.LastSession, selected.LastWindow)
			}
			if code := f.call(t, "POST", path+"/tmux-sessions/rename", request, nil); code != 409 {
				t.Fatal("stale name could rename another session", code)
			}
		})
	}
}

func TestRememberedRenamePreservesAnotherSelection(t *testing.T) {
	f := newFixture(t)
	host, err := f.store.SaveHost(Host{Name: "Fixture", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.RememberSession(host, "other", "@7"); err != nil {
		t.Fatal(err)
	}
	if err = f.store.RenameSession(host, "work", "renamed"); err != nil {
		t.Fatal(err)
	}
	selected, _ := f.store.Host(host.ID)
	if selected.LastSession != "other" || selected.LastWindow != "@7" {
		t.Fatal("rename replaced another Continue choice")
	}
}

func TestRenameUnselectedDefaultPreservesFallback(t *testing.T) {
	f := newFixture(t)
	host, err := f.store.SaveHost(Host{Name: "Fixture", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.RenameSession(host, "shellport-"+host.ID, "work"); err != nil {
		t.Fatal(err)
	}
	selected, _ := f.store.Host(host.ID)
	if selected.LastSession != "work" || selected.LastWindow != "" {
		t.Fatal("default fallback was lost after rename")
	}
}
