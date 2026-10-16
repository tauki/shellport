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

func expectWindowRename(t *testing.T, ws *websocket.Conn, id, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		kind, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatal("connected device did not receive tab name", err)
		}
		if kind != websocket.MessageText {
			continue
		}
		var message struct{ Type, Window, Name string }
		if err := json.Unmarshal(data, &message); err != nil {
			t.Fatal(err)
		}
		if message.Type == "tab-renamed" {
			if message.Window != id || message.Name != name {
				t.Fatal("wrong tab rename notification", message)
			}
			return
		}
	}
}

func expectWindowDisconnected(t *testing.T, ws *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		if _, _, err := ws.Read(ctx); err != nil {
			if ctx.Err() != nil {
				t.Fatal("closed tab remained connected or switched to another shell")
			}
			return
		}
	}
}

func TestWindowManagementLocalAndSSH(t *testing.T) {
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
			otherDevice := *f
			jar, _ := cookiejar.New(nil)
			otherDevice.client = &http.Client{Jar: jar, Timeout: 20 * time.Second}
			otherDevice.login(t)
			first, a := connectShellTab(t, f, host, map[string]any{"session": "work", "create": true})
			terminalCommand(t, first, "TAB_STATE=first; printf 'SET_%s\\n' \"$TAB_STATE\"", "SET_first\r\n")
			second, b := connectShellTab(t, &otherDevice, host, map[string]any{"session": a.Session, "sessionRef": a.SessionRef, "newWindow": true})
			terminalCommand(t, second, "TAB_STATE=second; printf 'SET_%s\\n' \"$TAB_STATE\"", "SET_second\r\n")
			watcher, _ := connectShellTab(t, &otherDevice, host, map[string]any{"session": a.Session, "sessionRef": a.SessionRef, "window": a.Window.ID})
			other, unrelated := connectShellTab(t, f, host, map[string]any{"session": "other", "create": true})
			path := "/api/hosts/" + host.ID + "/tmux-windows"
			request := map[string]any{"session": a.Session, "ref": a.SessionRef, "window": a.Window.ID, "name": "-build logs"}
			for _, invalid := range []string{"", "bad.name", "$(touch nope)", "__shellport_view_bad", strings.Repeat("a", 65)} {
				request["name"] = invalid
				if code := f.call(t, "POST", path+"/rename", request, nil); code != 400 {
					t.Fatal("invalid tab name accepted", invalid, code)
				}
			}
			request["name"], request["ref"] = "-build logs", strings.Repeat("0", 64)
			if code := f.call(t, "POST", path+"/rename", request, nil); code != 409 {
				t.Fatal("stale tab rename accepted", code)
			}
			request["ref"], request["window"] = a.SessionRef, unrelated.Window.ID
			if code := f.call(t, "POST", path+"/rename", request, nil); code != 409 {
				t.Fatal("renamed a window outside selected session", code)
			}
			request["window"] = a.Window.ID
			var reply struct{ Window TmuxWindow }
			if code := f.call(t, "POST", path+"/rename", request, &reply); code != 200 || reply.Window.ID != a.Window.ID || reply.Window.Name != "-build logs" {
				t.Fatal("tab rename failed or changed identity", code, reply)
			}
			expectWindowRename(t, first, a.Window.ID, "-build logs")
			expectWindowRename(t, watcher, a.Window.ID, "-build logs")
			if output, err := exec.Command(wrapper, "show-options", "-wv", "-t", a.Window.ID, "automatic-rename").Output(); err != nil || strings.TrimSpace(string(output)) != "off" {
				t.Fatal("custom tab name would be replaced automatically", string(output), err)
			}
			terminalCommand(t, first, "printf 'RENAMED_%s\\n' \"$TAB_STATE\"", "RENAMED_first\r\n")
			terminalCommand(t, second, "printf 'UNTOUCHED_%s\\n' \"$TAB_STATE\"", "UNTOUCHED_second\r\n")
			f.call(t, "POST", "/api/terminals/"+b.ID+"/select", map[string]any{}, nil) // other owner cannot select it
			if code := otherDevice.call(t, "POST", "/api/terminals/"+b.ID+"/select", map[string]any{}, nil); code != 200 {
				t.Fatal("could not remember closing tab", code)
			}
			request = map[string]any{"session": a.Session, "ref": a.SessionRef, "window": b.Window.ID}
			if code := f.call(t, "POST", path+"/close", request, nil); code != 400 {
				t.Fatal("tab close did not require confirmation", code)
			}
			request["confirm"], request["window"] = true, unrelated.Window.ID
			if code := f.call(t, "POST", path+"/close", request, nil); code != 409 {
				t.Fatal("closed a window outside selected session", code)
			}
			request["window"], request["ref"] = b.Window.ID, strings.Repeat("0", 64)
			if code := f.call(t, "POST", path+"/close", request, nil); code != 409 {
				t.Fatal("stale tab close accepted", code)
			}
			request["ref"] = a.SessionRef
			if code := f.call(t, "POST", path+"/close", request, nil); code != 200 {
				t.Fatal("confirmed tab close failed", code)
			}
			expectWindowDisconnected(t, second)
			selected, _ := f.store.Host(host.ID)
			if selected.LastSession != a.Session || selected.LastWindow != "" {
				t.Fatal("closed tab remained the Continue selection", selected.LastSession, selected.LastWindow)
			}
			terminalCommand(t, first, "printf 'SURVIVES_%s\\n' \"$TAB_STATE\"", "SURVIVES_first\r\n")
			terminalCommand(t, other, "printf 'OTHER_%s\\n' ok", "OTHER_ok\r\n")
			if code := f.call(t, "POST", "/api/hosts/"+host.ID+"/connect", map[string]any{"session": a.Session, "sessionRef": a.SessionRef, "window": b.Window.ID, "cols": 80, "rows": 24}, nil); code != 409 {
				t.Fatal("reconnect recreated closed tab", code)
			}
			if code := f.call(t, "POST", path+"/close", request, nil); code != 409 {
				t.Fatal("repeated close affected another window", code)
			}
			request["window"] = a.Window.ID
			if code := f.call(t, "POST", path+"/close", request, nil); code != 200 {
				t.Fatal("closing last tab failed", code)
			}
			expectWindowDisconnected(t, first)
			expectWindowDisconnected(t, watcher)
			if exec.Command(wrapper, "has-session", "-t", "="+a.Session).Run() == nil {
				t.Fatal("empty session survived closing its last tab")
			}
			reopened, err := OpenStore(f.store.Dir)
			if err != nil {
				t.Fatal(err)
			}
			selected, _ = reopened.Host(host.ID)
			if selected.LastSession != "" || selected.LastWindow != "" {
				t.Fatal("ended session selection persisted")
			}
			terminalCommand(t, other, "printf 'STILL_%s\\n' ok", "STILL_ok\r\n")
		})
	}
}

func TestWindowClosePreservesLinkedAndGroupedWork(t *testing.T) {
	wrapper := testTmux(t)
	run := localTmuxRunner(Config{TmuxExecutable: wrapper}, wrapper)
	ctx := context.Background()
	parent, err := chooseTmux(ctx, run, Host{ID: "fixture"}, tmuxChoice{Name: "work", Create: true}, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	window, err := chooseTmuxWindow(ctx, run, Host{}, parent, tmuxChoice{})
	if err != nil {
		t.Fatal(err)
	}
	if err = exec.Command(wrapper, "new-session", "-d", "-t", parent.id, "-s", "external-group").Run(); err != nil {
		t.Fatal(err)
	}
	if err = closeTmuxWindow(ctx, run, parent.Name, parent.Ref, window.ID, func() error { return nil }); err == nil {
		t.Fatal("close modified an externally grouped session")
	}
	if err = exec.Command(wrapper, "kill-session", "-t", "=external-group").Run(); err != nil {
		t.Fatal(err)
	}
	if err = exec.Command(wrapper, "new-session", "-d", "-s", "linked").Run(); err != nil {
		t.Fatal(err)
	}
	if err = exec.Command(wrapper, "link-window", "-d", "-s", parent.id+":"+window.ID, "-t", "linked:").Run(); err != nil {
		t.Fatal(err)
	}
	if err = closeTmuxWindow(ctx, run, parent.Name, parent.Ref, window.ID, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if exec.Command(wrapper, "has-session", "-t", "=work").Run() == nil {
		t.Fatal("closed last link remained in selected session")
	}
	if output, err := exec.Command(wrapper, "list-windows", "-t", "=linked", "-F", "#{window_id}").Output(); err != nil || !strings.Contains(string(output), window.ID+"\n") {
		t.Fatal("closing destroyed work linked to another session", string(output), err)
	}
}
