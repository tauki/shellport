package shellport

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestDirectShellOverridePreservesSavedSessions(t *testing.T) {
	for _, remote := range []bool{false, true} {
		name := "local"
		if remote {
			name = "SSH"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("SHELL", "/bin/sh")
			newline := "\r\n"
			if remote {
				newline = "\n"
			}
			f := newFixture(t)
			f.login(t)
			wrapper := testTmux(t)
			h := Host{Name: "One computer", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: true}
			var keyHost func(Host) Host
			if remote {
				ssh := serveTestSSH(t, f.store, filepath.Dir(wrapper))
				address, port, _ := net.SplitHostPort(ssh.listener.Addr().String())
				h.Address, h.Auth = address, "key"
				h.Port, _ = strconv.Atoi(port)
				keyHost = func(saved Host) Host {
					if err := f.store.TrustHost(saved.ID, saved.Address, saved.Port, ssh.key); err != nil {
						t.Fatal(err)
					}
					trusted, _ := f.store.Host(saved.ID)
					return trusted
				}
			} else {
				f.store.Config.AllowLocalShell = true
				f.store.Config.TmuxExecutable = wrapper
			}
			var err error
			h, err = f.store.SaveHost(h)
			if err != nil {
				t.Fatal(err)
			}
			if keyHost != nil {
				h = keyHost(h)
			}
			saved, selected := connectShellTab(t, f, h, map[string]any{"create": true, "session": "work"})
			terminalCommand(t, saved, "SAVED_VALUE=kept; printf 'SAVED_%s\\n' \"$SAVED_VALUE\"", "SAVED_kept\r\n")
			before, _ := f.store.Host(h.ID)
			direct, opened := connectShellTab(t, f, h, map[string]any{"direct": true})
			if opened.Tmux || !opened.Host.Tmux || opened.Session != "" || opened.SessionRef != "" || opened.Window.ID != "" {
				t.Fatal("direct connection changed the saved profile or attached to tmux", opened)
			}
			terminalCommand(t, direct, "DIRECT_VALUE=temporary; printf 'DIRECT_%s_%s\\n' \"${TMUX-unset}\" \"${SAVED_VALUE-unset}\"", "DIRECT_unset_unset"+newline)
			if code := f.call(t, "POST", "/api/terminals/"+opened.ID+"/select", map[string]any{}, nil); code != 404 {
				t.Fatal("direct shell was remembered as a saved session", code)
			}
			f.app.mu.Lock()
			connection := f.app.terminals[opened.ID]
			f.app.mu.Unlock()
			_ = direct.Close(websocket.StatusNormalClosure, "Direct tab closed")
			select {
			case <-connection.ctx.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("WebSocket close did not clean up the direct terminal")
			}
			fresh, _ := connectShellTab(t, f, h, map[string]any{"direct": true})
			terminalCommand(t, fresh, "printf 'FRESH_%s\\n' \"${DIRECT_VALUE-unset}\"", "FRESH_unset"+newline)
			after, _ := f.store.Host(h.ID)
			if after != before {
				t.Fatal("direct shells changed the computer or its Continue selection")
			}
			terminalCommand(t, saved, "printf 'SURVIVES_%s\\n' \"$SAVED_VALUE\"", "SURVIVES_kept\r\n")
			continued, reply := connectShellTab(t, f, h, map[string]any{})
			if !reply.Tmux || reply.SessionRef != selected.SessionRef || reply.Window.ID != selected.Window.ID {
				t.Fatal("default connection stopped using the original saved selection", reply)
			}
			terminalCommand(t, continued, "printf 'CONTINUE_%s\\n' \"$SAVED_VALUE\"", "CONTINUE_kept\r\n")
		})
	}
}

func TestDirectShellRejectsTmuxChoicesAndKeepsAccessChecks(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	h, err := f.store.SaveHost(Host{Name: "Local", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: true})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/hosts/" + h.ID + "/connect"
	for _, extra := range []map[string]any{
		{"session": "work"}, {"create": true}, {"sessionRef": "saved"}, {"window": "@0"}, {"newWindow": true}, {"mode": TmuxManaged},
	} {
		extra["direct"], extra["cols"], extra["rows"] = true, 80, 24
		if code := f.call(t, "POST", path, extra, nil); code != 400 {
			t.Fatal("mixed direct/tmux request accepted", extra, code)
		}
	}
	if code := f.call(t, "POST", path, map[string]any{"direct": true, "cols": 80, "rows": 24}, nil); code != 502 {
		t.Fatal("direct override enabled disabled local terminals", code)
	}
	remote := serveTestSSH(t, f.store)
	address, port, _ := net.SplitHostPort(remote.listener.Addr().String())
	h.ID, h.Auth, h.Address = "", "key", address
	h.Port, _ = strconv.Atoi(port)
	h, err = f.store.SaveHost(h)
	if err != nil {
		t.Fatal(err)
	}
	if code := f.call(t, "POST", "/api/hosts/"+h.ID+"/connect", map[string]any{"direct": true, "cols": 80, "rows": 24}, nil); code != 502 {
		t.Fatal("direct override bypassed SSH identity verification", code)
	}
}
