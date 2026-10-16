package shellport

import (
	"context"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestTerminalConnectionCleanupLocalAndSSH(t *testing.T) {
	for _, remote := range []bool{false, true} {
		name := "local"
		if remote {
			name = "SSH"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("SHELL", "/bin/sh")
			f := newFixture(t)
			f.login(t)
			host := Host{Name: "One computer", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local"}
			if remote {
				ssh := serveTestSSH(t, f.store)
				address, port, _ := net.SplitHostPort(ssh.listener.Addr().String())
				host.Address, host.Auth = address, "key"
				host.Port, _ = strconv.Atoi(port)
				var err error
				host, err = f.store.SaveHost(host)
				if err != nil {
					t.Fatal(err)
				}
				if err = f.store.TrustHost(host.ID, host.Address, host.Port, ssh.key); err != nil {
					t.Fatal(err)
				}
			} else {
				f.store.Config.AllowLocalShell = true
				var err error
				host, err = f.store.SaveHost(host)
				if err != nil {
					t.Fatal(err)
				}
			}
			jar, _ := cookiejar.New(nil)
			other := &fixture{f.store, f.app, f.http, &http.Client{Jar: jar, Timeout: 10 * time.Second}}
			if code := other.call(t, "DELETE", "/api/terminals/unknown", nil, nil); code != 401 {
				t.Fatal("unauthenticated cancellation", code)
			}
			other.login(t)
			for _, attached := range []bool{false, true} {
				var opened tabReply
				if code := f.call(t, "POST", "/api/hosts/"+host.ID+"/connect", map[string]any{"direct": true, "cols": 80, "rows": 24}, &opened); code != 200 {
					t.Fatal("connect", code, opened.Error)
				}
				path := "/api/terminals/" + opened.ID
				f.app.mu.Lock()
				terminal := f.app.terminals[opened.ID]
				f.app.mu.Unlock()
				// Repeated closing is safe without granting another device access.
				if code := other.call(t, "DELETE", path, nil, nil); code != 200 {
					t.Fatal(code)
				}
				select {
				case <-terminal.ctx.Done():
					t.Fatal("another device closed the terminal")
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				url := "ws" + strings.TrimPrefix(f.http.URL, "http") + path + "/terminal"
				if attached {
					socket, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: f.client, HTTPHeader: http.Header{"Origin": {f.http.URL}}})
					if err != nil {
						t.Fatal(err)
					}
					newline := "\r\n"
					if remote {
						newline = "\n"
					}
					terminalCommand(t, socket, "printf 'TERMINAL_%s\\n' alive", "TERMINAL_alive"+newline)
					_ = socket.Close(websocket.StatusNormalClosure, "Tab closed")
				} else {
					if code := f.call(t, "DELETE", path, nil, nil); code != 200 {
						t.Fatal("pending cancellation", code)
					}
					// An unattached local process has no WebSocket wait goroutine.
					if terminal.process != nil {
						_ = terminal.wait()
					}
				}
				select {
				case <-terminal.ctx.Done():
				case <-ctx.Done():
					t.Fatal("terminal leaked after close")
				}
				f.app.mu.Lock()
				_, exists := f.app.terminals[opened.ID]
				f.app.mu.Unlock()
				if exists {
					t.Fatal("closed terminal remains registered")
				}
				for i := 0; i < 2; i++ {
					if code := f.call(t, "DELETE", path, nil, nil); code != 200 {
						t.Fatal("repeated cancellation", code)
					}
				}
				_, res, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: f.client, HTTPHeader: http.Header{"Origin": {f.http.URL}}})
				if err == nil || res == nil || res.StatusCode != 404 {
					t.Fatal("closed terminal can attach", err)
				}
			}
		})
	}
}
