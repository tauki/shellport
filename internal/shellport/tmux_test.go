package shellport

import (
	"context"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func testTmux(t *testing.T) string {
	t.Helper()
	binary, err := exec.LookPath("tmux")
	if err != nil {
		t.Skip("real tmux integration requires tmux on PATH")
	}
	file := filepath.Join(t.TempDir(), "tmux")
	socket := "shellport-test-" + randomID()[:12]
	// A private socket and no operator configuration; fixtures use a non-login shell.
	// Explicit exec keeps the fixture shell's PID equal to tmux's pane PID even
	// when the platform shell does not optimize its final command into an exec.
	script := "#!/bin/sh\nexport SHELL=/bin/sh\ngrouped=0\nfor arg in \"$@\"; do [ \"$arg\" = -t ] && grouped=1; done\nif [ \"$1\" = new-session ] && [ \"$grouped\" = 0 ]; then\nexec " + shellQuote(binary) + " -L " + socket + " -f /dev/null \"$@\" 'exec /bin/sh'\nfi\nexec " + shellQuote(binary) + " -L " + socket + " -f /dev/null \"$@\"\n"
	if err := os.WriteFile(file, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command(file, "kill-server").Run() })
	return file
}

func connectNamed(t *testing.T, f *fixture, host Host, name string, create bool) (*websocket.Conn, string) {
	t.Helper()
	var created struct {
		ID      string
		Session string
		Error   string
	}
	code := f.call(t, "POST", "/api/hosts/"+host.ID+"/connect", map[string]any{"cols": 80, "rows": 24, "session": name, "create": create}, &created)
	if code != 200 {
		t.Fatalf("named connect %q: HTTP %d: %s", name, code, created.Error)
	}
	if name != "" && created.Session != name {
		t.Fatal("connected to a different session")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	socket, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.http.URL, "http")+"/api/terminals/"+created.ID+"/terminal", &websocket.DialOptions{HTTPClient: f.client, HTTPHeader: http.Header{"Origin": {f.http.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.CloseNow() })
	return socket, created.ID
}

// tmux may redraw lines with escape sequences before the newline. Assertions
// compare rendered terminal text, while preserving the raw stream for diagnostics.
var tmuxEscapes = regexp.MustCompile("\x1b(?:\\[[0-?]*[ -/]*[@-~]|\\][^\x07\x1b]*(?:\x07|\x1b\\\\)|[()][A-Za-z0-9]|[=>])")

func terminalCommand(t *testing.T, socket *websocket.Conn, command, marker string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := socket.Write(ctx, websocket.MessageBinary, []byte(command+"\n")); err != nil {
		t.Fatal(err)
	}
	var output string
	for !strings.Contains(tmuxEscapes.ReplaceAllString(output, ""), marker) {
		kind, data, err := socket.Read(ctx)
		if err != nil {
			if len(output) > 4096 {
				output = output[len(output)-4096:]
			}
			t.Fatalf("terminal did not produce the expected session marker: %v; fixture output: %q", err, output)
		}
		if kind == websocket.MessageBinary {
			output += string(data)
		}
		if len(output) > 1<<20 {
			t.Fatal("terminal proof exceeded bounded output")
		}
	}
}

func TestNamedTmuxSessionsAcrossDevices(t *testing.T) {
	f := newFixture(t)
	f.store.Config.AllowLocalShell = true
	f.store.Config.TmuxExecutable = testTmux(t)
	f.login(t)
	host, err := f.store.SaveHost(Host{Name: "Test server", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: true})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/hosts/" + host.ID + "/tmux-sessions"
	var directory struct {
		Sessions    []TmuxSession
		LastSession string
	}
	if code := f.call(t, "POST", path, map[string]any{}, &directory); code != 200 || len(directory.Sessions) != 0 {
		t.Fatal("fresh tmux account did not list as empty", code)
	}
	work, id := connectNamed(t, f, host, "work", true)
	terminalCommand(t, work, "SESSION_PROOF=kept; printf 'SET_%s\\n' \"$SESSION_PROOF\"", "SET_kept\r\n")
	if code := f.call(t, "DELETE", "/api/terminals/"+id, nil, nil); code != 200 {
		t.Fatal(code)
	}
	second := *f
	jar, _ := cookiejar.New(nil)
	second.client = &http.Client{Jar: jar, Timeout: 20 * time.Second}
	second.login(t)
	if code := second.call(t, "POST", path, map[string]any{}, &directory); code != 200 || len(directory.Sessions) != 1 || directory.LastSession != "work" {
		t.Fatal("other device did not discover persisted selection", code)
	}
	continued, continuedID := connectNamed(t, &second, host, "", false)
	terminalCommand(t, continued, "printf 'RETURN_%s\\n' \"$SESSION_PROOF\"", "RETURN_kept\r\n")
	notes, notesID := connectNamed(t, f, host, "notes", true)
	terminalCommand(t, notes, "printf 'SEPARATE_%s_END\\n' \"${SESSION_PROOF-unset}\"", "SEPARATE_unset_END\r\n")
	second.call(t, "DELETE", "/api/terminals/"+continuedID, nil, nil)
	reconnected, reconnectID := connectNamed(t, &second, host, "work", false)
	terminalCommand(t, reconnected, "printf 'EXACT_%s\\n' \"$SESSION_PROOF\"", "EXACT_kept\r\n")
	again, err := OpenStore(f.store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	remembered, _ := again.Host(host.ID)
	if remembered.LastSession != "work" {
		t.Fatal("selection did not survive reopening the store")
	}
	for _, invalid := range []map[string]any{
		{"session": "work", "create": true},
		{"session": "wor"},
		{"session": "missing"},
		{"session": "bad; kill-server", "create": true},
	} {
		invalid["cols"], invalid["rows"] = 80, 24
		if code := f.call(t, "POST", "/api/hosts/"+host.ID+"/connect", invalid, nil); code != 400 && code != 409 {
			t.Fatal("invalid or duplicate choice was accepted", code)
		}
	}
	// Discover a session made by a separate tmux client, including shell punctuation.
	externalName := "outside ' $(printf surprise); session"
	if out, err := exec.Command(f.store.Config.TmuxExecutable, "new-session", "-d", "-s", externalName).CombinedOutput(); err != nil {
		t.Fatalf("external fixture: %v %s", err, out)
	}
	external, externalID := connectNamed(t, f, host, externalName, false)
	terminalCommand(t, external, "printf 'OUTSIDE_%s\\n' yes", "OUTSIDE_yes\r\n")
	f.call(t, "DELETE", "/api/terminals/"+externalID, nil, nil)
	f.call(t, "DELETE", "/api/terminals/"+notesID, nil, nil)
	second.call(t, "DELETE", "/api/terminals/"+reconnectID, nil, nil)
	if err := exec.Command(f.store.Config.TmuxExecutable, "kill-session", "-t", "=work").Run(); err != nil {
		t.Fatal(err)
	}
	if code := f.call(t, "POST", "/api/hosts/"+host.ID+"/connect", map[string]any{"cols": 80, "rows": 24, "session": "work"}, nil); code != 409 {
		t.Fatal("ended session was silently recreated", code)
	}
}

func TestTmuxSelectionFollowsTheRemoteAccount(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	wrapper := testTmux(t)
	remote := serveTestSSH(t, f.store, filepath.Dir(wrapper))
	address, portString, _ := net.SplitHostPort(remote.listener.Addr().String())
	port, _ := strconv.Atoi(portString)
	host, err := f.store.SaveHost(Host{Name: "SSH fixture", Address: address, Port: port, Username: "tester", Auth: "key", Tmux: true})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/hosts/" + host.ID + "/tmux-sessions"
	if code := f.call(t, "POST", path, map[string]any{}, nil); code != 502 {
		t.Fatal("session listing bypassed host-key trust", code)
	}
	if err := f.store.TrustHost(host.ID, host.Address, host.Port, remote.key); err != nil {
		t.Fatal(err)
	}
	host, _ = f.store.Host(host.ID)
	socket, id := connectNamed(t, f, host, "remote work", true)
	terminalCommand(t, socket, "PROOF=ssh; printf 'REMOTE_%s\\n' \"$PROOF\"", "REMOTE_ssh\r\n")
	f.call(t, "DELETE", "/api/terminals/"+id, nil, nil)
	resumed, resumeID := connectNamed(t, f, host, "remote work", false)
	terminalCommand(t, resumed, "printf 'SSH_RETURN_%s\\n' \"$PROOF\"", "SSH_RETURN_ssh\r\n")
	f.call(t, "DELETE", "/api/terminals/"+resumeID, nil, nil)
}

func TestRememberedSessionPreservedByEditsAndClearedByRetargeting(t *testing.T) {
	f := newFixture(t)
	host, _ := f.store.SaveHost(Host{Name: "Original", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "key", Tmux: true})
	if err := f.store.RememberSession(host, "work"); err != nil {
		t.Fatal(err)
	}
	host.Name = "Renamed"
	host.LastSession = "browser-supplied"
	renamed, err := f.store.SaveHost(host)
	if err != nil || renamed.LastSession != "work" {
		t.Fatal("edit overwrote the selected session", err)
	}
	renamed.Username = "different-user"
	changed, err := f.store.SaveHost(renamed)
	if err != nil || changed.LastSession != "" {
		t.Fatal("different remote account retained selection", err)
	}
	if err := f.store.RememberSession(host, "stale"); err == nil {
		t.Fatal("stale host selection was saved")
	}
}

func TestExistingDefaultTmuxSessionRemainsAvailable(t *testing.T) {
	f := newFixture(t)
	f.store.Config.AllowLocalShell = true
	f.store.Config.TmuxExecutable = testTmux(t)
	f.login(t)
	host, err := f.store.SaveHost(Host{Name: "Legacy", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: true, LastSession: "browser-supplied"})
	if err != nil || host.LastSession != "" {
		t.Fatal("new host accepted a browser-supplied selection", err)
	}
	name := "shellport-" + host.ID
	if err := exec.Command(f.store.Config.TmuxExecutable, "new-session", "-d", "-s", name).Run(); err != nil {
		t.Fatal(err)
	}
	socket, id := connectNamed(t, f, host, "", false)
	terminalCommand(t, socket, "printf 'LEGACY_%s\\n' ok", "LEGACY_ok\r\n")
	f.call(t, "DELETE", "/api/terminals/"+id, nil, nil)
	var directory struct {
		Sessions                    []TmuxSession
		LastSession, DefaultSession string
	}
	if code := f.call(t, "POST", "/api/hosts/"+host.ID+"/tmux-sessions", map[string]any{}, &directory); code != 200 || directory.LastSession != name || directory.DefaultSession != name || len(directory.Sessions) != 1 {
		t.Fatal("legacy default session was replaced or hidden", code)
	}
}
