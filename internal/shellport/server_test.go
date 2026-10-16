package shellport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

const testPassword = "synthetic-test-password"

type fixture struct {
	store  *Store
	app    *Server
	http   *httptest.Server
	client *http.Client
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir, testPassword, []string{"http://127.0.0.1:8088"}, ""); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	app := NewServer(store, nil)
	server := httptest.NewUnstartedServer(app)
	server.Config = app.HTTPServer("")
	server.Start()
	app.auth.origins[server.URL] = true
	jar, _ := cookiejar.New(nil)
	f := &fixture{store, app, server, &http.Client{Jar: jar, Timeout: 20 * time.Second}}
	t.Cleanup(func() { app.Close(); server.Close() })
	return f
}
func (f *fixture) call(t *testing.T, method, path string, input, out any) int {
	t.Helper()
	data, _ := json.Marshal(input)
	req, err := http.NewRequest(method, f.http.URL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", f.http.URL)
	req.Header.Set("Content-Type", "application/json")
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if out != nil {
		if err = json.Unmarshal(body, out); err != nil {
			t.Fatalf("decode %s: %v, %s", path, err, body)
		}
	}
	return res.StatusCode
}
func (f *fixture) login(t *testing.T) {
	if status := f.call(t, "POST", "/api/login", map[string]string{"password": testPassword}, nil); status != 200 {
		t.Fatalf("login %d", status)
	}
}

func TestAuthenticationAndOriginBoundaries(t *testing.T) {
	f := newFixture(t)
	if code := f.call(t, "GET", "/api/hosts", nil, nil); code != 401 {
		t.Fatalf("unauthenticated read: %d", code)
	}
	if code := f.call(t, "POST", "/api/login", map[string]string{"password": "incorrect"}, nil); code != 401 {
		t.Fatalf("wrong password: %d", code)
	}
	f.login(t)
	for _, origin := range []string{"", "http://evil.example", "https" + strings.TrimPrefix(f.http.URL, "http")} {
		req, _ := http.NewRequest("POST", f.http.URL+"/api/hosts", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		res, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("origin %q allowed: %d", origin, res.StatusCode)
		}
	}
	req, _ := http.NewRequest("GET", f.http.URL+"/api/hosts", nil)
	req.Host = "attacker.example"
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("DNS rebinding host accepted: %d", res.StatusCode)
	}
	if code := f.call(t, "POST", "/api/logout", map[string]any{}, nil); code != 200 {
		t.Fatal(code)
	}
	if code := f.call(t, "GET", "/api/hosts", nil, nil); code != 401 {
		t.Fatalf("cookie still authorized after logout: %d", code)
	}
}

func TestLoginCookieAndRateLimit(t *testing.T) {
	f := newFixture(t)
	f.app.auth.origins["https://shellport.example.test"] = true
	f.app.auth.trustedProxies, _ = parseTrustedProxies([]string{"127.0.0.1", "::1"})
	req, _ := http.NewRequest("POST", f.http.URL+"/api/login", strings.NewReader(`{"password":"`+testPassword+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://shellport.example.test")
	req.Header.Set("X-Forwarded-Host", "shellport.example.test")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-For", "192.0.2.1")
	res, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	cookies := res.Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Domain != "" {
		t.Fatalf("unsafe cookie: %+v", cookies)
	}
	// Successful logins do not consume the ten-failure allowance.
	f = newFixture(t)
	f.login(t)
	for range 10 {
		f.call(t, "POST", "/api/login", map[string]string{"password": "wrong"}, nil)
	}
	if code := f.call(t, "POST", "/api/login", map[string]string{"password": "wrong"}, nil); code != 429 {
		t.Fatalf("rate limit missing: %d", code)
	}
}

func TestSavedHostsPreserveAndInvalidateTrust(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	var h Host
	input := Host{Name: "Example", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "key", Tmux: true, HostKey: "browser-must-not-set-trust", Fingerprint: "forged"}
	if code := f.call(t, "POST", "/api/hosts", input, &h); code != 200 {
		t.Fatal(code)
	}
	if h.HostKey != "" || h.Fingerprint != "" {
		t.Fatal("browser supplied server trust")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	if err := f.store.TrustHost(h.ID, h.Address, h.Port, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	input.Name = "Renamed"
	if code := f.call(t, "PUT", "/api/hosts/"+h.ID, input, &h); code != 200 {
		t.Fatal(code)
	}
	if h.Fingerprint == "" {
		t.Fatal("rename lost trust")
	}
	input.Port = 2222
	id := h.ID
	h = Host{}
	f.call(t, "PUT", "/api/hosts/"+id, input, &h)
	if h.HostKey != "" || h.Fingerprint != "" {
		t.Fatal("retargeting retained trust")
	}
	again, err := OpenStore(f.store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Hosts()) != 1 || again.Hosts()[0].Port != 2222 {
		t.Fatal("host metadata did not persist")
	}
	st, _ := os.Stat(filepath.Join(f.store.Dir, "hosts.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal("host file is not private")
	}
	before, _ := os.ReadFile(filepath.Join(f.store.Dir, "config.json"))
	if Initialize(f.store.Dir, testPassword, []string{"http://localhost"}, "") == nil {
		t.Fatal("initialization overwrote existing data")
	}
	after, _ := os.ReadFile(filepath.Join(f.store.Dir, "config.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("config changed on repeated init")
	}
}

type sshFixture struct {
	listener    net.Listener
	key         ssh.PublicKey
	resized     chan [2]uint32
	inputs      chan []byte
	mu          sync.Mutex
	connections []net.Conn
}

func serveTestSSH(t *testing.T, store *Store, execDirectory ...string) *sshFixture {
	t.Helper()
	return serveTestSSHWithShell(t, store, []string{"/bin/sh", "-c"}, execDirectory...)
}

func serveTestSSHWithShell(t *testing.T, store *Store, execShell []string, execDirectory ...string) *sshFixture {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	serverSigner, _ := ssh.NewSignerFromKey(priv)
	data, _ := os.ReadFile(store.Config.KeyFile)
	clientSigner, _ := ssh.ParsePrivateKey(data)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
			return nil, os.ErrPermission
		}
		return nil, nil
	}}
	cfg.AddHostKey(serverSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &sshFixture{listener: listener, key: serverSigner.PublicKey(), resized: make(chan [2]uint32, 8), inputs: make(chan []byte, 8)}
	t.Cleanup(func() {
		listener.Close()
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, c := range f.connections {
			c.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.connections = append(f.connections, conn)
			f.mu.Unlock()
			go func() {
				sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					conn.Close()
					return
				}
				defer sshConn.Close()
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						newChan.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					ch, requests, e := newChan.Accept()
					if e != nil {
						return
					}
					go func() {
						defer ch.Close()
						var shell *exec.Cmd
						var terminalRequested bool
						for req := range requests {
							switch req.Type {
							case "pty-req":
								terminalRequested = true
								_ = req.Reply(true, nil)
							case "window-change":
								var v struct{ Cols, Rows, Width, Height uint32 }
								_ = ssh.Unmarshal(req.Payload, &v)
								f.resized <- [2]uint32{v.Cols, v.Rows}
							case "shell":
								shell = exec.Command("/bin/sh")
								in, _ := shell.StdinPipe()
								shell.Stdout = ch
								shell.Stderr = ch
								if shell.Start() != nil {
									_ = req.Reply(false, nil)
									return
								}
								_ = req.Reply(true, nil)
								go func() {
									b := make([]byte, 4096)
									for {
										n, e := ch.Read(b)
										if n > 0 {
											select {
											case f.inputs <- append([]byte{}, b[:n]...):
											default:
											}
											_, _ = in.Write(b[:n])
										}
										if e != nil {
											in.Close()
											return
										}
									}
								}()
								go func(cmd *exec.Cmd) {
									_ = cmd.Wait()
									_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
									ch.Close()
								}(shell)
							case "exec":
								if len(execDirectory) == 0 {
									_ = req.Reply(false, nil)
									continue
								}
								var input struct{ Command string }
								if ssh.Unmarshal(req.Payload, &input) != nil {
									_ = req.Reply(false, nil)
									continue
								}
								args := append(append([]string{}, execShell[1:]...), input.Command)
								shell = exec.Command(execShell[0], args...)
								shell.Env = append(os.Environ(), "PATH="+execDirectory[0]+string(os.PathListSeparator)+os.Getenv("PATH"), "TERM=xterm-256color")
								if len(execDirectory) > 1 {
									// A controlled remote PATH fixture can model absent software.
									shell.Env = append(shell.Env, "PATH="+execDirectory[1])
								}
								if terminalRequested {
									file, err := pty.StartWithSize(shell, &pty.Winsize{Cols: 80, Rows: 24})
									if err != nil {
										_ = req.Reply(false, nil)
										return
									}
									_ = req.Reply(true, nil)
									go func() { _, _ = io.Copy(file, ch); _ = file.Close() }()
									go func() { _, _ = io.Copy(ch, file) }()
								} else {
									shell.Stdout, shell.Stderr = ch, ch.Stderr()
									if err := shell.Start(); err != nil {
										_ = req.Reply(false, nil)
										return
									}
									_ = req.Reply(true, nil)
								}
								go func(cmd *exec.Cmd) {
									code := uint32(0)
									if err := cmd.Wait(); err != nil {
										code = uint32(cmd.ProcessState.ExitCode())
									}
									_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
									_ = ch.Close()
								}(shell)
							default:
								_ = req.Reply(false, nil)
							}
						}
						if shell != nil && shell.Process != nil {
							_ = shell.Process.Kill()
						}
					}()
				}
			}()
		}
	}()
	return f
}

func TestRealSSHOverAuthenticatedWebSocket(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	remote := serveTestSSH(t, f.store)
	addr, portText, _ := net.SplitHostPort(remote.listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	var h Host
	if code := f.call(t, "POST", "/api/hosts", Host{Name: "Test shell", Address: addr, Port: port, Username: "tester", Auth: "key"}, &h); code != 200 {
		t.Fatal(code)
	}
	if code := f.call(t, "POST", "/api/hosts/"+h.ID+"/connect", map[string]int{"cols": 80, "rows": 24}, nil); code != 502 {
		t.Fatal("unverified identity accepted", code)
	}
	var p Probe
	if code := f.call(t, "POST", "/api/hosts/"+h.ID+"/probe", map[string]any{}, &p); code != 200 {
		t.Fatal(code)
	}
	if p.Fingerprint != ssh.FingerprintSHA256(remote.key) {
		t.Fatal("incorrect fingerprint")
	}
	if code := f.call(t, "POST", "/api/hosts/"+h.ID+"/trust", map[string]string{"fingerprint": "wrong"}, nil); code != 409 {
		t.Fatal("incorrect identity confirmation accepted", code)
	}
	if code := f.call(t, "POST", "/api/hosts/"+h.ID+"/trust", map[string]string{"fingerprint": p.Fingerprint}, nil); code != 200 {
		t.Fatal(code)
	}
	var created struct {
		ID string `json:"id"`
	}
	if code := f.call(t, "POST", "/api/hosts/"+h.ID+"/connect", map[string]int{"cols": 80, "rows": 24}, &created); code != 200 {
		t.Fatal(code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(f.http.URL, "http") + "/api/terminals/" + created.ID + "/terminal"
	// A terminal identifier is insufficient without the signed-in device cookie.
	_, res, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": {f.http.URL}}})
	if err == nil || res == nil || res.StatusCode != 401 {
		t.Fatal("terminal authorized by ID alone")
	}
	socket, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: f.client, HTTPHeader: http.Header{"Origin": {f.http.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	// Hijacking must clear the HTTP request-read deadline for terminal traffic.
	<-time.After(f.http.Config.ReadTimeout + 100*time.Millisecond)
	// A foreground connection check must round-trip as metadata, never shell input.
	if err = socket.Write(ctx, websocket.MessageText, []byte(`{"type":"ping","nonce":"heartbeat-check-1"}`)); err != nil {
		t.Fatal(err)
	}
	for {
		kind, data, err := socket.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if kind != websocket.MessageText {
			continue
		}
		var pong struct{ Type, Nonce string }
		if json.Unmarshal(data, &pong) != nil || pong.Type != "pong" || pong.Nonce != "heartbeat-check-1" {
			t.Fatal("Incorrect connection-check response", string(data))
		}
		break
	}
	if err = socket.Write(ctx, websocket.MessageText, []byte(`{"type":"resize","cols":92,"rows":31}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case size := <-remote.resized:
		if size != [2]uint32{92, 31} {
			t.Fatal(size)
		}
	case <-ctx.Done():
		t.Fatal("resize not forwarded")
	}
	command := []byte("printf 'SHELLPORT_REAL_SHELL\\n'\n")
	if err = socket.Write(ctx, websocket.MessageBinary, command); err != nil {
		t.Fatal(err)
	}
	var output string
	for !strings.Contains(output, "SHELLPORT_REAL_SHELL") {
		kind, b, err := socket.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if kind == websocket.MessageBinary {
			output += string(b)
		}
	}
	select {
	case b := <-remote.inputs:
		if !bytes.Equal(b, command) {
			t.Fatalf("input changed: %q", b)
		}
	case <-ctx.Done():
		t.Fatal("input not forwarded")
	}
	// Logging out revokes this device and closes an already-open SSH channel.
	if code := f.call(t, "POST", "/api/logout", map[string]any{}, nil); code != 200 {
		t.Fatal(code)
	}
	expectSocketClosed(t, ctx, socket)
	f.app.mu.Lock()
	remaining := len(f.app.terminals)
	f.app.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d leaked terminals", remaining)
	}
}

func TestInvalidTerminalHeartbeatsAreRejected(t *testing.T) {
	for _, nonce := range []string{"", strings.Repeat("a", 65), "line\nbreak", "not a nonce"} {
		t.Run("length-"+strconv.Itoa(len(nonce)), func(t *testing.T) {
			f := newFixture(t)
			f.store.Config.AllowLocalShell = true
			f.login(t)
			h, err := f.store.SaveHost(Host{Name: "Heartbeat fixture", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local"})
			if err != nil {
				t.Fatal(err)
			}
			var created struct {
				ID string `json:"id"`
			}
			if code := f.call(t, "POST", "/api/hosts/"+h.ID+"/connect", map[string]int{"cols": 80, "rows": 24}, &created); code != 200 {
				t.Fatal(code)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			socket, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.http.URL, "http")+"/api/terminals/"+created.ID+"/terminal", &websocket.DialOptions{HTTPClient: f.client, HTTPHeader: http.Header{"Origin": {f.http.URL}}})
			if err != nil {
				t.Fatal(err)
			}
			defer socket.CloseNow()
			message, _ := json.Marshal(map[string]string{"type": "ping", "nonce": nonce})
			if err := socket.Write(ctx, websocket.MessageText, message); err != nil {
				t.Fatal(err)
			}
			expectSocketClosed(t, ctx, socket)
		})
	}
}

func TestPinnedIdentityRejectsChangedKey(t *testing.T) {
	f := newFixture(t)
	remote := serveTestSSH(t, f.store)
	addr, p, _ := net.SplitHostPort(remote.listener.Addr().String())
	port, _ := strconv.Atoi(p)
	h, _ := f.store.SaveHost(Host{Name: "Pinned", Address: addr, Port: port, Username: "tester", Auth: "key"})
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	different, _ := ssh.NewSignerFromKey(priv)
	if err := f.store.TrustHost(h.ID, h.Address, h.Port, different.PublicKey()); err != nil {
		t.Fatal(err)
	}
	h, _ = f.store.Host(h.ID)
	if client, err := connectSSH(context.Background(), f.store.Config, h, "", ""); err == nil {
		client.Close()
		t.Fatal("changed host key accepted")
	}
}

func TestThisServerPTYRequiresOptInAndResizes(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	host := Host{Name: "This test server", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local"}
	if code := f.call(t, "POST", "/api/hosts", host, nil); code != 403 {
		t.Fatal("local shell enabled without operator opt-in", code)
	}
	f.store.Config.AllowLocalShell = true
	t.Setenv("SHELL", "/bin/sh")
	var saved Host
	if code := f.call(t, "POST", "/api/hosts", host, &saved); code != 200 {
		t.Fatal(code)
	}
	var created struct {
		ID string `json:"id"`
	}
	if code := f.call(t, "POST", "/api/hosts/"+saved.ID+"/connect", map[string]int{"cols": 80, "rows": 24}, &created); code != 200 {
		t.Fatal(code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	socket, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.http.URL, "http")+"/api/terminals/"+created.ID+"/terminal", &websocket.DialOptions{HTTPClient: f.client, HTTPHeader: http.Header{"Origin": {f.http.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	if err = socket.Write(ctx, websocket.MessageText, []byte(`{"type":"resize","cols":91,"rows":33}`)); err != nil {
		t.Fatal(err)
	}
	if err = socket.Write(ctx, websocket.MessageBinary, []byte("stty size\n")); err != nil {
		t.Fatal(err)
	}
	var output string
	for !strings.Contains(output, "33 91") {
		kind, data, err := socket.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if kind == websocket.MessageBinary {
			output += string(data)
		}
	}
	// A full-screen process can be interrupted by an unmodified Ctrl-C byte.
	if err = socket.Write(ctx, websocket.MessageBinary, []byte("sleep 10\n")); err != nil {
		t.Fatal(err)
	}
	if err = socket.Write(ctx, websocket.MessageBinary, []byte{3}); err != nil {
		t.Fatal(err)
	}
	if err = socket.Write(ctx, websocket.MessageBinary, []byte("printf 'PTY_INTERRUPT_RETURNED\\n'\n")); err != nil {
		t.Fatal(err)
	}
	output = ""
	for !strings.Contains(output, "PTY_INTERRUPT_RETURNED\r\n") {
		kind, data, err := socket.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if kind == websocket.MessageBinary {
			output += string(data)
		}
	}
	f.call(t, "POST", "/api/logout", map[string]any{}, nil)
	expectSocketClosed(t, ctx, socket)
}

func expectSocketClosed(t *testing.T, parent context.Context, socket *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	// Frames already in transit can arrive before the close frame. Drain them,
	// then require closure rather than mistaking buffered output for authority.
	for {
		_, _, err := socket.Read(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("terminal did not close after logout")
			}
			return
		}
	}
}
