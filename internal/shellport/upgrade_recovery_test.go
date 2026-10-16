package shellport

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

// Default builds exercise the recovery procedure, not compatibility between
// published versions. Explicit verified binaries can repeat it across releases.
func TestUpgradeBackupRecovery(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")
	root, tmux := shortTmuxFixture(t)
	from, to := rehearsalBinaries(t, root)
	active := filepath.Join(root, "current")
	switchRehearsalBinary(t, active, from)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	origin := fmt.Sprintf("http://localhost:%d", port)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	dir := filepath.Join(root, "data")
	keys := filepath.Join(root, "external-key")
	if err = Initialize(keys, testPassword, []string{origin}, ""); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(keys, "id_ed25519")
	passwordFile := filepath.Join(root, "password.txt")
	if err = os.WriteFile(passwordFile, []byte(testPassword+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(active, "init", "--data-dir", dir, "--origin", origin, "--password-file", passwordFile, "--key-file", keyFile)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fixture initialization failed: %v %s", err, output)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.Configuration()
	cfg.AllowLocalShell, cfg.MaxSessions = true, 8
	cfg.TmuxMode, cfg.TmuxExecutable = TmuxIndependent, tmux
	cfg.TmuxSocket = filepath.Join(root, "independent.sock")
	cfg.TmuxAdditional = &TmuxProfile{Mode: TmuxManaged, Executable: tmux, Socket: filepath.Join(root, "managed.sock")}
	if err = writePrivate(filepath.Join(dir, "config.json"), cfg); err != nil {
		t.Fatal(err)
	}

	// A test-owned foreground tmux process represents an independent owner.
	// No launch agent, systemd unit or production socket is installed or touched.
	independent := startRehearsalProcess(t, exec.Command(tmux, "-D", "-S", cfg.TmuxSocket, "-f", "/dev/null"), filepath.Join(root, "tmux.log"))
	if err = waitTmux(cfg, independent.done); err != nil {
		t.Fatal(err)
	}
	setShell, err := LocalTmuxClient(cfg, "set-option", "-g", "default-shell", "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if err = setShell.Run(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	local, err := store.SaveHost(Host{Name: "Local rehearsal", Address: "127.0.0.1", Port: 22, Username: "demo", Auth: "local", Tmux: true})
	if err != nil {
		t.Fatal(err)
	}
	remoteTmux := testTmux(t)
	remote := serveTestSSH(t, store, filepath.Dir(remoteTmux))
	host, portText, _ := net.SplitHostPort(remote.listener.Addr().String())
	sshPort, _ := strconv.Atoi(portText)
	remoteHost, err := store.SaveHost(Host{Name: "SSH rehearsal", Address: host, Port: sshPort, Username: "demo", Auth: "key", Tmux: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.TrustHost(remoteHost.ID, remoteHost.Address, remoteHost.Port, remote.key); err != nil {
		t.Fatal(err)
	}
	remoteHost, _ = store.Host(remoteHost.ID)
	for name, text := range map[string]string{
		"startup/service.txt": "fixture executable: " + active + "\nfixture data: " + dir + "\n",
		"proxy/site.txt":      "fixture origin: " + origin + "\nfixture upstream: " + address + "\n",
	} {
		path := filepath.Join(root, name)
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	jar, _ := cookiejar.New(nil)
	f := &fixture{store: store, http: &httptest.Server{URL: origin}, client: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
	server := startRehearsalServer(t, active, dir, address, origin, filepath.Join(root, "baseline.log"))
	f.login(t)
	authenticator := newTestAuthenticator(t)
	var options testPasskeyOptions
	if code := f.call(t, "POST", "/api/passkeys/register/begin", struct{}{}, &options); code != 200 {
		t.Fatal("passkey registration begin", code)
	}
	if code := f.call(t, "POST", "/api/passkeys/register/finish", map[string]any{"name": "Rehearsal key", "credential": authenticator.registration(t, options, origin, "localhost", 5)}, nil); code != 200 {
		t.Fatal("passkey registration finish", code)
	}
	localSocket, selected := connectShellTab(t, f, local, map[string]any{"create": true, "session": "upgrade-check", "mode": TmuxIndependent})
	localSecond, selectedSecond := connectShellTab(t, f, local, map[string]any{"session": selected.Session, "sessionRef": selected.SessionRef, "newWindow": true})
	sshSocket, sshSelected := connectShellTab(t, f, remoteHost, map[string]any{"create": true, "session": "ssh-upgrade-check"})
	records := []rehearsalShell{
		seedRehearsalShell(t, localSocket, local, selected, localTmuxRunner(cfg, tmux)),
		seedRehearsalShell(t, localSecond, local, selectedSecond, localTmuxRunner(cfg, tmux)),
	}
	sshClient, err := connectSSH(context.Background(), cfg, remoteHost, "", "")
	if err != nil {
		t.Fatal(err)
	}
	records = append(records, seedRehearsalShell(t, sshSocket, remoteHost, sshSelected, remoteTmuxRunner(sshClient)))
	sshClient.Close()
	managed, managedReply := connectShellTab(t, f, local, map[string]any{"create": true, "session": "managed-check", "mode": TmuxManaged})
	terminalCommand(t, managed, "printf 'MANAGED_%s\\n' ready", "MANAGED_ready\r\n")
	direct, _ := connectShellTab(t, f, local, map[string]any{"direct": true})
	terminalCommand(t, direct, "VOLATILE=rehearsal; printf 'DIRECT_%s\\n' \"$VOLATILE\"", "DIRECT_rehearsal\r\n")
	if code := f.call(t, "POST", "/api/terminals/"+selected.ID+"/select", struct{}{}, nil); code != 200 {
		t.Fatal("remembered tab", code)
	}
	server.stop(t)
	loaded, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	baselineHosts := loaded.Hosts()
	sources := []string{"data", "external-key/id_ed25519", "external-key/id_ed25519.pub", "startup", "proxy"}
	backup := filepath.Join(root, "backup")
	if err = os.Mkdir(backup, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range sources {
		copyRehearsalTree(t, filepath.Join(root, name), filepath.Join(backup, name))
	}
	baseline := rehearsalSnapshot(t, root, sources)
	assertRehearsalSnapshot(t, baseline, rehearsalSnapshot(t, backup, sources))

	t.Log("upgrade: replacing baseline executable while keeping private data and independent tmux")
	switchRehearsalBinary(t, active, to)
	server = startRehearsalServer(t, active, dir, address, origin, filepath.Join(root, "candidate.log"))
	assertRehearsalSnapshot(t, baseline, rehearsalSnapshot(t, root, sources))
	verifyRehearsalAccess(t, f, authenticator, 1, baselineHosts)
	resumeRehearsalShells(t, f, records)
	var directory struct{ Sessions []TmuxSession }
	if code := f.call(t, "POST", "/api/hosts/"+local.ID+"/tmux-sessions", struct{}{}, &directory); code != 200 {
		t.Fatal(code)
	}
	for _, session := range directory.Sessions {
		if session.Ref == managedReply.SessionRef {
			t.Fatal("managed work incorrectly survived server restart")
		}
	}
	fresh, _ := connectShellTab(t, f, local, map[string]any{"direct": true})
	terminalCommand(t, fresh, "if [ -z \"$VOLATILE\" ]; then printf 'FRESH_%s\\n' unset; fi", "FRESH_unset\r\n")
	fresh.CloseNow()
	server.stop(t)
	afterUpgrade := rehearsalSnapshot(t, root, sources)
	currentStore, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	upgradedHosts := currentStore.Hosts()

	t.Log("failed update: candidate exits before readiness; rollback changes only executable")
	broken := filepath.Join(root, "broken")
	if err = os.WriteFile(broken, []byte("#!/bin/sh\nexit 42\n"), 0700); err != nil {
		t.Fatal(err)
	}
	switchRehearsalBinary(t, active, broken)
	failed := startRehearsalProcess(t, exec.Command(active, "serve", "--data-dir", dir, "--listen", address), filepath.Join(root, "failed.log"))
	if err = failed.ready(origin); err == nil {
		failed.stop(t)
		t.Fatal("failed candidate was reported ready")
	}
	assertRehearsalSnapshot(t, afterUpgrade, rehearsalSnapshot(t, root, sources))
	switchRehearsalBinary(t, active, from)
	server = startRehearsalServer(t, active, dir, address, origin, filepath.Join(root, "rollback.log"))
	assertRehearsalSnapshot(t, afterUpgrade, rehearsalSnapshot(t, root, sources))
	verifyRehearsalAccess(t, f, authenticator, 2, upgradedHosts)
	resumeRehearsalShells(t, f, records)
	server.stop(t)

	t.Log("backup recovery: restore private data, external SSH key and operator configuration to their original paths")
	aside := filepath.Join(root, "before-restore")
	if err = os.Mkdir(aside, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"data", "external-key", "startup", "proxy"} {
		if err = os.Rename(filepath.Join(root, name), filepath.Join(aside, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range sources {
		copyRehearsalTree(t, filepath.Join(backup, name), filepath.Join(root, name))
	}
	assertRehearsalSnapshot(t, baseline, rehearsalSnapshot(t, root, sources))
	restored, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	beforeKey, err := publicKeyFingerprint(filepath.Join(backup, "external-key/id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	afterKey, err := publicKeyFingerprint(restored.Configuration().KeyFile)
	if err != nil || afterKey != beforeKey {
		t.Fatal("SSH identity changed during restoration", err)
	}
	server = startRehearsalServer(t, active, dir, address, origin, filepath.Join(root, "restore.log"))
	verifyRehearsalAccess(t, f, authenticator, 3, baselineHosts)
	resumeRehearsalShells(t, f, records)
	server.stop(t)
	t.Log("PASS: upgrade, failed-update rollback and backup restoration; password/passkey access, SSH trust, selections, independent pane PIDs and variables verified")
}

type rehearsalProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func startRehearsalProcess(t *testing.T, cmd *exec.Cmd, logPath string) *rehearsalProcess {
	t.Helper()
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	process := &rehearsalProcess{cmd: cmd, done: make(chan struct{})}
	go func() { process.err = cmd.Wait(); log.Close(); close(process.done) }()
	t.Cleanup(func() { process.stop(t) })
	return process
}
func (p *rehearsalProcess) stop(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
		if p.err != nil {
			t.Errorf("rehearsal process failed during shutdown: %v", p.err)
		}
	case <-time.After(20 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
		t.Error("rehearsal process required forced termination")
	}
}
func (p *rehearsalProcess) ready(origin string) error {
	client := &http.Client{Timeout: 300 * time.Millisecond}
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-p.done:
			return fmt.Errorf("server exited before readiness: %w", p.err)
		default:
		}
		response, err := client.Get(origin + "/api/health")
		if err == nil {
			var health struct {
				OK      bool
				Product string
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&health)
			response.Body.Close()
			if response.StatusCode == 200 && decodeErr == nil && health.OK && health.Product == "shellport" {
				return nil
			}
		}
		select {
		case <-p.done:
			return fmt.Errorf("server exited before readiness: %w", p.err)
		case <-deadline.C:
			return fmt.Errorf("server readiness timed out")
		case <-tick.C:
		}
	}
}
func startRehearsalServer(t *testing.T, binary, dir, address, origin, log string) *rehearsalProcess {
	t.Helper()
	process := startRehearsalProcess(t, exec.Command(binary, "serve", "--data-dir", dir, "--listen", address), log)
	if err := process.ready(origin); err != nil {
		t.Fatal(err)
	}
	return process
}
func rehearsalBinaries(t *testing.T, root string) (string, string) {
	t.Helper()
	from, to := os.Getenv("SHELLPORT_REHEARSAL_FROM"), os.Getenv("SHELLPORT_REHEARSAL_TO")
	if (from == "") != (to == "") {
		t.Fatal("set both SHELLPORT_REHEARSAL_FROM and SHELLPORT_REHEARSAL_TO")
	}
	if from == "" {
		t.Log("building two labeled current-source fixtures; published-release compatibility remains untested")
		project, err := filepath.Abs(filepath.Join("..", ".."))
		if err != nil {
			t.Fatal(err)
		}
		for i, target := range []*string{&from, &to} {
			name := []string{"baseline", "candidate"}[i]
			*target = filepath.Join(root, name)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", "-X main.version=v0.0.0-rehearsal."+name+" -X main.commit=unknown", "-o", *target, "./cmd/shellport")
			cmd.Dir = project
			output, err := cmd.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatalf("fixture build: %v %s", err, output)
			}
		}
	} else {
		for i, target := range []*string{&from, &to} {
			absolute, err := filepath.Abs(*target)
			if err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(root, []string{"verified-baseline", "verified-candidate"}[i])
			copyRehearsalTree(t, absolute, destination)
			*target = destination
		}
	}
	left, right := rehearsalFile(t, from), rehearsalFile(t, to)
	if left.Digest == right.Digest {
		t.Fatal("baseline and candidate must be different executables")
	}
	for _, binary := range []string{from, to} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		output, err := exec.CommandContext(ctx, binary, "version").CombinedOutput()
		cancel()
		if err != nil || !strings.HasPrefix(string(output), "Shellport ") {
			t.Fatalf("compatible native version command required: %v", err)
		}
		t.Log(strings.TrimSpace(string(output)))
	}
	return from, to
}
func switchRehearsalBinary(t *testing.T, active, target string) {
	t.Helper()
	next := active + ".next"
	if err := os.Symlink(target, next); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, active); err != nil {
		t.Fatal(err)
	}
}

type rehearsalFileState struct {
	Digest [32]byte
	Mode   fs.FileMode
}

func rehearsalFile(t *testing.T, path string) rehearsalFileState {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return rehearsalFileState{sha256.Sum256(data), info.Mode().Perm()}
}
func rehearsalSnapshot(t *testing.T, root string, names []string) map[string]rehearsalFileState {
	t.Helper()
	result := map[string]rehearsalFileState{}
	for _, name := range names {
		err := filepath.WalkDir(filepath.Join(root, name), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if entry.Name() == "server.lock" {
				return nil
			}
			if !entry.Type().IsRegular() {
				return fmt.Errorf("unexpected non-regular backup entry")
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			result[relative] = rehearsalFile(t, path)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}
func assertRehearsalSnapshot(t *testing.T, want, got map[string]rehearsalFileState) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatal("private data or file permissions changed unexpectedly")
	}
}
func copyRehearsalTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		if entry.Name() == "server.lock" {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("backup copy refuses non-regular files")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

type rehearsalShell struct {
	Host       Host
	Reply      tabReply
	PID, Value string
}

func seedRehearsalShell(t *testing.T, socket *websocket.Conn, host Host, reply tabReply, run tmuxRunner) rehearsalShell {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, _, err := run(ctx, "display-message", "-p", "-t", "="+reply.Session+":"+reply.Window.ID, "#{pane_pid}")
	if err != nil {
		t.Fatal(err)
	}
	pid := strings.TrimSpace(string(output))
	if _, err = strconv.Atoi(pid); err != nil {
		t.Fatal("invalid pane PID")
	}
	value := randomID()[:12]
	terminalCommand(t, socket, "REHEARSAL_VALUE="+value+"; printf 'STATE_%s_%s\\n' \"$REHEARSAL_VALUE\" \"$$\"", "STATE_"+value+"_"+pid+"\r\n")
	return rehearsalShell{host, reply, pid, value}
}
func resumeRehearsalShells(t *testing.T, f *fixture, records []rehearsalShell) {
	t.Helper()
	for _, record := range records {
		socket, reply := connectShellTab(t, f, record.Host, map[string]any{"session": record.Reply.Session, "sessionRef": record.Reply.SessionRef, "window": record.Reply.Window.ID})
		if reply.SessionRef != record.Reply.SessionRef || reply.Window.ID != record.Reply.Window.ID {
			t.Fatal("resumed a different saved shell")
		}
		terminalCommand(t, socket, "printf 'STATE_%s_%s\\n' \"$REHEARSAL_VALUE\" \"$$\"", "STATE_"+record.Value+"_"+record.PID+"\r\n")
		socket.CloseNow()
	}
}
func verifyRehearsalAccess(t *testing.T, f *fixture, a *testAuthenticator, counter uint32, wantHosts []Host) {
	t.Helper()
	if code := f.call(t, "GET", "/api/hosts", nil, nil); code != 401 {
		t.Fatal("pre-restart sign-in survived", code)
	}
	f.login(t)
	var hosts []Host
	if code := f.call(t, "GET", "/api/hosts", nil, &hosts); code != 200 || !reflect.DeepEqual(hosts, wantHosts) {
		t.Fatal("saved computers or selections changed", code)
	}
	if code := f.call(t, "POST", "/api/logout", struct{}{}, nil); code != 200 {
		t.Fatal(code)
	}
	var options testPasskeyOptions
	if code := f.call(t, "POST", "/api/passkeys/login/begin", struct{}{}, &options); code != 200 || options.NeedsPassword {
		t.Fatal("restored passkey unavailable", code)
	}
	if code := f.call(t, "POST", "/api/passkeys/login/finish", map[string]any{"credential": a.assertion(t, options, f.http.URL, "localhost", 5, counter)}, nil); code != 200 {
		t.Fatal("passkey login failed", code)
	}
}
func publicKeyFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(key.PublicKey()), nil
}
