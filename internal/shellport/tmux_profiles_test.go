package shellport

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func startProfileServer(t *testing.T, cfg Config) {
	t.Helper()
	if err := privateTmuxDirectory(filepath.Dir(cfg.TmuxSocket)); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cfg.TmuxExecutable, "-D", "-f", "/dev/null", "-S", cfg.TmuxSocket)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	if err := waitTmux(cfg, done); err != nil {
		t.Fatal(err)
	}
}

func profilesFixture(t *testing.T, primary string) (*fixture, *TmuxRuntime, string) {
	t.Helper()
	f := newFixture(t)
	root, binary := shortTmuxFixture(t)
	cfg := f.store.Configuration()
	cfg.AllowLocalShell = true
	cfg.TmuxMode = primary
	cfg.TmuxExecutable = binary
	cfg.TmuxSocket = filepath.Join(root, "primary.sock")
	if err := f.store.saveTmuxConfiguration(cfg); err != nil {
		t.Fatal(err)
	}
	if primary == TmuxIndependent {
		startProfileServer(t, cfg)
	}
	t.Setenv("SHELLPORT_MANAGED_TEST_HELPER", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := newTmuxRuntime(f.store, executable, "-test.run=^TestManagedTmuxHelperProcess$", "--")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	runtime.plan = func(dir, mode, executable string) (*TmuxSetupPlan, error) {
		return planTmuxSetup(dir, mode, executable, setupEnvironment{"linux", root, filepath.Join(root, "c"), os.Getuid()})
	}
	f.app.SetTmuxRuntime(runtime)
	f.login(t)
	return f, runtime, root
}

func chooseDefault(t *testing.T, f *fixture, mode string) {
	t.Helper()
	var info struct{ Revision string }
	if code := f.call(t, "GET", "/api/tmux-modes", nil, &info); code != 200 {
		t.Fatal("mode settings", code)
	}
	var reply struct{ Error string }
	if code := f.call(t, "POST", "/api/tmux-modes", map[string]any{"mode": mode, "revision": info.Revision, "confirm": true}, &reply); code != 200 {
		t.Fatal("default mode", code, reply.Error)
	}
}

func TestLocalTmuxProfilesCoexistAndKeepExactSelections(t *testing.T) {
	f, _, _ := profilesFixture(t, TmuxIndependent)
	h, err := f.store.SaveHost(Host{Name: "Local", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: true})
	if err != nil {
		t.Fatal(err)
	}
	independent, a := connectShellTab(t, f, h, map[string]any{"create": true, "session": "same", "mode": TmuxIndependent})
	terminalCommand(t, independent, "POOL_VALUE=independent; printf 'A_%s\\n' \"$POOL_VALUE\"", "A_independent\r\n")
	chooseDefault(t, f, TmuxManaged)
	terminalCommand(t, independent, "printf 'A_STILL_%s\\n' \"$POOL_VALUE\"", "A_STILL_independent\r\n")
	managed, b := connectShellTab(t, f, h, map[string]any{"create": true, "session": "same"})
	terminalCommand(t, managed, "POOL_VALUE=managed; printf 'B_%s\\n' \"$POOL_VALUE\"", "B_managed\r\n")
	if a.SessionRef == b.SessionRef {
		t.Fatal("different pools returned an interchangeable session reference")
	}
	var directory struct {
		Sessions                    []TmuxSession
		DefaultMode, LastSessionRef string
	}
	path := "/api/hosts/" + h.ID
	if code := f.call(t, "POST", path+"/tmux-sessions", map[string]any{}, &directory); code != 200 || len(directory.Sessions) != 2 || directory.LastSessionRef != b.SessionRef {
		t.Fatal("merged directory or Continue selection", code, directory)
	}
	modes := map[string]bool{}
	for _, s := range directory.Sessions {
		modes[s.Mode] = true
	}
	if !modes[TmuxIndependent] || !modes[TmuxManaged] {
		t.Fatal("session ownership labels missing")
	}
	chooseDefault(t, f, TmuxIndependent)
	terminalCommand(t, managed, "printf 'B_STILL_%s\\n' \"$POOL_VALUE\"", "B_STILL_managed\r\n")
	jar, _ := cookiejar.New(nil)
	other := *f
	other.client = &http.Client{Jar: jar, Timeout: 20 * time.Second}
	other.login(t)
	resumed, same := connectShellTab(t, &other, h, map[string]any{"session": b.Session, "sessionRef": b.SessionRef, "window": b.Window.ID})
	if same.SessionRef != b.SessionRef {
		t.Fatal("another device followed the changed default instead of its selected session")
	}
	terminalCommand(t, resumed, "printf 'RESUMED_%s\\n' \"$POOL_VALUE\"", "RESUMED_managed\r\n")
	newTab, child := connectShellTab(t, f, h, map[string]any{"session": b.Session, "sessionRef": b.SessionRef, "newWindow": true})
	terminalCommand(t, newTab, "printf 'CHILD_%s\\n' \"${POOL_VALUE-unset}\"", "CHILD_unset\r\n")
	managedCfg, _ := managedTmuxConfiguration(f.store.Configuration())
	windows, _, err := localTmuxRunner(managedCfg, managedCfg.TmuxExecutable)(context.Background(), "list-windows", "-t", "=same", "-F", "#{window_id}")
	if err != nil || len(strings.Fields(string(windows))) != 2 {
		t.Fatal("new tab did not inherit managed ownership", err, string(windows))
	}
	// Identical names and window IDs on different servers must not redirect
	// rename, close, deletion or the server-side Continue selection.
	if code := f.call(t, "POST", path+"/tmux-windows/rename", map[string]any{"session": b.Session, "ref": b.SessionRef, "window": b.Window.ID, "name": "managed tab"}, nil); code != 200 {
		t.Fatal("rename managed tab", code)
	}
	terminalCommand(t, independent, "printf 'UNTOUCHED_%s\\n' \"$POOL_VALUE\"", "UNTOUCHED_independent\r\n")
	if code := f.call(t, "POST", path+"/tmux-windows/close", map[string]any{"session": b.Session, "ref": b.SessionRef, "window": child.Window.ID, "confirm": true}, nil); code != 200 {
		t.Fatal("close managed child", code)
	}
	if code := f.call(t, "POST", path+"/tmux-sessions/rename", map[string]any{"session": b.Session, "ref": b.SessionRef, "name": "renamed"}, nil); code != 200 {
		t.Fatal("rename managed session", code)
	}
	if code := f.call(t, "POST", "/api/terminals/"+a.ID+"/select", map[string]any{}, nil); code != 200 {
		t.Fatal("select independent", code)
	}
	if code := f.call(t, "POST", path+"/tmux-sessions/delete", map[string]any{"session": "renamed", "ref": b.SessionRef, "confirm": true}, nil); code != 200 {
		t.Fatal("delete managed session", code)
	}
	current, _ := f.store.Host(h.ID)
	if current.LastSessionRef != a.SessionRef {
		t.Fatal("deleting another pool cleared Continue")
	}
	terminalCommand(t, independent, "printf 'KEPT_%s\\n' \"$POOL_VALUE\"", "KEPT_independent\r\n")
}

func TestManagedPoolEndsWithOwnerWhileIndependentWorkSurvives(t *testing.T) {
	f, runtime, _ := profilesFixture(t, TmuxIndependent)
	h, err := f.store.SaveHost(Host{Name: "Local", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: true})
	if err != nil {
		t.Fatal(err)
	}
	independent, a := connectShellTab(t, f, h, map[string]any{"create": true, "session": "kept"})
	terminalCommand(t, independent, "POOL_VALUE=survives; printf 'SET_%s\\n' \"$POOL_VALUE\"", "SET_survives\r\n")
	chooseDefault(t, f, TmuxManaged)
	managed, _ := connectShellTab(t, f, h, map[string]any{"create": true, "session": "owned"})
	terminalCommand(t, managed, "printf 'OWNED_ready\\n'", "OWNED_ready\r\n")
	cfg := f.store.Configuration()
	managedCfg, _ := managedTmuxConfiguration(cfg)
	f.app.Close()
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if tmuxReady(managedCfg) || !tmuxReady(cfg) {
		t.Fatal("owner shutdown did not distinguish the two lifetimes")
	}
	loaded, err := OpenStore(f.store.Dir)
	if err != nil || defaultTmuxMode(loaded.Configuration()) != TmuxManaged {
		t.Fatal("mode configuration did not persist", err)
	}
	reopened, err := newTmuxRuntime(loaded, mustTestExecutable(t), "-test.run=^TestManagedTmuxHelperProcess$", "--")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	sessions, err := localProfileSessions(context.Background(), loaded.Configuration())
	if err != nil || len(sessions) != 1 || sessions[0].Ref != a.SessionRef {
		t.Fatal("independent identity changed after owner restart", err, sessions)
	}
	command, _ := LocalTmuxClient(cfg, "send-keys", "-t", "=kept:", "printf 'AFTER_%s\\n' \"$POOL_VALUE\"", "Enter")
	if err = command.Run(); err != nil {
		t.Fatal(err)
	}
	command, _ = LocalTmuxClient(cfg, "capture-pane", "-p", "-t", "=kept:")
	for i := 0; i < 50; i++ {
		out, _ := command.Output()
		if strings.Contains(string(out), "AFTER_survives") {
			return
		}
		time.Sleep(20 * time.Millisecond)
		command, _ = LocalTmuxClient(cfg, "capture-pane", "-p", "-t", "=kept:")
	}
	t.Fatal("independent shell variable was lost")
}

func mustTestExecutable(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTmuxModeSettingsRejectStaleAndUnconfirmedWrites(t *testing.T) {
	f, runtime, _ := profilesFixture(t, TmuxIndependent)
	cfg := f.store.Configuration()
	revision := tmuxConfigRevision(cfg)
	for _, input := range []map[string]any{{"mode": TmuxManaged, "revision": revision}, {"mode": "bad", "revision": revision, "confirm": true}, {"mode": TmuxManaged, "revision": revision, "confirm": true, "privilegePolicy": "account"}, {"mode": TmuxManaged, "revision": strings.Repeat("0", 64), "confirm": true}} {
		if code := f.call(t, "POST", "/api/tmux-modes", input, nil); code == 200 {
			t.Fatal("invalid settings write accepted", input)
		}
	}
	runtime.start = func(Config) (*ManagedTmux, error) { return nil, errors.New("synthetic managed startup failure") }
	if err := runtime.setDefault(TmuxManaged, revision, ""); err == nil {
		t.Fatal("failed managed startup succeeded")
	}
	if tmuxConfigRevision(f.store.Configuration()) != revision || !tmuxReady(cfg) {
		t.Fatal("failed setup changed the existing pool or credentials")
	}
	f.app.auth.mu.Lock()
	for key, value := range f.app.auth.cookies {
		value.verified = time.Now().Add(-recentAuthTTL - time.Minute)
		f.app.auth.cookies[key] = value
	}
	f.app.auth.mu.Unlock()
	if code := f.call(t, "POST", "/api/tmux-modes", map[string]any{"mode": TmuxManaged, "revision": revision, "confirm": true}, nil); code != 403 {
		t.Fatal("old sign-in changed settings", code)
	}
}

func TestAdditionalIndependentSetupPreservesManagedSessions(t *testing.T) {
	f, runtime, _ := profilesFixture(t, TmuxManaged)
	base := f.store.Configuration()
	initialPlan := runtime.plan
	runtime.plan = func(dir, mode, executable string) (*TmuxSetupPlan, error) {
		p, err := initialPlan(dir, mode, executable)
		if err != nil {
			return nil, err
		}
		p.run = func(args ...string) error {
			if strings.Contains(strings.Join(args, " "), "enable --now") {
				candidate := p.config(base)
				candidate.TmuxAdditional = nil
				startProfileServer(t, candidate)
			}
			return nil
		}
		return p, nil
	}
	h, err := f.store.SaveHost(Host{Name: "Local", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: true})
	if err != nil {
		t.Fatal(err)
	}
	managed, _ := connectShellTab(t, f, h, map[string]any{"create": true, "session": "owned"})
	terminalCommand(t, managed, "POOL_VALUE=kept; printf 'BEFORE_%s\\n' \"$POOL_VALUE\"", "BEFORE_kept\r\n")
	var preview struct{ Revision string }
	if code := f.call(t, "GET", "/api/tmux-modes", nil, &preview); code != 200 {
		t.Fatal(code)
	}
	if code := f.call(t, "POST", "/api/tmux-modes", map[string]any{"mode": TmuxIndependent, "revision": preview.Revision, "confirm": true, "privilegePolicy": "restricted"}, nil); code != 200 {
		t.Fatal(code)
	}
	terminalCommand(t, managed, "printf 'AFTER_%s\\n' \"$POOL_VALUE\"", "AFTER_kept\r\n")
	independent, _ := connectShellTab(t, f, h, map[string]any{"create": true, "session": "separate"})
	terminalCommand(t, independent, "printf 'INDEPENDENT_ready\\n'", "INDEPENDENT_ready\r\n")
	cfg := f.store.Configuration()
	if cfg.TmuxAdditional == nil || cfg.TmuxAdditional.Service == nil {
		t.Fatal("additional service ownership was not retained")
	}
	receipt := cfg.TmuxAdditional.Service
	unit, err := os.ReadFile(receipt.ServicePath)
	if err != nil || receipt.PrivilegePolicy != "restricted" || !strings.Contains(string(unit), "NoNewPrivileges=true\n") {
		t.Fatal("new service ignored the reviewed policy", err)
	}
	additional := tmuxProfiles(cfg)[1]
	f.app.Close()
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if tmuxReady(base) || !tmuxReady(additional) {
		t.Fatal("shutdown confused primary managed and extra independent pools")
	}
}
