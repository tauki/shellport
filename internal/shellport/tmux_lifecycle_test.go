package shellport

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shortTmuxFixture(t *testing.T) (string, string) {
	t.Helper()
	binary, err := exec.LookPath("tmux")
	if err != nil {
		t.Skip("tmux integration requires tmux")
	}
	dir, err := os.MkdirTemp("/tmp", "shellport-lifecycle-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir, binary
}

func TestManagedTmuxHelperProcess(t *testing.T) {
	if os.Getenv("SHELLPORT_MANAGED_TEST_HELPER") != "1" {
		return
	}
	// StartManagedTmux appends its real CLI arguments after this test selector.
	index := 0
	for i, arg := range os.Args {
		if arg == "--data-dir" {
			index = i + 1
			break
		}
	}
	if index == 0 || index >= len(os.Args) {
		os.Exit(2)
	}
	store, err := OpenStore(os.Args[index])
	if err == nil {
		err = RunManagedTmuxHelper(store, os.Stdin, os.Stdout)
	}
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestManagedTmuxStopsOnOwnerPipeClosure(t *testing.T) {
	dir, binary := shortTmuxFixture(t)
	if err := Initialize(dir, testPassword, []string{"http://127.0.0.1:8088"}, ""); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.Configuration()
	cfg.AllowLocalShell = true
	cfg.TmuxMode = TmuxManaged
	cfg.TmuxExecutable = binary
	cfg.TmuxSocket = filepath.Join(dir, "runtime", "managed.sock")
	if err = writePrivate(filepath.Join(dir, "config.json"), cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHELLPORT_MANAGED_TEST_HELPER", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := StartManagedTmux(cfg, dir, exe, "-test.run=^TestManagedTmuxHelperProcess$", "--")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	command, err := LocalTmuxClient(cfg, "new-session", "-d", "-s", "kept", "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("new shell: %v %s", err, out)
	}
	if !tmuxReady(cfg) {
		t.Fatal("managed server did not become available")
	}
	// This is what abrupt loss of the owner does to its pipe, without invoking
	// the normal owner.Close cleanup path.
	if err = owner.watch.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-owner.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("helper did not clean up after owner loss")
	}
	if tmuxReady(cfg) {
		t.Fatal("managed tmux survived loss of its owner")
	}
	command, _ = LocalTmuxClient(cfg, "new-session", "-d", "-s", "must-not-recreate", "/bin/sh")
	if err = command.Run(); err == nil {
		t.Fatal("client silently recreated its stopped managed server")
	}
}

func setupFixture(t *testing.T, mode string) (*Store, *TmuxSetupPlan) {
	t.Helper()
	root, binary := shortTmuxFixture(t)
	dir := filepath.Join(root, "data")
	if err := Initialize(dir, testPassword, []string{"http://127.0.0.1:8088"}, ""); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planTmuxSetup(dir, mode, binary, setupEnvironment{"linux", root, filepath.Join(root, "config"), os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	plan.run = func(...string) error { return nil }
	plan.ready = func(Config) bool { return false }
	return store, plan
}

func TestTmuxSetupDefaultAndPreview(t *testing.T) {
	store, plan := setupFixture(t, "")
	if plan.Mode != TmuxIndependent || !strings.HasSuffix(plan.ServiceName, ".service") {
		t.Fatal("new setup did not default to independent ownership")
	}
	if store.Config.TmuxMode != "" {
		t.Fatal("legacy configuration changed during planning")
	}
	if _, err := os.Stat(plan.ServicePath); !os.IsNotExist(err) {
		t.Fatal("planning wrote a service")
	}
	if strings.Contains(string(plan.service), "PartOf=") || strings.Contains(string(plan.service), "BindsTo=") {
		t.Fatal("service lifetime was attached to another supervisor")
	}
	data, _ := json.Marshal(plan)
	if bytes.Contains(data, []byte(store.Config.PasswordHash)) {
		t.Fatal("preview exposed credential material")
	}
}

func TestTmuxSetupRefusesForeignServiceAndStalePlan(t *testing.T) {
	t.Run("foreign service", func(t *testing.T) {
		store, plan := setupFixture(t, TmuxIndependent)
		os.MkdirAll(filepath.Dir(plan.ServicePath), 0700)
		os.WriteFile(plan.ServicePath, []byte("operator-owned"), 0600)
		if err := plan.Apply(store); err == nil {
			t.Fatal("foreign service was overwritten")
		}
		data, _ := os.ReadFile(plan.ServicePath)
		if string(data) != "operator-owned" {
			t.Fatal("operator service changed")
		}
	})
	t.Run("stale configuration", func(t *testing.T) {
		store, plan := setupFixture(t, TmuxManaged)
		cfg := store.Configuration()
		cfg.MaxSessions = 5
		writePrivate(filepath.Join(store.Dir, "config.json"), cfg)
		if err := plan.Apply(store); err == nil || !strings.Contains(err.Error(), "changed since") {
			t.Fatal("stale setup was applied", err)
		}
	})
}

func TestTmuxSetupRollsBackServiceFailure(t *testing.T) {
	store, plan := setupFixture(t, TmuxIndependent)
	before, _ := os.ReadFile(filepath.Join(store.Dir, "config.json"))
	plan.run = func(args ...string) error {
		if strings.Contains(strings.Join(args, " "), "enable --now") {
			return errors.New("synthetic service-manager failure")
		}
		return nil
	}
	if err := plan.Apply(store); err == nil {
		t.Fatal("failed service installation was reported successful")
	}
	after, _ := os.ReadFile(filepath.Join(store.Dir, "config.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("failed setup changed the private configuration")
	}
	if _, err := os.Stat(plan.ServicePath); !os.IsNotExist(err) {
		t.Fatal("failed setup left its service file")
	}
	if _, err := os.Stat(filepath.Join(store.Dir, "tmux-setup.json")); !os.IsNotExist(err) {
		t.Fatal("failed setup claimed service ownership")
	}
	backups, _ := filepath.Glob(filepath.Join(store.Dir, "tmux-backups", "before-*.json"))
	if len(backups) != 1 {
		t.Fatal("setup did not retain a private rollback snapshot")
	}
}

func TestTmuxSetupPreservesLiveLegacyWork(t *testing.T) {
	store, plan := setupFixture(t, TmuxManaged)
	cfg := store.Configuration()
	cfg.AllowLocalShell = true
	cfg.TmuxExecutable = testTmux(t)
	store.Config = cfg
	if err := writePrivate(filepath.Join(store.Dir, "config.json"), cfg); err != nil {
		t.Fatal(err)
	}
	plan.source, _ = os.ReadFile(filepath.Join(store.Dir, "config.json"))
	if out, err := exec.Command(cfg.TmuxExecutable, "new-session", "-d", "-s", "work").CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v %s", err, out)
	}
	if err := plan.Apply(store); err == nil || !strings.Contains(err.Error(), "sessions were preserved") {
		t.Fatal("live work did not block mode change", err)
	}
	if err := exec.Command(cfg.TmuxExecutable, "has-session", "-t", "=work").Run(); err != nil {
		t.Fatal("mode change ended existing work")
	}
}

func TestTmuxSetupLockAndOperatorChanges(t *testing.T) {
	store, plan := setupFixture(t, TmuxIndependent)
	lock, err := LockInstallation(store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = plan.Apply(store); err == nil {
		t.Fatal("setup changed a running installation")
	}
	lock.Close()
	started := false
	plan.ready = func(Config) bool { return started }
	plan.run = func(args ...string) error {
		if strings.Contains(strings.Join(args, " "), "enable --now") {
			started = true
		}
		return nil
	}
	if err = plan.Apply(store); err != nil {
		t.Fatal(err)
	}
	current, err := OpenStore(store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	next, err := planTmuxSetup(store.Dir, TmuxManaged, plan.Executable, plan.env)
	if err != nil {
		t.Fatal(err)
	}
	next.run = func(...string) error { t.Fatal("operator-modified service reached a mutation"); return nil }
	f, err := os.OpenFile(plan.ServicePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("# operator change\n")
	f.Close()
	if err = next.Apply(current); err == nil || !strings.Contains(err.Error(), "changed outside") {
		t.Fatal("operator service edit was overwritten", err)
	}
}

func TestExplicitTmuxModesValidateAndLegacyRemainsCompatible(t *testing.T) {
	for _, cfg := range []Config{{TmuxMode: "bad"}, {TmuxMode: TmuxManaged, TmuxSocket: "relative", TmuxExecutable: "/bin/false"}, {TmuxSocket: "/tmp/socket"}} {
		if validateTmuxConfig(cfg) == nil {
			t.Fatal("invalid explicit mode accepted", cfg)
		}
	}
	if err := validateTmuxConfig(Config{TmuxExecutable: "operator-wrapper"}); err != nil {
		t.Fatal("legacy operator configuration rejected", err)
	}
}

func TestTmuxSetupChangesOnlyLifecycleConfiguration(t *testing.T) {
	store, plan := setupFixture(t, TmuxIndependent)
	keyBefore, _ := os.ReadFile(store.Config.KeyFile)
	initial := store.Configuration()
	started := false
	plan.ready = func(Config) bool { return started }
	plan.run = func(args ...string) error {
		if strings.Contains(strings.Join(args, " "), "enable --now") {
			started = true
		}
		return nil
	}
	if err := plan.Apply(store); err != nil {
		t.Fatal(err)
	}
	current, err := OpenStore(store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	next, err := planTmuxSetup(store.Dir, TmuxManaged, plan.Executable, plan.env)
	if err != nil {
		t.Fatal(err)
	}
	next.ready = func(Config) bool { return false }
	stopped := false
	next.run = func(args ...string) error {
		if strings.Contains(strings.Join(args, " "), "disable --now") {
			stopped = true
		}
		return nil
	}
	if err = next.Apply(current); err != nil {
		t.Fatal(err)
	}
	if !stopped {
		t.Fatal("owned independent service was not stopped before mode change")
	}
	if _, err = os.Stat(plan.ServicePath); !os.IsNotExist(err) {
		t.Fatal("managed mode retained its owned independent service file")
	}
	after, err := OpenStore(store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.Config.TmuxMode != TmuxManaged || after.Config.PasswordHash != initial.PasswordHash || after.Config.KeyFile != initial.KeyFile {
		t.Fatal("mode change changed installation identity")
	}
	keyAfter, _ := os.ReadFile(after.Config.KeyFile)
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("mode change replaced the SSH key")
	}
}

func TestTmuxSetupLaunchAgentIsValidXML(t *testing.T) {
	root, binary := shortTmuxFixture(t)
	plan, err := planTmuxSetup(filepath.Join(root, "data & work"), TmuxIndependent, binary, setupEnvironment{"darwin", root, filepath.Join(root, "c&"), os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(plan.service))
	for {
		_, err = decoder.Token()
		if err != nil {
			break
		}
	}
	if err != io.EOF {
		t.Fatal("generated launch agent is invalid XML", err)
	}
	if strings.Contains(string(plan.service), "/c&/") || !strings.Contains(string(plan.service), "/c&amp;/") {
		t.Fatal("service paths were not XML-escaped")
	}
	if strings.Contains(string(plan.service), "shellport serve") {
		t.Fatal("tmux service depends on the web-server process")
	}
}

func TestTmuxSetupSystemdPreservesLiteralExecutable(t *testing.T) {
	root, _ := shortTmuxFixture(t)
	binary := filepath.Join(root, "tmux $binary% &")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	plan, err := planTmuxSetup(filepath.Join(root, "data"), TmuxIndependent, binary, setupEnvironment{"linux", root, filepath.Join(root, "c$% &"), os.Getuid()})
	if err != nil {
		t.Fatal(err)
	}
	// Unlike arguments, systemd's executable word does not expand dollars.
	// Doubling one makes it look for a different, nonexistent executable.
	if !strings.Contains(string(plan.service), `ExecStart="`+root+`/tmux $binary%% &" -D`) {
		t.Fatal("systemd executable was changed by dollar escaping")
	}
	if !strings.Contains(string(plan.service), `/c$$%% &/Shellport/tmux/`) {
		t.Fatal("systemd socket argument did not protect dollars and specifiers")
	}
}
