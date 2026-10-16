package shellport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProcessPrivilegeParsingFailsUnknown(t *testing.T) {
	base := "Pid:\t123\nUid:\t501\t501\t501\t501\nNoNewPrivs:\t"
	for _, tc := range []struct{ status, state string }{
		{base + "0\n", "not-blocked"},
		{base + "1\n", "blocked"},
		{base + "2\n", "unknown"},
		{base + "1 0\n", "unknown"},
		{base + "\n", "unknown"},
		{base + "0\nNoNewPrivs:\t1\n", "unknown"},
		{strings.ReplaceAll(base+"0\n", "123", "124"), "unknown"},
		{strings.ReplaceAll(base+"0\n", "501", "502"), "unknown"},
		{"Pid:\t123\nUid:\t501\t501\t501\t501\n", "unknown"},
		{base + "1\nUid:\t501\t501\t501\t501\n", "unknown"},
	} {
		if got := parseProcessPrivileges(tc.status, 123, 501); got.State != tc.state {
			t.Fatalf("%q: got %s, want %s", tc.status, got.State, tc.state)
		}
	}
	if processPrivileges(-1).State != "unknown" {
		t.Fatal("invalid PID was treated as an unrestricted process")
	}
	if runtime.GOOS != "linux" && processPrivileges(os.Getpid()).State != "unknown" {
		t.Fatal("unsupported platform made a claim about sudo")
	}
}

func TestTmuxPrivilegeObservationReconfirmsAndNeverStartsServer(t *testing.T) {
	for _, tc := range []struct{ name, first, second, want string }{
		{"stable", "123\n", "123\n", "blocked"},
		{"replaced", "123\n", "124\n", "unknown"},
		{"invalid", "not-a-pid", "", "unknown"},
		{"exited", "123\n", "", "unknown"},
		{"zero", "0", "", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			run := func(_ context.Context, args ...string) ([]byte, []byte, error) {
				if strings.Join(args, " ") != "-N display-message -p #{pid}" {
					t.Fatal("diagnostic could start or change a server", args)
				}
				calls++
				if calls == 1 {
					return []byte(tc.first), nil, nil
				}
				if tc.second == "" {
					return nil, nil, errors.New("server exited")
				}
				return []byte(tc.second), nil, nil
			}
			got := tmuxRunnerPrivileges(context.Background(), run, func(pid int) localPrivileges {
				if pid != 123 {
					t.Fatal("unexpected observed process", pid)
				}
				return localPrivileges{State: "blocked"}
			})
			if got.State != tc.want {
				t.Fatal(got, tc.want)
			}
		})
	}
}

func TestPrivilegeSettingsPreserveSessionsAndRejectExistingPolicyChanges(t *testing.T) {
	f, _, _ := profilesFixture(t, TmuxIndependent)
	h, err := f.store.SaveHost(Host{Name: "Local", Address: "127.0.0.1", Port: 22, Username: "tester", Auth: "local", Tmux: true})
	if err != nil {
		t.Fatal(err)
	}
	terminal, _ := connectShellTab(t, f, h, map[string]any{"create": true, "session": "retained"})
	terminalCommand(t, terminal, "KEEP_VALUE=unchanged; printf 'PID_%s\\n' \"$$\"", "PID_")
	before, _ := os.ReadFile(filepath.Join(f.store.Dir, "config.json"))
	var info struct {
		Revision         string
		DirectPrivileges localPrivileges
		Modes            []tmuxModeOption
	}
	for i := 0; i < 2; i++ {
		if code := f.call(t, "GET", "/api/tmux-modes", nil, &info); code != 200 {
			t.Fatal(code)
		}
		if info.DirectPrivileges != processPrivileges(os.Getpid()) {
			t.Fatal("server flag not observed", info)
		}
		for _, mode := range info.Modes {
			if !mode.Configured {
				continue
			}
			want := processPrivileges(os.Getpid()).State
			if mode.Privileges.State != want {
				t.Fatal("tmux flag not observed", mode)
			}
		}
	}
	for _, policy := range []string{"account", "restricted"} {
		if code := f.call(t, "POST", "/api/tmux-modes", map[string]any{"mode": TmuxIndependent, "revision": info.Revision, "confirm": true, "privilegePolicy": policy}, nil); code != 409 {
			t.Fatal("existing pool policy change was accepted", code)
		}
	}
	after, _ := os.ReadFile(filepath.Join(f.store.Dir, "config.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("settings changed existing configuration")
	}
	terminalCommand(t, terminal, "printf 'KEPT_%s\\n' \"$KEEP_VALUE\"", "KEPT_unchanged\r\n")
}

func TestMissingTmuxPrivilegeDiagnosticDoesNotStartServer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux process flags")
	}
	root, binary := shortTmuxFixture(t)
	cfg := Config{AllowLocalShell: true, TmuxMode: TmuxIndependent, TmuxExecutable: binary, TmuxSocket: filepath.Join(root, "missing.sock")}
	if got := tmuxProcessPrivileges(context.Background(), cfg); got.State != "unknown" {
		t.Fatal(got)
	}
	if _, err := os.Stat(cfg.TmuxSocket); !os.IsNotExist(err) {
		t.Fatal("diagnostic created a server socket", err)
	}
}

func TestConfiguredTmuxPrivilegeObservation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux process flags")
	}
	binary := os.Getenv("SHELLPORT_TEST_TMUX")
	if binary == "" {
		var err error
		binary, err = exec.LookPath("tmux")
		if err != nil {
			t.Skip("tmux integration requires tmux or SHELLPORT_TEST_TMUX")
		}
	}
	root, err := os.MkdirTemp("/tmp", "shellport-privilege-tmux-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	cfg := Config{AllowLocalShell: true, TmuxMode: TmuxIndependent, TmuxExecutable: binary, TmuxSocket: filepath.Join(root, "tmux.sock")}
	startProfileServer(t, cfg)
	if got, want := tmuxProcessPrivileges(context.Background(), cfg), processPrivileges(os.Getpid()); got != want || got.State == "unknown" {
		t.Fatal("running configured tmux server's actual flag was not observed", got, want)
	}
}

func TestTmuxSetupPrivilegeChoiceAndSessionPreservation(t *testing.T) {
	store, plan := setupFixture(t, TmuxIndependent)
	if plan.PrivilegePolicy != "account" || !strings.Contains(string(plan.service), "NoNewPrivileges=false\n") {
		t.Fatal("unexpected new-service policy")
	}
	if err := plan.SetPrivilegePolicy("restricted"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plan.service), "NoNewPrivileges=true\n") {
		t.Fatal("restricted policy not in reviewed service")
	}
	startProfileServer(t, plan.config(store.Configuration()))
	plan.run = func(...string) error { return nil }
	if err := writePrivate(filepath.Join(store.Dir, "config.json"), plan.config(store.Configuration())); err != nil {
		t.Fatal(err)
	}
	store.Config = plan.config(store.Configuration())
	if err := os.MkdirAll(filepath.Dir(plan.ServicePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plan.ServicePath, plan.service, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(filepath.Join(store.Dir, "tmux-setup.json"), plan.record()); err != nil {
		t.Fatal(err)
	}
	cmd, _ := LocalTmuxClient(store.Configuration(), "new-session", "-d", "-s", "kept", "/bin/sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	before, _ := os.ReadFile(plan.ServicePath)
	next, err := planTmuxSetup(store.Dir, TmuxIndependent, plan.Executable, plan.env)
	if err != nil {
		t.Fatal(err)
	}
	if next.PrivilegePolicy != "restricted" || !bytes.Equal(before, next.service) {
		t.Fatal("omitted policy did not preserve the existing service")
	}
	next.run = func(args ...string) error {
		if strings.Contains(strings.Join(args, " "), "disable") {
			t.Fatal("saved work reached a service stop")
		}
		return nil
	}
	if err := next.Apply(store); err != nil {
		t.Fatal("unchanged service could not retain live work", err)
	}
	if err := next.SetPrivilegePolicy("account"); err != nil {
		t.Fatal(err)
	}
	if err := next.Apply(store); err == nil || !strings.Contains(err.Error(), "sessions were preserved") {
		t.Fatal("live service policy changed", err)
	}
	after, _ := os.ReadFile(plan.ServicePath)
	if !bytes.Equal(before, after) {
		t.Fatal("service policy changed despite saved work")
	}
	cmd, _ = LocalTmuxClient(store.Configuration(), "has-session", "-t", "=kept")
	if err := cmd.Run(); err != nil {
		t.Fatal("saved session ended", err)
	}
}

func TestTmuxSetupPreservesPrePolicyServiceTemplate(t *testing.T) {
	store, plan := setupFixture(t, TmuxIndependent)
	plan.legacyPrivileges = true
	if err := plan.setPrivilegePolicy("account", true); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(plan.ServicePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plan.ServicePath, plan.service, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(filepath.Join(store.Dir, "tmux-setup.json"), plan.record()); err != nil {
		t.Fatal(err)
	}
	next, err := planTmuxSetup(store.Dir, TmuxIndependent, plan.Executable, plan.env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(next.service, plan.service) || next.record().PrivilegePolicy != "" {
		t.Fatal("legacy service silently changed")
	}
	if err := next.SetPrivilegePolicy("restricted"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(next.service), "NoNewPrivileges=true\n") {
		t.Fatal("explicit policy was ignored")
	}
}

func TestTmuxPrivilegePolicyRejectsUnsupportedPlans(t *testing.T) {
	_, plan := setupFixture(t, TmuxIndependent)
	for _, policy := range []string{"root", "TRUE", "account\nNoNewPrivileges=true"} {
		if err := plan.SetPrivilegePolicy(policy); err == nil {
			t.Fatal("invalid policy accepted", fmt.Sprintf("%q", policy))
		}
	}
	for _, tc := range []struct{ mode, system string }{{TmuxManaged, "linux"}, {TmuxIndependent, "darwin"}} {
		plan.Mode, plan.env.system = tc.mode, tc.system
		if err := plan.SetPrivilegePolicy("account"); err == nil {
			t.Fatal("unsupported policy silently ignored", tc)
		}
	}
}
