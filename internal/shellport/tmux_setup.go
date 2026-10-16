package shellport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type tmuxSetupRecord struct {
	Version         int    `json:"version"`
	Mode            string `json:"mode"`
	Executable      string `json:"executable"`
	Socket          string `json:"socket"`
	ServiceName     string `json:"serviceName,omitempty"`
	ServicePath     string `json:"servicePath,omitempty"`
	ServiceHash     string `json:"serviceHash,omitempty"`
	PrivilegePolicy string `json:"privilegePolicy,omitempty"`
}

type setupEnvironment struct {
	system, home, config string
	uid                  int
}

// TmuxSetupPlan contains no credentials and can be displayed before any write.
type TmuxSetupPlan struct {
	Mode             string `json:"mode"`
	Effect           string `json:"effect"`
	DataDirectory    string `json:"dataDirectory"`
	Executable       string `json:"tmuxExecutable"`
	Socket           string `json:"socket"`
	ServiceManager   string `json:"serviceManager,omitempty"`
	ServiceName      string `json:"serviceName,omitempty"`
	ServicePath      string `json:"servicePath,omitempty"`
	Startup          string `json:"startup"`
	PrivilegePolicy  string `json:"privilegePolicy"`
	PrivilegeEffect  string `json:"privilegeEffect"`
	env              setupEnvironment
	service          []byte
	source           []byte
	recordSource     []byte
	run              func(...string) error
	ready            func(Config) bool
	legacyPrivileges bool
}

func PlanTmuxSetup(dir, mode, executable string) (*TmuxSetupPlan, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	config, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return planTmuxSetup(dir, mode, executable, setupEnvironment{runtime.GOOS, home, config, os.Getuid()})
}

func canonicalDirectory(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	base := abs
	var suffix []string
	for {
		if _, err = os.Stat(base); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(base)
		if parent == base {
			return "", err
		}
		suffix = append([]string{filepath.Base(base)}, suffix...)
		base = parent
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{base}, suffix...)...), nil
}

func planTmuxSetup(dir, mode, executable string, env setupEnvironment) (*TmuxSetupPlan, error) {
	if mode == "" {
		mode = TmuxIndependent
	}
	if mode != TmuxIndependent && mode != TmuxManaged {
		return nil, errors.New("choose --tmux-mode independent or managed")
	}
	abs, err := canonicalDirectory(dir)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(abs+env.home+env.config, "\x00\r\n") {
		return nil, errors.New("setup paths must not contain line breaks or NUL bytes")
	}
	source, err := readPrivateState(filepath.Join(abs, "config.json"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var cfg Config
	if len(source) > 0 {
		if err = json.Unmarshal(source, &cfg); err != nil {
			return nil, err
		}
	}
	if executable == "" {
		executable = cfg.TmuxExecutable
	}
	if executable == "" {
		executable = "tmux"
	}
	executable, err = exec.LookPath(executable)
	if err != nil {
		return nil, errors.New("install tmux first, or provide its absolute executable with --tmux-bin")
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(executable, "\x00\r\n") {
		return nil, errors.New("tmux executable path must not contain line breaks or NUL bytes")
	}
	hash := sha256.Sum256([]byte(abs))
	id := hex.EncodeToString(hash[:8])
	socket := filepath.Join(env.config, "Shellport", "tmux", id, mode+".sock")
	if len(socket) > 100 {
		return nil, errors.New("the user configuration path is too long for a Unix socket; choose a shorter user configuration location before setup")
	}
	p := &TmuxSetupPlan{Mode: mode, DataDirectory: abs, Executable: executable, Socket: socket, env: env, source: source, run: runTmuxService, ready: tmuxReady}
	p.recordSource, err = os.ReadFile(filepath.Join(abs, "tmux-setup.json"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if mode == TmuxManaged {
		p.Effect = "Closing the browser keeps local shells running. Stopping or restarting Shellport ends all of this installation's local tmux shells. SSH targets are unchanged."
		p.Startup = "Shellport starts and owns its private tmux server; no OS service is installed."
		p.PrivilegePolicy = "inherited"
		p.PrivilegeEffect = "Managed shells inherit Shellport's process restrictions. Configure the service that launches Shellport to change them. Existing processes keep their restrictions."
	} else {
		p.Effect = "Local tmux shells survive Shellport and hosting-supervisor restarts. Stopping tmux or rebooting its computer ends them. SSH targets are unchanged."
		switch env.system {
		case "linux":
			p.ServiceManager = "systemd user service"
			p.ServiceName = "shellport-tmux-" + id + ".service"
			p.ServicePath = filepath.Join(env.config, "systemd", "user", p.ServiceName)
			p.Startup = "Enabled in the user service manager. Boot without login requires separately configured user lingering."
			policy := "account"
			if len(p.recordSource) > 0 {
				var previous tmuxSetupRecord
				if err := json.Unmarshal(p.recordSource, &previous); err != nil {
					return nil, err
				}
				if previous.Mode == TmuxIndependent && previous.ServiceName == p.ServiceName && previous.ServicePath == p.ServicePath {
					if previous.PrivilegePolicy == "" {
						// Preserve the exact pre-policy template when no change was
						// requested, including while saved sessions are running.
						p.legacyPrivileges = true
					} else {
						policy = previous.PrivilegePolicy
					}
				}
			}
			if err := p.setPrivilegePolicy(policy, p.legacyPrivileges); err != nil {
				return nil, err
			}
		case "darwin":
			p.ServiceManager = "launchd user agent"
			p.ServiceName = "site.shellport.tmux." + id
			p.ServicePath = filepath.Join(env.home, "Library", "LaunchAgents", p.ServiceName+".plist")
			p.Startup = "Starts in the user's GUI login session; a logged-in launchd GUI domain is required."
			p.PrivilegePolicy = "inherited"
			p.PrivilegeEffect = "Shells use the account's OS permissions and the user service manager's restrictions. The Linux privilege policy option does not apply."
			p.service = []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>" + xmlText(p.ServiceName) + "</string><key>ProgramArguments</key><array>" + plistStrings(executable, "-D", "-f", "/dev/null", "-S", socket) + "</array><key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict><key>Umask</key><integer>63</integer><key>EnvironmentVariables</key><dict><key>PATH</key><string>" + xmlText(servicePath(executable)) + "</string><key>LANG</key><string>C.UTF-8</string></dict></dict></plist>\n")
		default:
			return nil, errors.New("automatic independent tmux setup supports Linux systemd user services and macOS GUI launch agents; use managed mode or retain an existing operator setup on this host")
		}
	}
	return p, nil
}

// SetPrivilegePolicy changes only a reviewed Linux independent-service plan.
// Applying it still requires the installation lock, service ownership checks and
// no existing tmux work. An omitted option preserves an existing owned policy.
func (p *TmuxSetupPlan) SetPrivilegePolicy(policy string) error {
	return p.setPrivilegePolicy(policy, false)
}

func (p *TmuxSetupPlan) setPrivilegePolicy(policy string, legacy bool) error {
	if policy == "" {
		return nil
	}
	if p.Mode != TmuxIndependent || p.env.system != "linux" {
		return errors.New("--tmux-privileges applies only to independent tmux services on Linux; managed shells inherit Shellport's process policy")
	}
	if policy != "account" && policy != "restricted" {
		return errors.New("choose --tmux-privileges account or restricted")
	}
	p.legacyPrivileges = legacy
	p.PrivilegePolicy = policy
	p.PrivilegeEffect = "Uses the account's normal OS permissions. Sudo still depends on account authorization and other OS rules. Existing processes keep their restrictions."
	setting := "false"
	if policy == "restricted" {
		setting = "true"
		p.PrivilegeEffect = "Blocks gaining privileges through setuid programs such as sudo using NoNewPrivileges=true. Existing processes keep their restrictions."
	}
	line := "NoNewPrivileges=" + setting + "\n"
	if p.legacyPrivileges {
		line = ""
	}
	// The executable word has no environment expansion; only arguments need
	// doubled dollar signs. The setting controls this new service, not its manager.
	p.service = []byte("[Unit]\nDescription=Shellport persistent tmux\n\n[Service]\nType=exec\nExecStart=" + systemdEnvironment(p.Executable) + " -D -f /dev/null -S " + systemdWord(p.Socket) + "\nEnvironment=" + systemdEnvironment("PATH="+servicePath(p.Executable)) + "\nEnvironment=LANG=C.UTF-8\nUMask=0077\n" + line + "Restart=on-failure\nRestartSec=2\nTimeoutStopSec=10\n\n[Install]\nWantedBy=default.target\n")
	return nil
}

func (p *TmuxSetupPlan) Preflight() error {
	if p.Mode == TmuxIndependent {
		return p.serviceCheck()
	}
	return nil
}

func servicePath(executable string) string {
	return filepath.Dir(executable) + ":/usr/local/bin:/usr/bin:/bin"
}
func systemdEnvironment(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`).Replace(value) + `"`
}
func systemdWord(value string) string {
	return strings.ReplaceAll(systemdEnvironment(value), "$", "$$")
}
func xmlText(value string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}
func plistStrings(values ...string) string {
	var b strings.Builder
	for _, value := range values {
		b.WriteString("<string>" + xmlText(value) + "</string>")
	}
	return b.String()
}

func runTmuxService(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var diagnostic boundedOutput
	cmd.Stderr = &diagnostic
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w: %s", args[0], err, strings.TrimSpace(string(diagnostic.data)))
	}
	return nil
}

func (p *TmuxSetupPlan) serviceCheck() error {
	if p.env.system == "linux" {
		return p.run("systemctl", "--user", "show", "--property=Version")
	}
	return p.run("launchctl", "print", "gui/"+strconv.Itoa(p.env.uid))
}
func (p *TmuxSetupPlan) serviceStart() error {
	if p.env.system == "linux" {
		if err := p.run("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		return p.run("systemctl", "--user", "enable", "--now", p.ServiceName)
	}
	domain := "gui/" + strconv.Itoa(p.env.uid)
	if err := p.run("launchctl", "enable", domain+"/"+p.ServiceName); err != nil {
		return err
	}
	if p.run("launchctl", "print", domain+"/"+p.ServiceName) == nil {
		return nil
	}
	return p.run("launchctl", "bootstrap", domain, p.ServicePath)
}
func (p *TmuxSetupPlan) serviceStop() error {
	if p.env.system == "linux" {
		return p.run("systemctl", "--user", "disable", "--now", p.ServiceName)
	}
	name := "gui/" + strconv.Itoa(p.env.uid) + "/" + p.ServiceName
	if p.run("launchctl", "print", name) != nil {
		return nil
	}
	return p.run("launchctl", "bootout", name)
}

func (p *TmuxSetupPlan) config(cfg Config) Config {
	cfg.AllowLocalShell = true
	cfg.TmuxMode = p.Mode
	cfg.TmuxSocket = p.Socket
	cfg.TmuxExecutable = p.Executable
	return cfg
}
func (p *TmuxSetupPlan) record() tmuxSetupRecord {
	r := tmuxSetupRecord{Version: 1, Mode: p.Mode, Executable: p.Executable, Socket: p.Socket, ServiceName: p.ServiceName, ServicePath: p.ServicePath}
	if p.Mode == TmuxIndependent && p.env.system == "linux" && !p.legacyPrivileges {
		r.PrivilegePolicy = p.PrivilegePolicy
	}
	if len(p.service) > 0 {
		hash := sha256.Sum256(p.service)
		r.ServiceHash = hex.EncodeToString(hash[:])
	}
	return r
}

func (p *TmuxSetupPlan) oldService() (*TmuxSetupPlan, error) {
	if len(p.recordSource) == 0 {
		return nil, nil
	}
	var old tmuxSetupRecord
	if err := json.Unmarshal(p.recordSource, &old); err != nil {
		return nil, err
	}
	if old.Version != 1 {
		return nil, errors.New("unsupported tmux setup record; retained files were preserved")
	}
	if old.Mode != TmuxIndependent {
		return nil, nil
	}
	expected, err := planTmuxSetup(p.DataDirectory, TmuxIndependent, old.Executable, p.env)
	if err != nil {
		return nil, err
	}
	if old.ServicePath != expected.ServicePath || old.ServiceName != expected.ServiceName {
		return nil, errors.New("tmux service ownership record does not match this installation")
	}
	content, err := os.ReadFile(old.ServicePath)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(content)
	if hex.EncodeToString(hash[:]) != old.ServiceHash {
		return nil, errors.New("tmux service file was changed outside Shellport; it was not overwritten")
	}
	expected.service = content
	return expected, nil
}

func checkNoTmuxWork(cfg Config) error {
	if !cfg.AllowLocalShell {
		return nil
	}
	executable, err := tmuxExecutable(cfg)
	if err != nil {
		return err
	}
	sessions, err := rawTmuxSessions(context.Background(), localTmuxRunner(cfg, executable))
	if err != nil {
		return err
	}
	if len(sessions) > 0 {
		return errors.New("existing local tmux sessions were preserved; stop Shellport and finish or explicitly migrate that work before changing its lifecycle")
	}
	return nil
}

// Apply validates the reviewed plan again under an installation lock. Services
// are changed only through their user manager, and only receipt-owned files can
// be replaced or removed. Existing sessions are never killed to make setup pass.
func (p *TmuxSetupPlan) Apply(store *Store) (err error) {
	lock, err := LockInstallation(store.Dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	current, err := readPrivateState(filepath.Join(store.Dir, "config.json"))
	if err != nil {
		return err
	}
	if !bytes.Equal(current, p.source) {
		return errors.New("configuration changed since the setup preview; review a fresh plan")
	}
	recordPath := filepath.Join(store.Dir, "tmux-setup.json")
	record, readErr := os.ReadFile(recordPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	if !bytes.Equal(record, p.recordSource) {
		return errors.New("tmux setup changed since the preview; review a fresh plan")
	}
	cfg := store.Configuration()
	next := p.config(cfg)
	if cfg.TmuxAdditional != nil && (cfg.TmuxMode != p.Mode || cfg.TmuxSocket != p.Socket || cfg.TmuxExecutable != p.Executable) {
		return errors.New("Both local tmux modes are configured. Change the default in Workspace settings; existing pools were preserved.")
	}
	old, err := p.oldService()
	if err != nil {
		return err
	}
	same := cfg.AllowLocalShell && cfg.TmuxMode == next.TmuxMode && cfg.TmuxSocket == next.TmuxSocket && cfg.TmuxExecutable == next.TmuxExecutable
	if same && (p.Mode == TmuxManaged || old != nil && bytes.Equal(old.service, p.service)) {
		if p.Mode == TmuxIndependent {
			if err = p.serviceCheck(); err != nil {
				return err
			}
			if err = p.serviceStart(); err != nil {
				return err
			}
			return p.waitReady(next)
		}
		return nil
	}
	if err = checkNoTmuxWork(cfg); err != nil {
		return err
	}
	if p.Mode == TmuxIndependent {
		if err = p.serviceCheck(); err != nil {
			return fmt.Errorf("independent tmux needs an available user service manager: %w", err)
		}
		if _, e := os.Lstat(p.ServicePath); e == nil && (old == nil || old.ServicePath != p.ServicePath) {
			return errors.New("an existing service file is not owned by this installation; it was preserved")
		} else if e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	if err = privateTmuxDirectory(filepath.Dir(p.Socket)); err != nil {
		return err
	}
	if p.ready(next) && !(old != nil && cfg.TmuxSocket == next.TmuxSocket) {
		return errors.New("the new socket already has a tmux server; it was not adopted or stopped")
	}
	if err = p.backup(old); err != nil {
		return err
	}
	if old != nil {
		old.run = p.run
		if err = old.serviceStop(); err != nil {
			return err
		}
	}
	started := false
	written := false
	oldRemoved := false
	defer func() {
		if err == nil {
			return
		}
		// No web server can create work while this lock is held. Still refuse
		// rollback if a manual client created a session on the candidate socket.
		if p.ready(next) && checkNoTmuxWork(next) != nil {
			err = fmt.Errorf("%w; new tmux work exists, so rollback was not attempted", err)
			return
		}
		if written {
			if started {
				_ = p.serviceStop()
			}
			if old != nil {
				_ = writeAtomic(old.ServicePath, old.service, 0600)
			} else {
				_ = os.Remove(p.ServicePath)
			}
			if p.env.system == "linux" {
				_ = p.run("systemctl", "--user", "daemon-reload")
			}
		}
		if old != nil {
			if oldRemoved {
				if restore := writeAtomic(old.ServicePath, old.service, 0600); restore != nil {
					err = fmt.Errorf("%w; previous service file restore failed: %v", err, restore)
					return
				}
			}
			if restore := old.serviceStart(); restore != nil {
				err = fmt.Errorf("%w; previous service restart failed: %v", err, restore)
			}
		}
	}()
	if p.Mode == TmuxIndependent {
		if err = os.MkdirAll(filepath.Dir(p.ServicePath), 0700); err != nil {
			return err
		}
		if err = writeAtomic(p.ServicePath, p.service, 0600); err != nil {
			return err
		}
		written = true
		started = true
		if err = p.serviceStart(); err != nil {
			return err
		}
		if err = p.waitReady(next); err != nil {
			return err
		}
	}
	if p.Mode == TmuxManaged && old != nil {
		if err = os.Remove(old.ServicePath); err != nil {
			return err
		}
		oldRemoved = true
		if p.env.system == "linux" {
			if err = p.run("systemctl", "--user", "daemon-reload"); err != nil {
				return err
			}
		}
	}
	if err = writePrivate(recordPath, p.record()); err != nil {
		return err
	}
	if err = writePrivate(filepath.Join(store.Dir, "config.json"), next); err != nil {
		if len(record) > 0 {
			_ = writeAtomic(recordPath, record, 0600)
		} else {
			_ = os.Remove(recordPath)
		}
		return err
	}
	store.mu.Lock()
	store.Config = next
	store.mu.Unlock()
	return nil
}

func (p *TmuxSetupPlan) backup(old *TmuxSetupPlan) error {
	dir := filepath.Join(p.DataDirectory, "tmux-backups")
	if err := privateTmuxDirectory(dir); err != nil {
		return err
	}
	snapshot := struct {
		Configuration json.RawMessage `json:"configuration"`
		Setup         json.RawMessage `json:"setup,omitempty"`
		ServicePath   string          `json:"servicePath,omitempty"`
		Service       []byte          `json:"service,omitempty"`
	}{Configuration: p.source, Setup: p.recordSource}
	if old != nil {
		snapshot.ServicePath = old.ServicePath
		snapshot.Service = old.service
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "before-*.json")
	if err != nil {
		return err
	}
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func (p *TmuxSetupPlan) waitReady(cfg Config) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if p.ready(cfg) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("independent tmux did not become ready; the previous configuration was preserved")
}
