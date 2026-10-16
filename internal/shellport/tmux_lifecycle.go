package shellport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	TmuxIndependent = "independent"
	TmuxManaged     = "managed"
)

func validateTmuxConfig(cfg Config) error {
	if err := validateTmuxProfiles(cfg); err != nil {
		return err
	}
	// An absent mode preserves existing operator wrappers and default sockets.
	if cfg.TmuxMode == "" {
		if cfg.TmuxSocket != "" {
			return errors.New("tmuxSocket requires an explicit tmuxMode")
		}
		return nil
	}
	if cfg.TmuxMode != TmuxIndependent && cfg.TmuxMode != TmuxManaged {
		return errors.New("tmuxMode must be independent or managed")
	}
	if !filepath.IsAbs(cfg.TmuxExecutable) {
		return errors.New("explicit tmux modes require an absolute tmuxExecutable")
	}
	if !filepath.IsAbs(cfg.TmuxSocket) || len(cfg.TmuxSocket) > 100 {
		return errors.New("tmuxSocket must be an absolute path of at most 100 bytes")
	}
	return nil
}

// LockInstallation excludes a live server, setup and password recovery. The file stays
// in place so closing one owner cannot unlink a lock held by its successor.
func LockInstallation(dir string) (*os.File, error) {
	dir, err := privateStateDirectory(dir)
	if err != nil {
		return nil, err
	}
	parent, err := openStateDirectory(dir, true)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), "server.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(dir, "server.lock"))
	if err = validatePrivateStateFile(f); err != nil {
		f.Close()
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("Shellport or another setup/recovery operation is already running for this data directory; stop it before continuing")
	}
	return f, nil
}

func lockFile(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("refusing a symbolic-link lock file")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("Shellport or another setup/recovery operation is already running for this data directory; stop it before continuing")
	}
	return f, nil
}

func privateTmuxDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || int(owner.Uid) != os.Getuid() || info.Mode().Perm()&0077 != 0 {
		return errors.New("tmux socket directory must be a private, owner-controlled directory without a symbolic link")
	}
	return nil
}

func tmuxReady(cfg Config) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd, err := localTmuxCommand(cfg, cfg.TmuxExecutable, "show-options", "-s", "-v", "exit-empty")
	if err != nil {
		return false
	}
	bounded := exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	bounded.Env, bounded.Dir = cmd.Env, cmd.Dir
	return bounded.Run() == nil
}

func waitTmux(cfg Config, exited <-chan struct{}) error {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if tmuxReady(cfg) {
			return nil
		}
		select {
		case <-exited:
			return errors.New("tmux exited before its private server became ready; check the executable and its -D/-N/-S support")
		case <-deadline.C:
			return errors.New("tmux did not become ready on its configured socket")
		case <-tick.C:
		}
	}
}

// ManagedTmux owns a helper and its parent-liveness pipe, never a stored PID.
// The helper also cleans up after SIGKILL of the web process, when defers cannot run.
type ManagedTmux struct {
	cmd   *exec.Cmd
	watch *os.File
	done  chan struct{}
	once  sync.Once
	err   error
}

func StartManagedTmux(cfg Config, dataDir, executable string, prefix ...string) (*ManagedTmux, error) {
	if cfg.TmuxMode != TmuxManaged {
		return nil, errors.New("managed tmux requires managed mode")
	}
	if err := privateTmuxDirectory(filepath.Dir(cfg.TmuxSocket)); err != nil {
		return nil, err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	args := append(append([]string{}, prefix...), "tmux-server", "--data-dir", dataDir)
	cmd := exec.Command(executable, args...)
	cmd.Stdin = reader
	cmd.Stderr = os.Stderr
	output, err := cmd.StdoutPipe()
	if err != nil {
		reader.Close()
		writer.Close()
		return nil, err
	}
	owner := &ManagedTmux{cmd: cmd, watch: writer, done: make(chan struct{})}
	if err = cmd.Start(); err != nil {
		reader.Close()
		writer.Close()
		return nil, err
	}
	reader.Close()
	go func() { owner.err = cmd.Wait(); close(owner.done) }()
	ready := make(chan bool, 1)
	go func() {
		line := make([]byte, 6)
		_, err := io.ReadFull(output, line)
		ready <- err == nil && string(line) == "ready\n"
	}()
	select {
	case ok := <-ready:
		if ok {
			return owner, nil
		}
	case <-time.After(15 * time.Second):
	}
	_ = owner.Close()
	return nil, errors.New("could not start Shellport's managed tmux server; check the startup diagnostic")
}

func (m *ManagedTmux) Done() <-chan struct{} { return m.done }
func (m *ManagedTmux) Err() error            { <-m.done; return m.err }
func (m *ManagedTmux) Close() error {
	m.once.Do(func() { _ = m.watch.Close() })
	select {
	case <-m.done:
		return m.err
	case <-time.After(10 * time.Second):
		return errors.New("managed tmux cleanup is unconfirmed; no replacement server was started")
	}
}

// RunManagedTmuxHelper runs only with a pipe from the owning Shellport process.
// Keeping this watchdog separate means parent termination cannot orphan tmux.
func RunManagedTmuxHelper(store *Store, watch *os.File, ready io.Writer) error {
	info, err := watch.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("tmux-server is an internal helper requiring its parent's liveness pipe")
	}
	cfg, configured := managedTmuxConfiguration(store.Configuration())
	if !configured {
		return errors.New("this installation does not use managed local tmux")
	}
	if cfg.TmuxMode != TmuxManaged || !cfg.AllowLocalShell {
		return errors.New("this installation does not use managed local tmux")
	}
	if err = privateTmuxDirectory(filepath.Dir(cfg.TmuxSocket)); err != nil {
		return err
	}
	lock, err := lockFile(filepath.Join(store.Dir, "tmux-runtime.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if tmuxReady(cfg) {
		return errors.New("a server already owns the managed socket; it was not adopted or stopped")
	}
	cmd, err := localCommand(cfg, cfg.TmuxExecutable, "-D", "-f", "/dev/null", "-S", cfg.TmuxSocket)
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err = cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(done) }()
	stop := func() {
		select {
		case <-done:
			return
		default:
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	defer stop()
	parentGone := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, watch); close(parentGone) }()
	if err = waitTmux(cfg, done); err != nil {
		return err
	}
	if _, err = fmt.Fprint(ready, "ready\n"); err != nil {
		return err
	}
	select {
	case <-parentGone:
		stop()
		return nil
	case <-done:
		if waitErr == nil {
			return errors.New("managed tmux stopped while Shellport was still running")
		}
		return fmt.Errorf("managed tmux stopped: %w", waitErr)
	}
}

// LocalTmuxClient gives the CLI the same socket and fail-closed behavior as HTTP.
func LocalTmuxClient(cfg Config, args ...string) (*exec.Cmd, error) {
	executable, err := tmuxExecutable(cfg)
	if err != nil {
		return nil, err
	}
	return localTmuxCommand(cfg, executable, args...)
}
