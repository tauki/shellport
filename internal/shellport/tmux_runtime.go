package shellport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// TmuxRuntime owns only managed tmux. Independent pools retain their service
// ownership. Defaults can change without stopping either pool or any session.
type TmuxRuntime struct {
	mu      sync.Mutex
	store   *Store
	lock    *os.File
	managed *ManagedTmux
	failed  chan struct{}
	err     error
	closed  bool
	start   func(Config) (*ManagedTmux, error)
	plan    func(string, string, string) (*TmuxSetupPlan, error)
}

func NewTmuxRuntime(store *Store) (*TmuxRuntime, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return newTmuxRuntime(store, executable)
}

func newTmuxRuntime(store *Store, executable string, prefix ...string) (*TmuxRuntime, error) {
	lock, err := LockInstallation(store.Dir)
	if err != nil {
		return nil, err
	}
	// The CLI loads the store before obtaining this lock. Password recovery may
	// have finished in that interval; never start with a stale password hash.
	data, err := readPrivateState(filepath.Join(store.Dir, "config.json"))
	var current Config
	if err == nil {
		err = json.Unmarshal(data, &current)
	}
	if err != nil {
		lock.Close()
		return nil, err
	}
	if current.PasswordHash != store.Configuration().PasswordHash {
		lock.Close()
		return nil, errors.New("configuration changed while starting Shellport; restart it to use the current password")
	}
	r := &TmuxRuntime{store: store, lock: lock, failed: make(chan struct{}), plan: PlanTmuxSetup}
	r.start = func(cfg Config) (*ManagedTmux, error) { return StartManagedTmux(cfg, store.Dir, executable, prefix...) }
	if cfg, ok := managedTmuxConfiguration(store.Configuration()); ok {
		r.managed, err = r.start(cfg)
		if err != nil {
			lock.Close()
			return nil, err
		}
		r.watch(r.managed)
	}
	return r, nil
}

func (r *TmuxRuntime) watch(owner *ManagedTmux) {
	go func() {
		<-owner.Done()
		r.mu.Lock()
		defer r.mu.Unlock()
		if !r.closed && r.managed == owner {
			r.err = fmt.Errorf("managed tmux stopped: %v", owner.Err())
			close(r.failed)
		}
	}()
}
func (r *TmuxRuntime) Done() <-chan struct{} { return r.failed }
func (r *TmuxRuntime) Err() error            { r.mu.Lock(); defer r.mu.Unlock(); return r.err }
func (r *TmuxRuntime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	if r.managed != nil {
		err = r.managed.Close()
	}
	return errors.Join(err, r.lock.Close())
}

func tmuxConfigRevision(cfg Config) string {
	data, _ := json.Marshal(cfg)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (s *Store) saveTmuxConfiguration(cfg Config) error {
	if err := validateTmuxConfig(cfg); err != nil {
		return err
	}
	if err := writePrivate(filepath.Join(s.Dir, "config.json"), cfg); err != nil {
		return err
	}
	s.mu.Lock()
	s.Config = cfg
	s.mu.Unlock()
	return nil
}

func (r *TmuxRuntime) setDefault(mode, revision, privilegePolicy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.err != nil {
		return errors.New("Shellport is stopping; try again after it restarts")
	}
	r.store.configMu.Lock()
	defer r.store.configMu.Unlock()
	cfg := r.store.Configuration()
	if !cfg.AllowLocalShell {
		return &tmuxError{409, "Local terminals are disabled by the server operator."}
	}
	if revision != tmuxConfigRevision(cfg) {
		return &tmuxError{409, "Settings changed. Reload settings before saving."}
	}
	data, err := readPrivateState(filepath.Join(r.store.Dir, "config.json"))
	if err != nil {
		return err
	}
	var disk Config
	if err = json.Unmarshal(data, &disk); err != nil {
		return err
	}
	if tmuxConfigRevision(disk) != revision {
		return &tmuxError{409, "The server configuration changed outside Shellport. Restart it before saving."}
	}
	if mode != TmuxIndependent && mode != TmuxManaged {
		return &tmuxError{400, "Choose independent or managed sessions."}
	}
	next := cfg
	configured := mode == primaryTmuxMode(cfg) || cfg.TmuxAdditional != nil && cfg.TmuxAdditional.Mode == mode
	if configured && privilegePolicy != "" {
		return &tmuxError{409, "This service already exists. Its policy and sessions were preserved; review policy changes offline with the server operator."}
	}
	if !configured {
		if cfg.TmuxAdditional != nil {
			return errors.New("Both tmux profiles are already configured")
		}
		p, err := r.plan(r.store.Dir, mode, cfg.TmuxExecutable)
		if err != nil {
			return err
		}
		if err = p.SetPrivilegePolicy(privilegePolicy); err != nil {
			return &tmuxError{400, err.Error()}
		}
		if err = p.Preflight(); err != nil {
			return err
		}
		if err = privateTmuxDirectory(filepath.Dir(p.Socket)); err != nil {
			return err
		}
		candidate := p.config(cfg)
		candidate.TmuxAdditional = nil
		if p.ready(candidate) {
			return errors.New("The additional socket already has a tmux server, or the executable forces another socket. It was not adopted or stopped.")
		}
		if err = p.backup(nil); err != nil {
			return err
		}
		profile := &TmuxProfile{Mode: mode, Executable: p.Executable, Socket: p.Socket}
		next.TmuxAdditional = profile
		next.TmuxDefaultMode = mode
		if mode == TmuxManaged {
			if err = r.store.saveTmuxConfiguration(next); err != nil {
				return err
			}
			managedCfg, _ := managedTmuxConfiguration(next)
			owner, startErr := r.start(managedCfg)
			if startErr != nil {
				// A failed helper must not make an existing pool unreachable.
				return errors.Join(startErr, r.store.saveTmuxConfiguration(cfg))
			}
			r.managed = owner
			r.watch(owner)
			return nil
		}
		if _, e := os.Lstat(p.ServicePath); e == nil {
			return errors.New("An existing service file was preserved; review the additional independent setup with the server operator.")
		} else if !os.IsNotExist(e) {
			return e
		}
		if err = os.MkdirAll(filepath.Dir(p.ServicePath), 0700); err != nil {
			return err
		}
		if err = writeAtomic(p.ServicePath, p.service, 0600); err != nil {
			return err
		}
		rollback := func(failure error) error {
			if p.ready(candidate) && checkNoTmuxWork(candidate) != nil {
				return fmt.Errorf("%w; additional tmux work appeared, so its service was preserved for operator recovery", failure)
			}
			stopErr := p.serviceStop()
			if stopErr != nil {
				return errors.Join(failure, stopErr)
			}
			removeErr := os.Remove(p.ServicePath)
			if p.env.system == "linux" {
				_ = p.run("systemctl", "--user", "daemon-reload")
			}
			return errors.Join(failure, removeErr)
		}
		if err = p.serviceStart(); err != nil {
			return rollback(err)
		}
		if err = p.waitReady(candidate); err != nil {
			return rollback(err)
		}
		record := p.record()
		profile.Service = &record
		if err = r.store.saveTmuxConfiguration(next); err != nil {
			return rollback(err)
		}
		return nil
	}
	next.TmuxDefaultMode = mode
	return r.store.saveTmuxConfiguration(next)
}
