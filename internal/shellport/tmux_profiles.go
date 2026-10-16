package shellport

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

// Each pool has a stable socket and lifetime. Changing the default only changes
// where new sessions are created; existing sessions never move between servers.
type TmuxProfile struct {
	Mode       string           `json:"mode"`
	Executable string           `json:"executable"`
	Socket     string           `json:"socket"`
	Service    *tmuxSetupRecord `json:"service,omitempty"`
}

func primaryTmuxMode(cfg Config) string {
	if cfg.TmuxMode == TmuxManaged {
		return TmuxManaged
	}
	return TmuxIndependent
}

func defaultTmuxMode(cfg Config) string {
	if cfg.TmuxDefaultMode != "" {
		return cfg.TmuxDefaultMode
	}
	return primaryTmuxMode(cfg)
}

func tmuxProfiles(cfg Config) []Config {
	profiles := []Config{cfg}
	if p := cfg.TmuxAdditional; p != nil {
		other := cfg
		other.TmuxMode, other.TmuxExecutable, other.TmuxSocket = p.Mode, p.Executable, p.Socket
		other.tmuxNamespace = p.Mode + ":" + p.Socket
		other.TmuxAdditional = nil
		profiles = append(profiles, other)
	}
	return profiles
}

func managedTmuxConfiguration(cfg Config) (Config, bool) {
	for _, p := range tmuxProfiles(cfg) {
		if p.TmuxMode == TmuxManaged {
			return p, cfg.AllowLocalShell
		}
	}
	return Config{}, false
}

func LocalTmuxClientForMode(cfg Config, mode string, args ...string) (*exec.Cmd, error) {
	if mode == "" {
		return LocalTmuxClient(cfg, args...)
	}
	for _, profile := range tmuxProfiles(cfg) {
		if primaryTmuxMode(profile) == mode {
			return LocalTmuxClient(profile, args...)
		}
	}
	return nil, errors.New("this tmux mode is not configured; enable it in Workspace settings")
}

func validateTmuxProfiles(cfg Config) error {
	if cfg.TmuxDefaultMode != "" && cfg.TmuxDefaultMode != TmuxIndependent && cfg.TmuxDefaultMode != TmuxManaged {
		return errors.New("tmuxDefaultMode must be independent or managed")
	}
	if p := cfg.TmuxAdditional; p != nil {
		if p.Mode == primaryTmuxMode(cfg) || p.Mode != TmuxIndependent && p.Mode != TmuxManaged || !filepath.IsAbs(p.Executable) || !filepath.IsAbs(p.Socket) || len(p.Socket) > 100 || p.Socket == cfg.TmuxSocket {
			return errors.New("invalid additional tmux profile")
		}
	}
	if cfg.TmuxDefaultMode != "" && cfg.TmuxDefaultMode != primaryTmuxMode(cfg) && (cfg.TmuxAdditional == nil || cfg.TmuxAdditional.Mode != cfg.TmuxDefaultMode) {
		return errors.New("default tmux mode is not configured")
	}
	return nil
}

func localProfileSessions(ctx context.Context, cfg Config) ([]TmuxSession, error) {
	executable, err := tmuxExecutable(cfg)
	if err != nil {
		return nil, err
	}
	sessions, err := listTmux(ctx, localTmuxRunner(cfg, executable))
	for i := range sessions {
		sessions[i].Mode = primaryTmuxMode(cfg)
	}
	return sessions, err
}

func profileForSession(ctx context.Context, cfg Config, name, ref, createMode string, create bool) (Config, error) {
	profiles := tmuxProfiles(cfg)
	if create {
		if createMode == "" {
			createMode = defaultTmuxMode(cfg)
		}
		for _, p := range profiles {
			if primaryTmuxMode(p) == createMode {
				return p, nil
			}
		}
		return Config{}, &tmuxError{409, "Enable this mode in Workspace settings before creating its sessions."}
	}
	if ref == "" && name == "" {
		return cfg, nil
	} // Preserve old API clients' primary-server behavior.
	var found *Config
	var failures []error
	for _, p := range profiles {
		sessions, err := localProfileSessions(ctx, p)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for _, session := range sessions {
			if ref != "" && session.Ref == ref || ref == "" && session.Name == name {
				if found != nil {
					return Config{}, &tmuxError{409, "Choose the session from the picker so its mode is unambiguous."}
				}
				copy := p
				found = &copy
			}
		}
	}
	if found != nil {
		return *found, nil
	}
	if len(failures) > 0 {
		return Config{}, errors.Join(failures...)
	}
	return Config{}, &tmuxError{409, "The selected session ended. Choose another saved session."}
}

func withHostTmuxRef(ctx context.Context, cfg Config, h Host, password, passphrase, name, ref string, fn func(tmuxRunner) error) error {
	if h.Auth == "local" {
		var err error
		cfg, err = profileForSession(ctx, cfg, name, ref, "", false)
		if err != nil {
			return err
		}
	}
	return withHostTmux(ctx, cfg, h, password, passphrase, fn)
}

// Secondary-server session IDs and creation timestamps can equal those on the
// primary server. Namespace only the extra pool, preserving all incumbent refs.
func namespacedTmuxList(data []byte, namespace string) []byte {
	if namespace == "" {
		return data
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		fields := strings.SplitN(line, "\t", 7)
		if len(fields) == 7 {
			fields[3] += "/" + namespace
			lines[i] = strings.Join(fields, "\t")
		}
	}
	return []byte(strings.Join(lines, "\n"))
}
