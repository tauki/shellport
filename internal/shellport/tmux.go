package shellport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

var errTmuxUnavailable = errors.New("tmux was not found for this account; install it to use saved sessions")

type TmuxSession struct {
	Name     string `json:"name"`
	Windows  int    `json:"windows"`
	Attached int    `json:"attached"`
	Ref      string `json:"ref"`
	Mode     string `json:"mode,omitempty"`
	id       string
	parent   string
	group    string
}

type tmuxChoice struct {
	Mode      string
	Name      string
	Create    bool
	Ref       string
	Window    string
	NewWindow bool
}

type tmuxError struct {
	status  int
	message string
}

func (e *tmuxError) Error() string { return e.message }

var tmuxID = regexp.MustCompile(`^\$[0-9]+$`)
var tmuxWindowID = regexp.MustCompile(`^@[0-9]+$`)
var tmuxViewName = regexp.MustCompile(`^__shellport_view_[a-f0-9]{24}$`)

func validSessionName(name string) bool {
	if name == "" || len(name) > 256 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validNewSessionName(name string) bool {
	if !validSessionName(name) || strings.HasPrefix(name, "__shellport_view_") || utf8.RuneCountInString(name) > 64 || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' ' && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// SSH exec requests are parsed by the remote account's shell. Every argument
// is quoted separately; attachment targets are validated tmux-generated IDs.
func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func tmuxCommand(args ...string) string {
	parts := []string{"exec tmux"}
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

func localCommand(cfg Config, executable string, args ...string) (*exec.Cmd, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(executable, args...)
	cmd.Dir = home
	path := os.Getenv("PATH")
	if filepath.IsAbs(cfg.TmuxExecutable) {
		path = filepath.Dir(cfg.TmuxExecutable) + string(os.PathListSeparator) + path
	}
	cmd.Env = []string{"HOME=" + home, "PATH=" + path, "TERM=xterm-256color", "LANG=C.UTF-8"}
	for _, name := range []string{"USER", "LOGNAME", "SHELL"} {
		if v := os.Getenv(name); v != "" {
			cmd.Env = append(cmd.Env, name+"="+v)
		}
	}
	return cmd, nil
}

func localTmuxCommand(cfg Config, executable string, args ...string) (*exec.Cmd, error) {
	if cfg.TmuxMode != "" {
		args = append([]string{"-N", "-S", cfg.TmuxSocket}, args...)
	}
	return localCommand(cfg, executable, args...)
}

func tmuxExecutable(cfg Config) (string, error) {
	if !cfg.AllowLocalShell {
		return "", errors.New("the operator has not enabled this-server terminals")
	}
	name := cfg.TmuxExecutable
	if name == "" {
		name = "tmux"
	}
	executable, err := exec.LookPath(name)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return "", errTmuxUnavailable
		}
		return "", fmt.Errorf("could not access tmux: %w", err)
	}
	return executable, nil
}

type boundedOutput struct {
	data     []byte
	overflow bool
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	remaining := (128 << 10) - len(b.data)
	if len(data) > remaining {
		b.data = append(b.data, data[:remaining]...)
		b.overflow = true
	} else {
		b.data = append(b.data, data...)
	}
	return len(data), nil
}

type tmuxRunner func(context.Context, ...string) ([]byte, []byte, error)

func localTmuxRunner(cfg Config, executable string) tmuxRunner {
	return func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		cmd, err := localTmuxCommand(cfg, executable, args...)
		if err != nil {
			return nil, nil, err
		}
		// Reuse the sanitized environment, but bind finite commands to cancellation.
		bounded := exec.CommandContext(ctx, executable, cmd.Args[1:]...)
		bounded.Dir, bounded.Env = cmd.Dir, cmd.Env
		var out, diagnostic boundedOutput
		bounded.Stdout, bounded.Stderr = &out, &diagnostic
		err = bounded.Run()
		if len(args) > 0 && args[0] == "list-sessions" {
			out.data = namespacedTmuxList(out.data, cfg.tmuxNamespace)
		}
		if out.overflow || diagnostic.overflow {
			err = errors.New("tmux output exceeded the session-list limit")
		}
		return out.data, diagnostic.data, err
	}
}

func remoteTmuxRunner(client *ssh.Client) tmuxRunner {
	return func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		session, err := client.NewSession()
		if err != nil {
			return nil, nil, err
		}
		defer session.Close()
		stop := context.AfterFunc(ctx, func() { _ = session.Close() })
		defer stop()
		var out, diagnostic boundedOutput
		session.Stdout, session.Stderr = &out, &diagnostic
		err = session.Run(tmuxCommand(args...))
		if out.overflow || diagnostic.overflow {
			err = errors.New("tmux output exceeded the session-list limit")
		}
		return out.data, diagnostic.data, err
	}
}

func rawTmuxSessions(ctx context.Context, run tmuxRunner) ([]TmuxSession, error) {
	output, diagnostic, err := run(ctx, "list-sessions", "-F", "#{session_id}\t#{session_windows}\t#{session_attached}\t#{session_created}:#{start_time}:#{pid}\t#{@shellport_parent}\t#{session_group}\t#{session_name}")
	if err != nil {
		// A fresh account with no tmux server has an empty directory. Missing tmux,
		// permission errors and interrupted commands must still report a failure.
		var localExit *exec.ExitError
		var remoteExit *ssh.ExitError
		exitOne := errors.As(err, &localExit) && localExit.ExitCode() == 1 || errors.As(err, &remoteExit) && remoteExit.ExitStatus() == 1
		if exitOne && (strings.Contains(string(diagnostic), "no server running") || strings.Contains(string(diagnostic), "no sessions") || strings.Contains(string(diagnostic), "error connecting to") && strings.Contains(string(diagnostic), "No such file or directory")) {
			return []TmuxSession{}, nil
		}
		detail := strings.TrimSpace(string(diagnostic))
		if len(detail) > 1024 {
			detail = detail[:1024]
		}
		if detail != "" {
			return nil, fmt.Errorf("could not list tmux sessions: %s", detail)
		}
		return nil, fmt.Errorf("could not list tmux sessions: %w", err)
	}
	sessions := []TmuxSession{}
	for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 7)
		if len(fields) != 7 || !tmuxID.MatchString(fields[0]) || !validSessionName(fields[6]) {
			return nil, errors.New("tmux returned an unsupported session name or invalid session list")
		}
		windows, werr := strconv.Atoi(fields[1])
		attached, aerr := strconv.Atoi(fields[2])
		if werr != nil || aerr != nil || windows < 1 || attached < 0 || len(sessions) >= 512 {
			return nil, errors.New("tmux session list exceeded its supported limits")
		}
		identity := sha256.Sum256([]byte(fields[0] + ":" + fields[3]))
		sessions = append(sessions, TmuxSession{Name: fields[6], Windows: windows, Attached: attached, Ref: hex.EncodeToString(identity[:]), id: fields[0], parent: fields[4], group: fields[5]})
	}
	return sessions, nil
}

func managedView(session TmuxSession) bool {
	return tmuxViewName.MatchString(session.Name) && tmuxID.MatchString(session.parent)
}

func listTmux(ctx context.Context, run tmuxRunner) ([]TmuxSession, error) {
	raw, err := rawTmuxSessions(ctx, run)
	if err != nil {
		return nil, err
	}
	sessions := []TmuxSession{}
	for _, session := range raw {
		// An orphaned view remains discoverable for recovery if its parent was
		// removed outside Shellport; never hide its only surviving windows.
		hidden := false
		if managedView(session) {
			for _, parent := range raw {
				if parent.id == session.parent && parent.group == session.group {
					hidden = true
					break
				}
			}
		}
		if hidden {
			continue
		}
		for _, view := range raw {
			if managedView(view) && view.parent == session.id && view.group == session.group {
				session.Attached += view.Attached
			}
		}
		sessions = append(sessions, session)
	}
	if len(sessions) > 256 {
		return nil, errors.New("tmux session list exceeded its supported limits")
	}
	return sessions, nil
}

func chooseTmux(ctx context.Context, run tmuxRunner, h Host, choice tmuxChoice, cols, rows int) (TmuxSession, error) {
	name := choice.Name
	if choice.Create && name == "" {
		name = randomID()[:6]
	}
	legacy := !choice.Create && name == "" && h.LastSession == ""
	if name == "" {
		name = h.LastSession
		if name == "" {
			name = "shellport-" + h.ID
		}
	}
	if !validSessionName(name) || choice.Create && !validNewSessionName(name) {
		return TmuxSession{}, &tmuxError{400, "Use a session name of up to 64 letters, numbers, spaces, hyphens or underscores."}
	}
	sessions, err := listTmux(ctx, run)
	if err != nil {
		return TmuxSession{}, err
	}
	// A stable reference identifies the same session after a rename, even if
	// another session has since reused the old name on a disconnected device.
	if !choice.Create && choice.Ref != "" {
		for _, session := range sessions {
			if session.Ref == choice.Ref {
				return session, nil
			}
		}
		return TmuxSession{}, &tmuxError{409, "The selected session changed or ended. Refresh the session list."}
	}
	for _, session := range sessions {
		if session.Name == name {
			if choice.Create {
				return TmuxSession{}, &tmuxError{409, "A session with that name already exists. Attach to it or choose another name."}
			}
			return session, nil
		}
	}
	if !choice.Create && !legacy {
		return TmuxSession{}, &tmuxError{409, "The selected session no longer exists. Choose another session or create a new one."}
	}
	if len(sessions) >= 256 {
		return TmuxSession{}, &tmuxError{409, "The session limit is reached. Attach to an existing session."}
	}
	if _, _, err = run(ctx, "new-session", "-d", "-s", name, "-x", strconv.Itoa(cols), "-y", strconv.Itoa(rows)); err != nil {
		return TmuxSession{}, errors.New("could not create the tmux session; refresh the list and check whether its name is already in use")
	}
	sessions, err = listTmux(ctx, run)
	if err != nil {
		return TmuxSession{}, err
	}
	for _, session := range sessions {
		if session.Name == name {
			return session, nil
		}
	}
	return TmuxSession{}, errors.New("the new tmux session ended before it could be attached")
}

func hostTmuxSessions(ctx context.Context, cfg Config, h Host, password, passphrase string) ([]TmuxSession, error) {
	if h.Auth == "local" {
		sessions := []TmuxSession{}
		profiles := tmuxProfiles(cfg)
		for _, p := range profiles {
			found, err := localProfileSessions(ctx, p)
			if err != nil {
				if len(profiles) > 1 && errors.Is(err, errTmuxUnavailable) {
					return nil, fmt.Errorf("could not read %s sessions: %v", primaryTmuxMode(p), err)
				}
				return nil, err
			}
			sessions = append(sessions, found...)
		}
		return sessions, nil
	}
	client, err := connectSSH(ctx, cfg, h, password, passphrase)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	if err := checkRemoteTmux(ctx, client); err != nil {
		return nil, err
	}
	return listTmux(ctx, remoteTmuxRunner(client))
}

func checkRemoteTmux(ctx context.Context, client *ssh.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("could not check tmux availability: %w", err)
	}
	defer session.Close()
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stop()
	var out, diagnostic boundedOutput
	session.Stdout, session.Stderr = &out, &diagnostic
	// SSH runs commands through the account's login shell, which may be csh or
	// fish. Delegate POSIX syntax explicitly, and keep the quoted argument on one
	// line because csh does not accept literal newlines inside single quotes.
	script := strings.Join([]string{
		`if command -v tmux >/dev/null 2>&1; then`,
		`printf 'shellport-tmux-available\n';`,
		`else IFS=:; set -f;`,
		`for directory in $PATH; do`,
		`[ -n "$directory" ] || directory=.;`,
		`if [ -d "$directory" ] && [ ! -x "$directory" ]; then`,
		`printf 'Cannot search a directory in this account\047s PATH.\n' >&2; exit 126;`,
		`fi;`,
		`if [ -e "$directory/tmux" ] || [ -L "$directory/tmux" ]; then`,
		`printf 'tmux exists but this account cannot execute it.\n' >&2; exit 126;`,
		`fi; done;`,
		`printf 'shellport-tmux-missing\n'; fi`,
	}, " ")
	err = session.Run("exec /bin/sh -c " + shellQuote(script))
	if out.overflow || diagnostic.overflow {
		return errors.New("tmux availability response exceeded its limit")
	}
	if err != nil {
		detail := strings.TrimSpace(string(diagnostic.data))
		if len(detail) > 1024 {
			detail = detail[:1024]
		}
		if detail != "" {
			return fmt.Errorf("could not check tmux availability: %s", detail)
		}
		return fmt.Errorf("could not check tmux availability: %w", err)
	}
	switch strings.TrimSpace(string(out.data)) {
	case "shellport-tmux-available":
		return nil
	case "shellport-tmux-missing":
		return errTmuxUnavailable
	default:
		return errors.New("the SSH server did not return a tmux availability result; check this account's shell and command permissions")
	}
}
