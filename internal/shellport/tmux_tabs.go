package shellport

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

type TmuxWindow struct {
	ID     string `json:"id"`
	Index  int    `json:"index"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

func listTmuxWindows(ctx context.Context, run tmuxRunner, session TmuxSession) ([]TmuxWindow, error) {
	output, _, err := run(ctx, "list-windows", "-t", session.id, "-F", "#{window_id}\t#{window_index}\t#{window_active}\t#{window_name}")
	if err != nil {
		return nil, &tmuxError{409, "The selected session no longer exists. Refresh the session list."}
	}
	windows := []TmuxWindow{}
	for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		fields := strings.SplitN(line, "\t", 4)
		if len(fields) != 4 || !tmuxWindowID.MatchString(fields[0]) || !validSessionName(fields[3]) {
			return nil, errors.New("tmux returned an unsupported tab list")
		}
		index, err := strconv.Atoi(fields[1])
		if err != nil || index < 0 || (fields[2] != "0" && fields[2] != "1") || len(windows) >= 256 {
			return nil, errors.New("tmux tab list exceeded its supported limits")
		}
		windows = append(windows, TmuxWindow{ID: fields[0], Index: index, Name: fields[3], Active: fields[2] == "1"})
	}
	return windows, nil
}

func chooseTmuxWindow(ctx context.Context, run tmuxRunner, h Host, session TmuxSession, choice tmuxChoice) (TmuxWindow, error) {
	windows, err := listTmuxWindows(ctx, run, session)
	if err != nil {
		return TmuxWindow{}, err
	}
	if choice.NewWindow {
		if len(windows) >= 256 {
			return TmuxWindow{}, &tmuxError{409, "The tab limit is reached. Open an existing tab."}
		}
		out, _, err := run(ctx, "new-window", "-d", "-t", session.id+":", "-P", "-F", "#{window_id}")
		if err != nil {
			return TmuxWindow{}, errors.New("could not create a tab; refresh the tab list before trying again")
		}
		choice.Window = strings.TrimSpace(string(out))
		if !tmuxWindowID.MatchString(choice.Window) {
			return TmuxWindow{}, errors.New("tmux returned an invalid new tab identity")
		}
		windows, err = listTmuxWindows(ctx, run, session)
		if err != nil {
			return TmuxWindow{}, err
		}
	}
	if choice.Window == "" && h.LastSession == session.Name {
		for _, window := range windows {
			if window.ID == h.LastWindow {
				return window, nil
			}
		}
	}
	for _, window := range windows {
		if window.ID == choice.Window || choice.Window == "" && window.Active {
			return window, nil
		}
	}
	if choice.Window == "" && len(windows) > 0 {
		return windows[0], nil
	}
	return TmuxWindow{}, &tmuxError{409, "The selected tab no longer exists. Choose another tab or create a new one."}
}

// Grouped sessions share the persistent windows but keep each client's selected
// window independent. The short-lived view is destroyed after its client detaches.
func createTmuxView(ctx context.Context, run tmuxRunner, session TmuxSession, window TmuxWindow) (string, func(), error) {
	name := "__shellport_view_" + randomID()[:24]
	cleanup := func() { _, _, _ = run(context.Background(), "kill-session", "-t", "="+name) }
	args := []string{"new-session", "-d", "-t", session.id, "-s", name,
		";", "set-option", "-t", name, "@shellport_parent", session.id,
		";", "set-option", "-t", name, "destroy-unattached", "off",
		";", "set-option", "-t", name, "detach-on-destroy", "on",
		";", "set-option", "-t", name, "status-left", "[#{session_group}] ",
		";", "select-window", "-t", name + ":" + window.ID}
	if _, _, err := run(ctx, args...); err != nil {
		cleanup()
		return "", nil, errors.New("could not open the selected tab; its shell remains on the computer")
	}
	raw, err := rawTmuxSessions(ctx, run)
	var parent, view *TmuxSession
	for i := range raw {
		if raw[i].id == session.id && raw[i].Ref == session.Ref {
			parent = &raw[i]
		}
		if raw[i].Name == name {
			view = &raw[i]
		}
	}
	if err != nil || parent == nil || view == nil || parent.group != view.group {
		cleanup()
		return "", nil, &tmuxError{409, "The selected session changed. Refresh the session list."}
	}
	return name, cleanup, nil
}

func tmuxViewAttach(name string) []string {
	return []string{"attach-session", "-t", "=" + name, ";", "set-option", "-t", name, "destroy-unattached", "on"}
}

func withHostTmux(ctx context.Context, cfg Config, h Host, password, passphrase string, fn func(tmuxRunner) error) error {
	if h.Auth == "local" {
		executable, err := tmuxExecutable(cfg)
		if err != nil {
			return err
		}
		return fn(localTmuxRunner(cfg, executable))
	}
	client, err := connectSSH(ctx, cfg, h, password, passphrase)
	if err != nil {
		return err
	}
	defer client.Close()
	return fn(remoteTmuxRunner(client))
}

func selectedTmux(ctx context.Context, run tmuxRunner, name, ref string) (TmuxSession, error) {
	sessions, err := listTmux(ctx, run)
	if err != nil {
		return TmuxSession{}, err
	}
	for _, session := range sessions {
		if session.Name == name && session.Ref == ref {
			return session, nil
		}
	}
	return TmuxSession{}, &tmuxError{409, "The selected session changed or ended. Refresh the session list."}
}

func selectedTmuxWindow(ctx context.Context, run tmuxRunner, name, ref, id string) (TmuxSession, TmuxWindow, error) {
	session, err := selectedTmux(ctx, run, name, ref)
	if err != nil {
		return TmuxSession{}, TmuxWindow{}, err
	}
	windows, err := listTmuxWindows(ctx, run, session)
	if err != nil {
		return TmuxSession{}, TmuxWindow{}, err
	}
	for _, window := range windows {
		if window.ID == id {
			return session, window, nil
		}
	}
	return TmuxSession{}, TmuxWindow{}, &tmuxError{409, "The selected tab no longer exists. Refresh the tab list."}
}

func renameTmuxWindow(ctx context.Context, run tmuxRunner, name, ref, id, newName string, authorize func() error) (TmuxWindow, error) {
	if !validNewSessionName(newName) {
		return TmuxWindow{}, &tmuxError{400, "Use up to 64 letters, numbers, spaces, hyphens or underscores."}
	}
	session, window, err := selectedTmuxWindow(ctx, run, name, ref, id)
	if err != nil {
		return TmuxWindow{}, err
	}
	if err = authorize(); err != nil {
		return TmuxWindow{}, err
	}
	// tmux also disables automatic renaming for this window, so running another
	// command does not replace the owner's chosen name.
	if _, _, err = run(ctx, "rename-window", "-t", session.id+":"+window.ID, "--", newName); err != nil {
		return TmuxWindow{}, errors.New("could not rename the tab; refresh the list before trying again")
	}
	window.Name = newName
	return window, nil
}

func closeTmuxWindow(ctx context.Context, run tmuxRunner, name, ref, id string, authorize func() error) error {
	session, window, err := selectedTmuxWindow(ctx, run, name, ref, id)
	if err != nil {
		return err
	}
	raw, err := rawTmuxSessions(ctx, run)
	if err != nil {
		return err
	}
	for _, other := range raw {
		if other.id != session.id && session.group != "" && other.group == session.group && !managedView(other) {
			return &tmuxError{409, "This session shares its tabs with another tmux session. Ungroup it in tmux before closing a tab."}
		}
	}
	if err = authorize(); err != nil {
		return err
	}
	// A grouped client would otherwise silently switch to another shell when its
	// window is killed. End views showing this window before ending its shell.
	for _, view := range raw {
		if !managedView(view) || view.parent != session.id || view.group != session.group {
			continue
		}
		out, _, err := run(ctx, "display-message", "-p", "-t", view.id, "#{window_id}")
		if err != nil {
			return errors.New("a terminal changed while closing the tab; refresh before trying again")
		}
		if strings.TrimSpace(string(out)) == window.ID {
			if _, _, err = run(ctx, "kill-session", "-t", view.id); err != nil {
				return errors.New("could not disconnect a tab terminal; refresh before trying again")
			}
		}
	}
	// Remove this session's link. The shell is destroyed only when no other
	// session owns the window; explicitly linked work elsewhere survives.
	if _, _, err = run(ctx, "unlink-window", "-k", "-t", session.id+":"+window.ID); err != nil {
		return errors.New("could not close the tab on the computer; refresh the list before trying again")
	}
	return nil
}

func renameTmuxSession(ctx context.Context, run tmuxRunner, name, ref, newName string, authorize func() error) (TmuxSession, error) {
	if !validNewSessionName(newName) {
		return TmuxSession{}, &tmuxError{400, "Use up to 64 letters, numbers, spaces, hyphens or underscores."}
	}
	session, err := selectedTmux(ctx, run, name, ref)
	if err != nil {
		return TmuxSession{}, err
	}
	sessions, err := listTmux(ctx, run)
	if err != nil {
		return TmuxSession{}, err
	}
	for _, existing := range sessions {
		if existing.Name == newName && existing.Ref != ref {
			return TmuxSession{}, &tmuxError{409, "A session with that name already exists. Choose another name."}
		}
	}
	if err = authorize(); err != nil {
		return TmuxSession{}, err
	}
	if session.Name != newName {
		if _, _, err = run(ctx, "rename-session", "-t", session.id, "--", newName); err != nil {
			return TmuxSession{}, errors.New("could not rename the session; refresh the list and check whether the name is already in use")
		}
	}
	session.Name = newName
	return session, nil
}

func deleteTmuxSession(ctx context.Context, run tmuxRunner, name, ref string, authorize func() error) error {
	session, err := selectedTmux(ctx, run, name, ref)
	if err != nil {
		return err
	}
	raw, err := rawTmuxSessions(ctx, run)
	if err != nil {
		return err
	}
	if err := authorize(); err != nil {
		return err
	}
	// Remove only Shellport's views of this parent. Other tmux sessions, including
	// externally grouped sessions, retain their normal tmux ownership semantics.
	for _, view := range raw {
		if managedView(view) && view.parent == session.id && view.group == session.group {
			if _, _, err := run(ctx, "kill-session", "-t", view.id); err != nil {
				return errors.New("could not disconnect a session tab; refresh before deleting again")
			}
		}
	}
	if _, _, err := run(ctx, "kill-session", "-t", session.id); err != nil {
		return errors.New("could not delete the session on the computer; refresh before trying again")
	}
	return nil
}
