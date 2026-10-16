package shellport

import (
	"net/http"
)

type tmuxWindowInput struct {
	Session    string `json:"session"`
	Ref        string `json:"ref"`
	Window     string `json:"window"`
	Name       string `json:"name"`
	Confirm    bool   `json:"confirm"`
	Password   string `json:"password"`
	Passphrase string `json:"passphrase"`
}

func (s *Server) authorizeTmuxTab(r *http.Request, h Host, owner string) error {
	current, exists := s.store.Host(h.ID)
	if s.auth.owner(r) != owner {
		return &tmuxError{401, "Your sign-in expired. Sign in again."}
	}
	if !exists || current.Address != h.Address || current.Port != h.Port || current.Username != h.Username || current.Auth != h.Auth || current.HostKey != h.HostKey {
		return &tmuxError{409, "Computer changed. Refresh before changing a tab."}
	}
	return nil
}

func (s *Server) renameTmuxTab(w http.ResponseWriter, r *http.Request) {
	h, ok := s.getHost(w, r)
	if !ok {
		return
	}
	var input tmuxWindowInput
	if !decode(w, r, &input) {
		return
	}
	if !validSessionName(input.Session) || len(input.Ref) != 64 || !tmuxWindowID.MatchString(input.Window) || !validNewSessionName(input.Name) {
		apiError(w, 400, "Choose a tab from the current list and use up to 64 letters, numbers, spaces, hyphens or underscores.")
		return
	}
	owner := s.auth.owner(r)
	s.tmuxMu.Lock()
	defer s.tmuxMu.Unlock()
	var renamed TmuxWindow
	err := withHostTmuxRef(r.Context(), s.store.Configuration(), h, input.Password, input.Passphrase, input.Session, input.Ref, func(run tmuxRunner) error {
		var err error
		renamed, err = renameTmuxWindow(r.Context(), run, input.Session, input.Ref, input.Window, input.Name, func() error { return s.authorizeTmuxTab(r, h, owner) })
		return err
	})
	if err != nil {
		tmuxAPIError(w, err)
		return
	}
	s.mu.Lock()
	for _, terminal := range s.terminals {
		if terminal.host.ID != h.ID || terminal.tmuxRef != input.Ref || terminal.tmuxWindow.ID != input.Window {
			continue
		}
		terminal.tmuxWindow.Name = renamed.Name
		select {
		case terminal.windowRenames <- renamed:
		default:
			select {
			case <-terminal.windowRenames:
			default:
			}
			select {
			case terminal.windowRenames <- renamed:
			default:
			}
		}
	}
	s.mu.Unlock()
	respond(w, 200, map[string]any{"window": renamed})
}

func (s *Server) closeTmuxTab(w http.ResponseWriter, r *http.Request) {
	h, ok := s.getHost(w, r)
	if !ok {
		return
	}
	var input tmuxWindowInput
	if !decode(w, r, &input) {
		return
	}
	if !input.Confirm || !validSessionName(input.Session) || len(input.Ref) != 64 || !tmuxWindowID.MatchString(input.Window) {
		apiError(w, 400, "Confirm closing a tab from the current list.")
		return
	}
	owner := s.auth.owner(r)
	s.tmuxMu.Lock()
	defer s.tmuxMu.Unlock()
	endedSessions := map[string]bool{}
	err := withHostTmuxRef(r.Context(), s.store.Configuration(), h, input.Password, input.Passphrase, input.Session, input.Ref, func(run tmuxRunner) error {
		before, err := listTmux(r.Context(), run)
		if err != nil {
			return err
		}
		if err = closeTmuxWindow(r.Context(), run, input.Session, input.Ref, input.Window, func() error { return s.authorizeTmuxTab(r, h, owner) }); err != nil {
			return err
		}
		after, err := listTmux(r.Context(), run)
		if err != nil {
			return err
		}
		for _, prior := range before {
			endedSessions[prior.Name] = true
			for _, remaining := range after {
				if remaining.Ref == prior.Ref {
					endedSessions[prior.Name] = false
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		tmuxAPIError(w, err)
		return
	}
	s.mu.Lock()
	var ended []*terminalConnection
	for id, terminal := range s.terminals {
		if terminal.host.ID == h.ID && terminal.tmuxRef == input.Ref && terminal.tmuxWindow.ID == input.Window {
			delete(s.terminals, id)
			ended = append(ended, terminal)
		}
	}
	s.mu.Unlock()
	for _, terminal := range ended {
		terminal.close()
	}
	if err = s.store.ForgetWindow(h, input.Window, endedSessions, input.Ref); err != nil {
		tmuxAPIError(w, err)
		return
	}
	updated, _ := s.store.Host(h.ID)
	respond(w, 200, map[string]any{"closed": true, "host": updated})
}
