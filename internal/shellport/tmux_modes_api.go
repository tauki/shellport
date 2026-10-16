package shellport

import (
	"net/http"
	"os"
)

type tmuxModeOption struct {
	Mode          string          `json:"mode"`
	Configured    bool            `json:"configured"`
	Ready         bool            `json:"ready"`
	Sessions      int             `json:"sessions"`
	CanEnable     bool            `json:"canEnable"`
	Reason        string          `json:"reason,omitempty"`
	OperatorSetup bool            `json:"operatorSetup,omitempty"`
	Setup         *TmuxSetupPlan  `json:"setup,omitempty"`
	Privileges    localPrivileges `json:"privileges"`
}

func (s *Server) SetTmuxRuntime(runtime *TmuxRuntime) { s.tmuxRuntime = runtime }

func (s *Server) tmuxModes(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.Configuration()
	options := []tmuxModeOption{}
	for _, mode := range []string{TmuxIndependent, TmuxManaged} {
		option := tmuxModeOption{Mode: mode, Privileges: localPrivileges{State: "unknown"}}
		for _, profile := range tmuxProfiles(cfg) {
			if primaryTmuxMode(profile) != mode {
				continue
			}
			option.Configured = true
			option.OperatorSetup = profile.TmuxMode == ""
			if cfg.AllowLocalShell {
				option.Privileges = tmuxProcessPrivileges(r.Context(), profile)
				option.Ready = tmuxReady(profile)
				sessions, err := localProfileSessions(r.Context(), profile)
				if err == nil {
					option.Sessions = len(sessions)
				} else {
					option.Reason = "Could not read this mode’s sessions. Refresh before creating work."
				}
			}
		}
		option.CanEnable = cfg.AllowLocalShell && s.tmuxRuntime != nil
		if !option.Configured && option.CanEnable {
			plan, err := s.tmuxRuntime.plan(s.store.Dir, mode, cfg.TmuxExecutable)
			if err == nil {
				err = plan.Preflight()
			}
			if err != nil {
				option.CanEnable = false
				option.Reason = err.Error()
			} else {
				option.Setup = plan
			}
		}
		options = append(options, option)
	}
	direct := localPrivileges{State: "unknown"}
	if cfg.AllowLocalShell {
		direct = processPrivileges(os.Getpid())
	}
	respond(w, 200, map[string]any{"defaultMode": defaultTmuxMode(cfg), "localAvailable": cfg.AllowLocalShell, "revision": tmuxConfigRevision(cfg), "modes": options, "directPrivileges": direct})
}

func (s *Server) setTmuxDefault(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Mode            string `json:"mode"`
		Revision        string `json:"revision"`
		Confirm         bool   `json:"confirm"`
		PrivilegePolicy string `json:"privilegePolicy"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !input.Confirm || len(input.Revision) != 64 {
		apiError(w, 400, "Confirm the default for new local sessions.")
		return
	}
	if !s.auth.recent(s.auth.owner(r)) {
		respond(w, 403, map[string]string{"error": "Sign in again before changing local session settings.", "code": "reauth_required"})
		return
	}
	if s.tmuxRuntime == nil {
		apiError(w, 409, "Restart the updated Shellport server before changing session modes.")
		return
	}
	// Serialize finite tmux operations with adding a pool. Existing terminal
	// WebSockets stay attached; neither server nor its sessions is restarted.
	s.tmuxMu.Lock()
	defer s.tmuxMu.Unlock()
	if err := r.Context().Err(); err != nil {
		return
	}
	if err := s.tmuxRuntime.setDefault(input.Mode, input.Revision, input.PrivilegePolicy); err != nil {
		tmuxAPIError(w, err)
		return
	}
	respond(w, 200, map[string]any{"defaultMode": defaultTmuxMode(s.store.Configuration()), "sessionsPreserved": true})
}
