package shellport

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// This reports one observed process flag, not whether sudo is installed,
// authorized, or usable under every OS policy. It never attempts elevation.
type localPrivileges struct {
	State string `json:"state"`
}

func processPrivileges(pid int) localPrivileges {
	unknown := localPrivileges{State: "unknown"}
	if runtime.GOOS != "linux" || pid <= 0 {
		return unknown
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return unknown
	}
	return parseProcessPrivileges(string(data), pid, os.Geteuid())
}

func parseProcessPrivileges(status string, pid, uid int) localPrivileges {
	fields := map[string][]string{}
	for _, line := range strings.Split(status, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || key != "Pid" && key != "Uid" && key != "NoNewPrivs" {
			continue
		}
		if _, duplicate := fields[key]; duplicate {
			return localPrivileges{State: "unknown"}
		}
		fields[key] = strings.Fields(value)
	}
	if len(fields["Pid"]) != 1 || fields["Pid"][0] != strconv.Itoa(pid) || len(fields["Uid"]) != 4 || fields["Uid"][1] != strconv.Itoa(uid) || len(fields["NoNewPrivs"]) != 1 {
		return localPrivileges{State: "unknown"}
	}
	switch fields["NoNewPrivs"][0] {
	case "1":
		return localPrivileges{State: "blocked"}
	case "0":
		return localPrivileges{State: "not-blocked"}
	default:
		return localPrivileges{State: "unknown"}
	}
}

func tmuxProcessPrivileges(ctx context.Context, cfg Config) localPrivileges {
	unknown := localPrivileges{State: "unknown"}
	if runtime.GOOS != "linux" {
		return unknown
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	executable, err := tmuxExecutable(cfg)
	if err != nil {
		return unknown
	}
	return tmuxRunnerPrivileges(ctx, localTmuxRunner(cfg, executable), processPrivileges)
}

func tmuxRunnerPrivileges(ctx context.Context, run tmuxRunner, read func(int) localPrivileges) localPrivileges {
	unknown := localPrivileges{State: "unknown"}
	// -N is needed even for operator-selected legacy wrappers/default sockets:
	// reading Settings must never start a missing tmux server.
	query := func() (int, error) {
		out, _, err := run(ctx, "-N", "display-message", "-p", "#{pid}")
		if err != nil {
			return 0, err
		}
		return strconv.Atoi(strings.TrimSpace(string(out)))
	}
	pid, err := query()
	if err != nil || pid <= 0 {
		return unknown
	}
	observed := read(pid)
	// Reconfirm the socket's server after reading /proc, rather than reporting
	// a stale PID after a server exits or is replaced during this check.
	if current, err := query(); err != nil || current != pid {
		return unknown
	}
	return observed
}
