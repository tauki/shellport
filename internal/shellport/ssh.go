package shellport

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Probe struct {
	Fingerprint string `json:"fingerprint"`
	KeyType     string `json:"keyType"`
	Changed     bool   `json:"changed"`
	Previous    string `json:"previous,omitempty"`
}

func probeHost(ctx context.Context, h Host) (Probe, ssh.PublicKey, error) {
	address := net.JoinHostPort(h.Address, strconv.Itoa(h.Port))
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return Probe{}, nil, errors.New("could not reach this computer; check the address, SSH service and private network")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var key ssh.PublicKey
	cfg := &ssh.ClientConfig{User: h.Username, HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
		key = k
		return errors.New("identity probe complete")
	}}
	_, _, _, _ = ssh.NewClientConn(conn, address, cfg)
	if key == nil {
		return Probe{}, nil, errors.New("SSH did not present a server identity; check the SSH port")
	}
	fp := ssh.FingerprintSHA256(key)
	return Probe{Fingerprint: fp, KeyType: key.Type(), Changed: h.Fingerprint != "" && h.Fingerprint != fp, Previous: h.Fingerprint}, key, nil
}

func connectSSH(ctx context.Context, cfg Config, h Host, password, passphrase string) (*ssh.Client, error) {
	if h.HostKey == "" {
		return nil, errors.New("verify this computer's SSH fingerprint before connecting")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(h.HostKey)
	if err != nil {
		return nil, errors.New("saved server identity is invalid; verify it again")
	}
	key, err := ssh.ParsePublicKey(keyBytes)
	if err != nil {
		return nil, errors.New("saved server identity is invalid; verify it again")
	}
	var methods []ssh.AuthMethod
	var agentConn net.Conn
	switch h.Auth {
	case "password":
		if password == "" {
			return nil, errors.New("enter the SSH password for this connection")
		}
		methods = append(methods, ssh.Password(password))
	case "agent":
		if cfg.AgentSocket == "" {
			return nil, errors.New("the server operator has not configured an SSH agent")
		}
		agentConn, err = net.DialTimeout("unix", cfg.AgentSocket, 3*time.Second)
		if err != nil {
			return nil, errors.New("SSH agent is unavailable")
		}
		defer agentConn.Close()
		methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(agentConn).Signers))
	case "key":
		data, e := readPrivateState(cfg.KeyFile)
		if e != nil {
			return nil, errors.New("the server SSH key must be a regular private file owned by the service account (chmod 600)")
		}
		var signer ssh.Signer
		if passphrase != "" {
			signer, e = ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
		} else {
			signer, e = ssh.ParsePrivateKey(data)
		}
		if e != nil {
			return nil, errors.New("SSH key could not be unlocked; enter its passphrase if encrypted")
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	sshCfg := &ssh.ClientConfig{User: h.Username, Auth: methods, Timeout: 15 * time.Second, HostKeyCallback: ssh.FixedHostKey(key)}
	address := net.JoinHostPort(h.Address, strconv.Itoa(h.Port))
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, errors.New("could not reach this computer; check your network and the SSH service")
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	c, channels, requests, err := ssh.NewClientConn(conn, address, sshCfg)
	if err != nil {
		_ = conn.Close()
		return nil, errors.New("SSH connection refused: check the saved server identity, username, credentials and the computer's SSH authentication policy")
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, channels, requests), nil
}

type terminalConnection struct {
	id, owner     string
	host          Host
	client        *ssh.Client
	ssh           *ssh.Session
	in            io.WriteCloser
	out           io.ReadCloser
	writer        *io.PipeWriter
	attached      bool
	ctx           context.Context
	cancel        context.CancelFunc
	once          sync.Once
	process       *exec.Cmd
	localPTY      *os.File
	processWaited atomic.Bool
	tmuxSession   string
	tmuxRef       string
	tmuxWindow    TmuxWindow
	tmuxCleanup   func()
	renames       chan string
	windowRenames chan TmuxWindow
}

func openTerminal(ctx context.Context, cfg Config, h Host, password, passphrase string, cols, rows int, choice tmuxChoice) (*terminalConnection, error) {
	if h.Auth == "local" {
		return openLocalTerminal(ctx, cfg, h, cols, rows, choice)
	}
	client, err := connectSSH(ctx, cfg, h, password, passphrase)
	if err != nil {
		return nil, err
	}
	var selected TmuxSession
	var window TmuxWindow
	var view string
	var viewCleanup func()
	if h.Tmux {
		run := remoteTmuxRunner(client)
		selected, err = chooseTmux(ctx, run, h, choice, cols, rows)
		if err == nil {
			window, err = chooseTmuxWindow(ctx, run, h, selected, choice)
		}
		if err == nil {
			view, viewCleanup, err = createTmuxView(ctx, run, selected, window)
		}
		if err != nil {
			client.Close()
			return nil, err
		}
	}
	opened := false
	defer func() {
		if !opened && viewCleanup != nil {
			viewCleanup()
		}
	}()
	sess, err := client.NewSession()
	if err != nil {
		if viewCleanup != nil {
			viewCleanup()
		}
		client.Close()
		return nil, errors.New("this SSH server did not allow a terminal session")
	}
	cleanup := func() {
		if viewCleanup != nil {
			viewCleanup()
		}
		sess.Close()
		client.Close()
	}
	if err = sess.RequestPty("xterm-256color", rows, cols, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}); err != nil {
		cleanup()
		return nil, errors.New("this SSH server did not allow an interactive terminal")
	}
	in, err := sess.StdinPipe()
	if err != nil {
		cleanup()
		return nil, err
	}
	out, writer := io.Pipe()
	sess.Stdout = writer
	sess.Stderr = writer
	if h.Tmux {
		err = sess.Start(tmuxCommand(tmuxViewAttach(view)...))
	} else {
		err = sess.Shell()
	}
	if err != nil {
		writer.Close()
		out.Close()
		cleanup()
		return nil, fmt.Errorf("remote shell could not start: %w", err)
	}
	life, cancel := context.WithCancel(context.Background())
	opened = true
	return &terminalConnection{id: randomID(), host: h, client: client, ssh: sess, in: in, out: out, writer: writer, ctx: life, cancel: cancel, tmuxSession: selected.Name, tmuxRef: selected.Ref, tmuxWindow: window, tmuxCleanup: viewCleanup}, nil
}

func (t *terminalConnection) close() {
	t.once.Do(func() {
		t.cancel()
		if t.tmuxCleanup != nil {
			t.tmuxCleanup()
		}
		if t.client != nil {
			t.client.Close()
		}
		if t.ssh != nil {
			t.ssh.Close()
		}
		if t.process != nil && t.process.Process != nil && !t.processWaited.Load() {
			_ = syscall.Kill(-t.process.Process.Pid, syscall.SIGHUP)
		}
		t.in.Close()
		if t.writer != nil {
			t.writer.Close()
		}
		t.out.Close()
	})
}

func openLocalTerminal(ctx context.Context, cfg Config, h Host, cols, rows int, choice tmuxChoice) (*terminalConnection, error) {
	if !cfg.AllowLocalShell {
		return nil, errors.New("the operator has not enabled this-server terminals")
	}
	var cmd *exec.Cmd
	var selected TmuxSession
	var window TmuxWindow
	var viewCleanup func()
	var err error
	if h.Tmux {
		cfg, err = profileForSession(ctx, cfg, choice.Name, choice.Ref, choice.Mode, choice.Create)
		if err != nil {
			return nil, err
		}
		executable, err := tmuxExecutable(cfg)
		if err != nil {
			return nil, err
		}
		run := localTmuxRunner(cfg, executable)
		selected, err = chooseTmux(ctx, run, h, choice, cols, rows)
		if err != nil {
			return nil, err
		}
		window, err = chooseTmuxWindow(ctx, run, h, selected, choice)
		if err != nil {
			return nil, err
		}
		var view string
		view, viewCleanup, err = createTmuxView(ctx, run, selected, window)
		if err != nil {
			return nil, err
		}
		cmd, err = localTmuxCommand(cfg, executable, tmuxViewAttach(view)...)
	} else {
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		cmd, err = localCommand(cfg, shell, "-l")
	}
	if err != nil {
		if viewCleanup != nil {
			viewCleanup()
		}
		return nil, err
	}
	file, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		if viewCleanup != nil {
			viewCleanup()
		}
		return nil, errors.New("could not start this server's shell")
	}
	life, cancel := context.WithCancel(context.Background())
	return &terminalConnection{id: randomID(), host: h, in: file, out: file, localPTY: file, process: cmd, ctx: life, cancel: cancel, tmuxSession: selected.Name, tmuxRef: selected.Ref, tmuxWindow: window, tmuxCleanup: viewCleanup}, nil
}
func (t *terminalConnection) resize(cols, rows int) error {
	if t.localPTY != nil {
		return pty.Setsize(t.localPTY, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	}
	return t.ssh.WindowChange(rows, cols)
}
func (t *terminalConnection) wait() error {
	if t.process != nil {
		err := t.process.Wait()
		t.processWaited.Store(true)
		return err
	}
	return t.ssh.Wait()
}

func validSize(cols, rows int) bool { return cols >= 2 && cols <= 500 && rows >= 2 && rows <= 300 }
