package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"shellport/internal/shellport"
	"shellport/internal/web"
)

type origins []string

func (o *origins) String() string     { return strings.Join(*o, ",") }
func (o *origins) Set(v string) error { *o = append(*o, strings.TrimSuffix(v, "/")); return nil }
func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "shellport:", err)
		os.Exit(1)
	}
}

func main() { fail(run(os.Args[1:])) }

func run(args []string) error {
	command := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}
	if command == "version" {
		return runVersion(args)
	}
	if command == "serve" && len(args) > 0 && args[0] == "--version" {
		return runVersion(args[1:])
	}
	if command == "reset-password" {
		return runPasswordReset(args)
	}
	if command == "setup-proxy" {
		return runProxySetup(args)
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	dir := flags.String("data-dir", ".data", "private persistent data directory, outside release packages")
	passwordFile := flags.String("password-file", "", "init only: private app-password file; omitted for an interactive prompt")
	keyFile := flags.String("key-file", "", "init only: existing SSH key; omitted to create a dedicated key")
	var allowed origins
	flags.Var(&allowed, "origin", "init only: exact browser origin; repeat for local and private HTTPS URLs")
	var trustedProxies proxyAddresses
	flags.Var(&trustedProxies, "trusted-proxy", "init only: trusted reverse-proxy source IP or CIDR; repeat for multiple addresses")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8088"
	}
	listen := flags.String("listen", "127.0.0.1:"+port, "loopback listening address; defaults to the PORT environment variable or 8088")
	name := flags.String("name", "", "add-host only: computer name")
	address := flags.String("address", "", "add-host only: hostname/IP")
	user := flags.String("user", "", "add-host only: SSH username")
	sshPort := flags.Int("ssh-port", 22, "add-host only: SSH port")
	method := flags.String("auth", "key", "add-host only: key, password, agent or local")
	tmux := flags.Bool("tmux", true, "add-host only: attach/create a persistent remote tmux session")
	localShell := flags.Bool("local-shell", false, "init only: explicitly enable terminals on the Shellport server under its OS user")
	tmuxExecutable := flags.String("tmux-bin", "", "init/setup-tmux: operator-selected tmux executable for this-server sessions")
	tmuxMode := flags.String("tmux-mode", shellport.TmuxIndependent, "init/setup-tmux: initial lifetime; tmux: choose independent or managed pool")
	tmuxPrivileges := flags.String("tmux-privileges", "", "init/setup-tmux: Linux independent service policy, account or restricted; omitted to preserve an owned policy, or use account for a new service")
	dryRun := flags.Bool("dry-run", false, "init/setup-tmux: show the local tmux setup without changing files or services")
	yes := flags.Bool("yes", false, "init/setup-tmux: apply the displayed local tmux setup without prompting")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Shellport — your shell, anywhere.\n\nCommands: init, serve, setup-proxy, setup-tmux, tmux, add-host, public-key, reset-password, version\n\nLocal tmux defaults to independent service ownership. Managed mode ends its local shells when Shellport stops. Existing configurations retain their operator setup until setup-tmux is explicitly run.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 && command != "tmux" {
		return fmt.Errorf("unexpected positional arguments")
	}
	if command != "init" && len(trustedProxies) > 0 {
		return fmt.Errorf("--trusted-proxy is for init; use setup-proxy to update an existing installation")
	}
	explicitMode := false
	explicitPrivileges := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "tmux-mode" {
			explicitMode = true
		}
		if f.Name == "tmux-privileges" {
			explicitPrivileges = true
		}
	})
	if explicitPrivileges && (command != "init" && command != "setup-tmux" || command == "init" && !*localShell) {
		return fmt.Errorf("--tmux-privileges requires init --local-shell or setup-tmux")
	}
	if explicitPrivileges && *tmuxPrivileges == "" {
		return fmt.Errorf("choose --tmux-privileges account or restricted")
	}
	if command == "init" && explicitMode && !*localShell {
		return fmt.Errorf("--tmux-mode requires --local-shell when initializing")
	}
	if command == "init" {
		var plan *shellport.TmuxSetupPlan
		if *localShell {
			var err error
			plan, err = shellport.PlanTmuxSetup(*dir, *tmuxMode, *tmuxExecutable)
			if err != nil {
				return err
			}
			if err = plan.SetPrivilegePolicy(*tmuxPrivileges); err != nil {
				return err
			}
			if err = reviewTmuxPlan(plan, *dryRun, *yes); err != nil {
				return err
			}
			if *dryRun {
				return nil
			}
			if err = plan.Preflight(); err != nil {
				return err
			}
		} else if *dryRun {
			return fmt.Errorf("init --dry-run requires --local-shell")
		}
		var password string
		if *passwordFile != "" {
			st, err := os.Stat(*passwordFile)
			if err != nil {
				return err
			}
			if st.Mode().Perm()&0077 != 0 {
				return fmt.Errorf("password file must have mode 600")
			}
			data, err := os.ReadFile(*passwordFile)
			if err != nil {
				return err
			}
			password = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		} else {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return fmt.Errorf("use --password-file for unattended initialization")
			}
			fmt.Fprint(os.Stderr, "Choose an app password (12–72 bytes): ")
			data, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return err
			}
			fmt.Fprint(os.Stderr, "Confirm password: ")
			confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return err
			}
			if string(data) != string(confirm) {
				return fmt.Errorf("passwords did not match")
			}
			password = string(data)
		}
		if len(allowed) == 0 {
			allowed = []string{"http://127.0.0.1:8088", "http://shellport.localhost"}
		}
		if err := shellport.Initialize(*dir, password, allowed, *keyFile, trustedProxies...); err != nil {
			return err
		}
		if plan != nil {
			initialized, err := shellport.OpenStore(*dir)
			if err != nil {
				return err
			}
			fresh, err := shellport.PlanTmuxSetup(*dir, *tmuxMode, *tmuxExecutable)
			if err != nil {
				return err
			}
			if err = fresh.SetPrivilegePolicy(*tmuxPrivileges); err != nil {
				return err
			}
			before, _ := json.Marshal(plan)
			after, _ := json.Marshal(fresh)
			if !bytes.Equal(before, after) {
				return fmt.Errorf("setup changed after initialization; credentials were preserved, review setup-tmux before continuing")
			}
			if err = fresh.Apply(initialized); err != nil {
				return fmt.Errorf("credentials initialized and preserved, but local tmux setup failed; stop Shellport and retry setup-tmux: %w", err)
			}
		} else if *tmuxExecutable != "" {
			initialized, err := shellport.OpenStore(*dir)
			if err != nil {
				return err
			}
			cfg := initialized.Config
			cfg.AllowLocalShell = *localShell
			cfg.TmuxExecutable = *tmuxExecutable
			data, err := json.MarshalIndent(cfg, "", "  ")
			if err != nil {
				return err
			}
			if err = os.WriteFile(filepath.Join(initialized.Dir, "config.json"), append(data, '\n'), 0600); err != nil {
				return err
			}
		}
		fmt.Println("Shellport initialized. Your app password was not printed or saved in plaintext.")
		fmt.Println("Run public-key to view the SSH key to authorize on your computers.")
		return nil
	}
	store, err := shellport.OpenStore(*dir)
	if err != nil {
		return err
	}
	switch command {
	case "setup-tmux":
		plan, err := shellport.PlanTmuxSetup(*dir, *tmuxMode, *tmuxExecutable)
		if err != nil {
			return err
		}
		if err = plan.SetPrivilegePolicy(*tmuxPrivileges); err != nil {
			return err
		}
		if err = reviewTmuxPlan(plan, *dryRun, *yes); err != nil {
			return err
		}
		if *dryRun {
			return nil
		}
		if err = plan.Apply(store); err != nil {
			return err
		}
		fmt.Println("Local tmux configured. Start Shellport to use it.")
	case "tmux":
		mode := ""
		if explicitMode {
			mode = *tmuxMode
		}
		cmd, err := shellport.LocalTmuxClientForMode(store.Configuration(), mode, flags.Args()...)
		if err != nil {
			return err
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	case "tmux-server":
		return shellport.RunManagedTmuxHelper(store, os.Stdin, os.Stdout)
	case "add-host":
		h, err := store.SaveHost(shellport.Host{Name: *name, Address: *address, Port: *sshPort, Username: *user, Auth: *method, Tmux: *tmux})
		if err != nil {
			return err
		}
		fmt.Println("Computer saved:", h.Name, "— verify its SSH identity in Shellport before connecting.")
	case "public-key":
		pub, err := os.ReadFile(store.Config.KeyFile + ".pub")
		if err != nil {
			return err
		}
		fmt.Print(string(pub))
	case "serve":
		return serve(store, *listen)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	return nil
}

func reviewTmuxPlan(plan *shellport.TmuxSetupPlan, dryRun, yes bool) error {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	if dryRun || yes {
		return nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("review --dry-run first, then use --yes for unattended local tmux setup")
	}
	fmt.Fprint(os.Stderr, "Apply this local tmux setup? [y/N] ")
	var input []byte
	var b [1]byte
	for len(input) < 16 {
		n, err := os.Stdin.Read(b[:])
		if err != nil {
			return err
		}
		if n > 0 {
			if b[0] == '\n' {
				break
			}
			input = append(input, b[0])
		}
	}
	if answer := strings.TrimSpace(strings.ToLower(string(input))); answer != "y" && answer != "yes" {
		return fmt.Errorf("setup canceled; no changes applied")
	}
	return nil
}

func serve(store *shellport.Store, listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("bind Shellport to a loopback IP; use an HTTPS reverse proxy for access from other devices")
	}
	if _, err = strconv.Atoi(port); err != nil {
		return err
	}
	tmuxRuntime, err := shellport.NewTmuxRuntime(store)
	if err != nil {
		return err
	}
	defer tmuxRuntime.Close()
	app := shellport.NewServer(store, web.Files())
	app.SetTmuxRuntime(tmuxRuntime)
	defer app.Close()
	server := app.HTTPServer(listen)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	finished := make(chan struct{})
	var runtimeErr error
	go func() {
		defer close(finished)
		select {
		case <-ctx.Done():
		case <-tmuxRuntime.Done():
			runtimeErr = fmt.Errorf("local tmux runtime stopped; restart Shellport: %v", tmuxRuntime.Err())
		}
		app.Close()
		{
			if err := tmuxRuntime.Close(); err != nil && runtimeErr == nil {
				runtimeErr = err
			}
		}
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Println("Shellport listening at http://"+listen, "— data:", store.Dir)
	err = server.ListenAndServe()
	stop()
	<-finished
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return runtimeErr
}
