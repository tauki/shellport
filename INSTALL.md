# Installing Shellport with an assistant

Use this guide when a user asks you to install Shellport. Discover the machine, agree on the setup, then carry out and verify the approved plan. Read [README.md](README.md) from the version being installed for the current commands and behavior. [HOWIUSEIT.md](HOWIUSEIT.md) is an optional personal example, not a required architecture.

## 1. Discover before changing the machine

Start with relevant read-only inspection. Respect the user's instructions, machine permissions and any existing installation. Do not read unrelated private files or print credential contents.

Establish:

- Which computer will host the server, its OS, userspace architecture and ordinary OS account. Inspect the actual machine rather than assuming from its hardware model. On Linux, `uname -m`, `getconf LONG_BIT` and, where available, `dpkg --print-architecture` help distinguish a 64-bit kernel from a 32-bit OS. On macOS, check whether the host is Apple Silicon or Intel, including whether the current shell is running under Rosetta.
- Whether Shellport already exists: executable, running process, service registration, persistent data location and configured proxy. Record paths and versions where available without exposing secrets. An upgrade must preserve the installation's credentials, saved targets and tmux work.
- How devices will reach it: local-only evaluation, home network, existing private VPN or authenticated gateway; hostname, certificate and reverse proxy. Identify available service managers and existing infrastructure before proposing new ones. Phone access requires HTTPS and a network route; a certificate alone cannot make a private machine reachable.
- Which computers the user wants to operate, whether their SSH servers are reachable from the hosting computer, and whether tmux is available under the target account. Ask whether terminals on the hosting computer itself should be enabled; that feature is off by default.
- Available build/download tools, free disk space, a free loopback port, and whether administrative access is available or needed.

Ask only for missing choices that affect the setup. A user may already have selected a host, domain, VPN, supervisor or authentication method; retain those decisions.

## 2. Confirm a concrete installation plan

Before downloading, building, installing dependencies or changing the machine, present the proposed server version/platform, executable and private data paths, runtime account, loopback port, browser URL, HTTPS/private-access arrangement, startup method and intended shell targets. Say which packages, services, proxy/DNS/firewall settings or credentials you need to create or change. For an upgrade, include a backup and executable rollback plan, and flag any data migration separately.

Obtain the user's confirmation of that plan. Existing explicit approval of the same concrete plan is sufficient. Then complete its routine steps without repeated permission questions. Confirm again if discoveries require a material change in scope, replacement of existing data, broader network exposure or another destructive action. If permissions or sandbox restrictions block an approved operation, request the appropriate elevated access; do not work around them by changing cache or home paths.

## 3. Choose a download or source build

Check [GitHub Releases](https://github.com/tauki/shellport/releases) for a stable release and inspect its actual assets. Pin an explicit tag; do not invent a version or assume `latest` will resolve. Public releases can be downloaded without GitHub credentials. If the repository is private, use only access the user has authorized, and do not request or expose a token unnecessarily.

Select the **server** archive, not an iPhone download:

| Hosting OS and architecture | Asset suffix |
| --- | --- |
| Linux, Intel/AMD 64-bit | `linux-amd64.tar.gz` |
| Linux, ARM64 with a 64-bit OS | `linux-arm64.tar.gz` |
| Linux, ARMv7-compatible 32-bit OS | `linux-armv7.tar.gz` |
| macOS, Apple Silicon | `darwin-arm64.tar.gz` |
| macOS, Intel | `darwin-amd64.tar.gz` |

The full filename is `shellport-<tag>-<platform>.tar.gz`. A Raspberry Pi with a 64-bit OS uses `linux-arm64`; a Pi running a compatible 32-bit OS uses `linux-armv7`, even when its processor supports 64 bits. Older ARMv6 systems are not covered. Native Windows releases are not provided; discuss a supported Linux/macOS host or an explicitly agreed WSL2 setup before proceeding on Windows.

If GitHub CLI is already available, inspect releases with `gh release list --repo tauki/shellport` and `gh release view <tag> --repo tauki/shellport --json tagName,isDraft,isPrerelease,assets,url`. Download only the chosen archive, `SHA256SUMS`, `SHA256SUMS.sig` and `shellport-release-key.pem` into a new staging directory. `gh release download <tag> --repo tauki/shellport --pattern <exact-asset-name> --dir <directory>` can be repeated for each file. HTTPS asset links from the release page work without the CLI. Do not overwrite an existing download or installation directory.

If no release has been published, or no compatible asset exists, propose building from source. Distinguish that condition from connectivity failures, access denial or rate limits; resolve or report those errors instead of silently switching sources. Prereleases or unverified downloads require the user's conscious agreement, and must not be described as verified stable binaries.

### Verify before running a downloaded binary

All releases, including beta and release candidates, sign the raw `SHA256SUMS` file using Ed25519 with the same release key. Obtain a trusted copy of the publisher's public key, or confirm the downloaded key against a previously trusted copy. A key fetched beside the same archive does not independently establish publisher identity. If no trust has been established, explain that limit and agree on a trusted source/key or a source build before proceeding. Installing Shellport never requires the publisher's release-signing private key.

With OpenSSL 3 and the trusted public key:

```sh
openssl pkeyutl -verify -pubin -inkey /absolute/path/to/trusted-release-key.pem \
  -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
```

Then compute the chosen archive's SHA256 with `sha256sum` on Linux or `shasum -a 256` on macOS and match it exactly to that filename's entry in the verified checksum file. There is no need to download the other platforms. Stop on missing signatures for an expected signed release, mismatches or verification failures.

Inspect archive entries before extraction: they should stay inside `shellport-<tag>-<platform>/` and contain the executable, documentation and license notices. Extract into a new version directory, preserve executable permissions and check the binary's platform with `file` where available. Do not remove macOS security protections automatically if execution is blocked; investigate and agree on the appropriate next step.

### Build when a release is unavailable

Obtain the source from `https://github.com/tauki/shellport` into the approved directory, or use an existing trusted checkout. Prefer an explicit tag/commit. If building an unreleased branch, record the actual commit and any local changes; do not describe it as a published release. Preserve existing work and inspect dependency/build scripts before running them.

Building requires Node 22.12+ or 24+, Go 1.26.9 or newer, Python 3 and `make`. Use a current security patch of your Go release. Complete integration checks also need tmux and tcsh; tests requiring a missing executable are skipped. Install missing prerequisites only within the confirmed plan. Use normal toolchain/cache locations; request required permissions instead of redirecting caches around restrictions.

From the source root:

```sh
npm ci
go mod download
make build
make test
```

`make build` builds the interface before embedding it in `bin/shellport`. Do not run a bare Go build against an absent or stale frontend. Copy the resulting executable into the approved version directory. Node, Go and Python are build tools; the installed Go binary embeds the frontend and does not need them at runtime. `make bundle` produces Linux ARM64 and ARMv7 binaries; it is not the native build command for every host. Record skipped or failed checks explicitly.

## 4. Configure the approved setup

Run Shellport under an ordinary OS account. Keep its private persistent data outside version directories, readable only by its owner, and back it up separately. For an existing installation, reuse that data and do not run `init` again or replace its SSH key. Run `shellport version` (or `--version`) to record the installed tag, commit and platform without opening its data directory. Source builds say `dev`; unavailable source revisions say `unknown`. Inspect the selected binary's `init -h`, `serve -h` and `add-host -h` if needed.

Passkeys use each configured hostname as its relying-party ID. Agree on a stable HTTPS browser address before enrollment; an IP address cannot be used for passkeys. Password login remains available. Preserve the full data directory, including `passkeys.json` when present. Let the user personally enroll through **Workspace settings → Add passkey** or the password-first setup flow on the login page, and complete the device's confirmation prompt. Do not create a passkey on their behalf or put one in an assistant's authenticator. A new hostname requires enrollment for that hostname; old keys are listed in settings with their address.

For a new installation, substitute the approved absolute paths and exact origins:

```sh
/absolute/path/to/shellport init --data-dir /absolute/private/shellport-data \
  --origin http://127.0.0.1:8088 \
  --origin https://shellport.example.com \
  --trusted-proxy 127.0.0.1
/absolute/path/to/shellport serve --data-dir /absolute/private/shellport-data \
  --listen 127.0.0.1:8088
```

Let the user enter the app password through the interactive prompt. For an approved unattended setup, `init --password-file` accepts a private mode-600 file; do not put the password in a command, transcript or service definition. Initialization hashes it and generates a dedicated SSH key. The password must be 12–72 bytes. An existing SSH key can be chosen with `--key-file` if approved. Use `public-key --data-dir ...` to obtain only the public key to authorize on agreed SSH targets.

Add `--local-shell` to `init` only when local terminals are wanted. They run as the server's OS user. Install tmux on each target where needed, including the hosting computer for local sessions. New local setups default to independent tmux ownership; agree on that lifetime during the installation plan. If its executable is outside the setup command's PATH, choose an absolute `--tmux-bin` path. Local initialization displays a service/configuration plan and asks for confirmation; use `--dry-run` to inspect it without initializing credentials or changing files, and `--yes` only within the already confirmed unattended plan.

The listener must use a numeric loopback IP. It defaults to port 8088, or the `PORT` environment variable; use the approved explicit address in the service definition. Configure a same-computer HTTPS proxy to that listener, including WebSocket upgrades, using the trusted client-address contract below. Allow exactly the browser origin, without a path or trailing slash. Shellport expects the root of a dedicated hostname. Keep ingress within the agreed private network or authenticated gateway.

Configure request-body timeouts and per-client and backend connection limits at that proxy as well. Shellport bounds each HTTP request read, including headers and body, to 10 seconds and decoded JSON to 64 KiB; upgraded terminal WebSockets retain their existing lifetime. Proxy limits must release stalled uploads and excess connections without imposing that short read budget on established terminal WebSockets.

### Configure trusted proxy client addresses

The HTTPS proxy is an external installation component. Shellport accepts forwarded client identities only from explicitly configured proxy IPs or CIDRs; no custom header or shared proxy secret is required for this mode. Keep the numeric loopback listener, HTTPS, exact allowed origins, private ingress and WebSocket upgrades.

Back up the private configuration and proxy settings, stop Shellport, and coordinate these changes before restarting:

1. Set the proxy's TCP source addresses, not browser addresses. New installations accept repeatable `init --trusted-proxy` flags. For an existing installation with a same-host proxy connecting over IPv4 and IPv6 loopback, run:

   ```sh
   /absolute/path/to/shellport setup-proxy --data-dir /absolute/private/shellport-data \
     --trusted-proxy 127.0.0.1 --trusted-proxy ::1
   ```

   This replaces the complete `trustedProxies` list, preserves all other configuration and saved state, and refuses to run while Shellport is active. Use only the addresses needed for the installation. Numeric IPs and CIDRs are supported; names, ports and zone identifiers are rejected. Narrow exact addresses are preferable to broad networks. There is no implicit loopback trust. Use `setup-proxy --data-dir ... --clear` to remove all trust and reject forwarded requests. Local HTTP development without a forwarding proxy needs no trusted-proxy configuration.

2. For every HTTP and WebSocket request, have the proxy replace incoming `X-Forwarded-For` with the connecting client's single IP address. Never append a chain or preserve a browser-supplied value. When forwarding the browser origin, replace `X-Forwarded-Host` with its original hostname and non-default port and `X-Forwarded-Proto` with `https`; supply these two headers together. If the transport already carries the correct host and scheme, both origin headers may be omitted. The proxy may also emit `Forwarded` and `X-Real-IP`; these never replace `X-Forwarded-For` as Shellport's client identity source. Missing or malformed XFF still fails closed.
3. If another gateway precedes the proxy, establish a trusted, sanitized handoff of the original client address there too. The immediate peer address may identify that gateway rather than the browser. A gateway that cannot replace the required headers needs a proxy that can. Do not trust arbitrary incoming address headers at any hop.
4. Restart and check password and passkey sign-in from two devices, existing signed-in operations, and terminal connections. Invalid or untrusted forwarding returns 403. `/api/health` remains available without proxy credentials and does not prove the forwarding setup works.

**Trust on the hosting computer:** trusting a proxy source address trusts every process able to connect to Shellport from that address. Trusting `127.0.0.1` or `::1` therefore also trusts other local processes to supply client addresses and forwarded origins. A malicious local process can impersonate the proxy, rotate apparent client IPs, and consume the public emergency allowance. This mode does not isolate hostile local users or processes. It still requires the app password or passkey to sign in, exact allowed origins, and a valid session for authenticated confirmation; forwarding headers never grant those privileges.

Local HTTP development without forwarding headers uses the TCP peer IP, including when that IP is listed in `trustedProxies`. With no configured proxy trust, forwarding metadata is rejected. Password login and passkey challenge creation each allow ten attempts per client per rolling minute, with a separate emergency ceiling of 100 across clients for each mechanism. Successful authentication refunds its attempt. Password confirmation and password changes share a separate allowance keyed by a valid signed-in session, so unauthenticated traffic cannot consume it. Devices sharing a source IP share public capacity; distributed clients and trusted local processes can still reach the emergency ceiling. No deployed proxy is changed by a Shellport source patch.

Register startup with the chosen service manager, using absolute executable/data paths and the intended account. Ensure its environment can find tmux if local persistence is enabled. The service should restart after failure and start after a reboot, without depending on an open interactive terminal. The unauthenticated `/api/health` endpoint is suitable for a health check; it does not prove a shell connection works.

### Local shell privileges

Discuss local-shell permissions when choosing the hosting service. Run Shellport under the intended ordinary OS account. Sudo remains subject to that account's authorization, authentication and other OS rules; Shellport does not grant root access or configure passwordless sudo.

On Linux, `NoNewPrivileges=true` prevents programs such as sudo from gaining privileges through setuid execution. Direct local shells and Shellport-managed tmux inherit the web server's process restrictions. Independent tmux shells inherit their separate tmux server's restrictions. SSH shells use the remote computer's policies. Session lifetime and privilege policy are separate choices.

**Workspace settings → Local sessions → Privilege elevation** reports the running web server's flag for direct shells and each configured tmux server's flag separately. “Not blocked by this flag” is not a guarantee that sudo works. “Unknown” means the platform, server or process information cannot be checked reliably. This is a read-only Linux flag check; it does not execute sudo or inspect its password. Existing shells can have additional restrictions of their own.

For a new Linux independent tmux service, `--tmux-privileges account` uses `NoNewPrivileges=false`, retaining the account's normal OS rules. `--tmux-privileges restricted` sets `NoNewPrivileges=true`. Omitting the option uses `account` for a new service and preserves an existing owned service's policy, including older units that left the setting unspecified. Initialization and offline setup include the policy and its effect in the plan:

```sh
shellport init --data-dir /absolute/private/shellport-data \
  --local-shell --origin https://shellport.example.com \
  --tmux-privileges account --dry-run
```

Review the plan, then omit `--dry-run` to initialize. Choose `restricted` instead when elevation should be blocked. On Linux, enabling an additional independent pool from Settings presents the same choice before creating its service. Normal default changes do not change a configured pool's policy. The flag applies only to independent Linux services; explicitly requesting it for managed mode or another platform returns an error.

For an existing primary independent service owned by this installation, stop Shellport and preview an offline policy change with `setup-tmux --data-dir PATH --tmux-privileges POLICY --dry-run`. Apply only after reviewing it and finishing the affected saved work. Setup refuses a policy change while saved sessions exist, preserves external/operator-modified services and retains rollback snapshots. Installations with both pools retain their existing services; review the affected service with the operator instead of trying to replace a pool with offline setup. Never change `.tmux.conf`, adopt a service, kill work or rewrite service policies merely to make sudo pass.

A running Linux process cannot clear the no-new-privileges flag, and its children inherit it. Changing a unit file alone does not update existing shells. A parent that already has the flag cannot launch an unrestricted child by setting `NoNewPrivileges=false`. If the intended policy permits elevation, the chosen service manager must launch a new service with that policy. Preserve existing sessions until the user agrees to the required transition; do not restart tmux silently. See the [Linux kernel explanation](https://docs.kernel.org/userspace-api/no_new_privs.html) and [systemd execution settings](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml).

Save targets through the web interface or `add-host`. Each SSH target needs its own reachable address, account and authentication. Verify the displayed SSH host fingerprint against an independent trusted source before accepting it. Never bypass a changed-key refusal. Do not place SSH private keys or passwords in browser storage or public files.

### Choose the local tmux lifetime

Both modes create sessions and shell tabs automatically through the interface. They govern local tmux only; SSH targets keep their own process lifetimes.

After installation, **Workspace settings → Local sessions** can enable both modes and choose the default for new sessions. Existing sessions retain their original pool and remain running when that default changes; tabs inherit their session’s mode. Enabling the additional independent pool previews its user-service startup requirements and requires explicit confirmation. It does not disable, adopt or rewrite the installation’s existing tmux service. Managed sessions use a second private socket and end when Shellport stops, including after loss of its owning process. The picker shows each session’s mode. Its **Advanced** section offers a compact **Session lifetime** toggle during creation. **Open direct shell** sits below the primary creation action and bypasses tmux for that connection. Direct shells end on disconnect; they preserve the saved computer and its last tmux selection. No new choice is required to resume work.

Add/Edit computer contains connection details only. Shellport discovers tmux availability when opening the computer; the old persistence checkbox is no longer needed. When tmux is not found for the account, direct shell becomes the primary action. Authentication, permissions, command failures and malformed availability responses remain errors, with no automatic fallback or installation. Existing saved computer records and their remembered selections are preserved.

Preserve the whole data directory, including any `tmuxAdditional` profile and service receipt in `config.json`. It identifies a separate server, not a replacement for the original pool. The original socket and stable references stay intact. Use `shellport tmux --data-dir PATH --tmux-mode independent -- ls` or `--tmux-mode managed` to inspect a chosen configured pool; an omitted mode retains the original CLI behavior. Offline `setup-tmux` changes the original installation and still refuses unsafe transitions; it is not the command for changing the browser’s new-session default.

- **Independent (default):** tmux runs in a separate user service, so local shells survive Shellport and hosting-supervisor restarts. Automatic setup supports Linux systemd user services and macOS GUI launch agents. The plan shows the binary, private socket, service file and startup requirements. Linux boot without login requires separately approved user lingering; macOS requires a GUI login session. Setup does not install tmux packages, change network access or grant additional OS permissions.
- **Managed:** Shellport owns a private foreground tmux server. Closing the browser leaves shells running; stopping or restarting Shellport ends those local tmux shells. A parent-liveness pipe cleans up after abrupt termination too. No OS service is installed for this mode.

For a new installation, preview and apply the default independent setup:

```sh
/absolute/path/to/shellport init --data-dir /absolute/private/shellport-data \
  --origin https://shellport.example.com --local-shell --dry-run
/absolute/path/to/shellport init --data-dir /absolute/private/shellport-data \
  --origin https://shellport.example.com --local-shell
```

To choose managed mode, add `--tmux-mode managed` to initialization. Use `--password-file` plus `--yes` for an approved unattended installation. An unavailable service manager is an error; do not silently substitute managed mode because it changes what happens to saved work.

For an existing installation, stop Shellport before changing local ownership. Use its existing private data directory:

```sh
/absolute/path/to/shellport setup-tmux --data-dir /absolute/private/shellport-data --dry-run
/absolute/path/to/shellport setup-tmux --data-dir /absolute/private/shellport-data --tmux-mode independent
```

`setup-tmux` defaults to independent; select `--tmux-mode managed` explicitly for Shellport-owned processes. It checks an installation lock, refuses a mode change while saved local sessions exist, retains credentials/computers/SSH keys, and saves private configuration/service snapshots under `tmux-backups/`. Service ownership is recorded in `tmux-setup.json`; only that installation's unmodified service file may be replaced or removed. A failed service installation preserves the prior configuration and attempts to restore its owned service. Read any recovery diagnostic before retrying an uncertain setup.

Configurations without the new mode fields retain their existing operator-selected tmux executable/wrapper and socket behavior. They are not silently migrated. Older running binaries do not hold the new setup lock: stop them explicitly before using `setup-tmux`. Preserve any separately managed service; Shellport does not adopt or disable it merely because its wrapper was configured previously.

A different socket is a different tmux server. Existing live shells cannot be moved simply by changing the socket path. Keep them available until an agreed transition is possible; never end or delete user work to make setup pass. Use an actual tmux executable or a transparent operator wrapper that forwards its flags; a wrapper that forces another socket is not suitable for the new modes.

Both modes use a dedicated private socket and tmux defaults (`-f /dev/null`), keeping unrelated default-server sessions separate. Clients use `-N` so an unavailable server is not recreated under the wrong supervisor. The server uses `-D` to stay in the foreground and remain available when no sessions exist. To open the same installation through another local/SSH client, use `shellport tmux --data-dir /absolute/private/shellport-data -- attach-session -t work` rather than a bare `tmux` command pointing at another socket. Flag meanings: [tmux manual](https://github.com/tmux/tmux/blob/3.5a/tmux.1).

For independent mode, verify a disposable shell retains its variable and pane PID after web-server and hosting-supervisor restarts. On Linux, compare `/proc/<tmux-server-pid>/cgroup` with the web supervisor rather than assuming detachment proves independence. For managed mode, verify closing the browser retains work but stopping Shellport ends its local tmux server. Test fail-closed behavior only with a disposable instance. Neither mode preserves running processes through reboot or power loss. Back up configuration/credentials separately from executable releases; rollback must not move clients away from live work without an agreed transition.

### Recover a forgotten app password

Only perform recovery when the operator asks for it. Reuse the existing private data directory under the server's OS account. Stop Shellport and pause any automatic restarter; verify an older binary has actually stopped because it may not participate in the installation lock. Explain the lifecycle impact before stopping: independent local tmux work remains available, while managed local shells and direct shells end.

Run `shellport reset-password --data-dir /absolute/private/shellport-data` in a local or SSH interactive terminal. Have the user enter the new password and confirmation at the hidden prompts. Do not enter a real user credential on their behalf, put it in an argument, read it into a transcript or rerun `init`. The offline command refuses a locked installation and preserves all non-password configuration, computers, SSH keys and passkeys. There is no network recovery endpoint or unattended password-file option.

After success, restart Shellport, restore its normal startup policy and let the user sign in with the new password or an existing passkey. Previous browser sign-ins expire on restart. The operator must update any separately maintained password file. Report failures without removing or recreating private data.

### Upgrade, backup and rollback

Follow [BACKUP.md](BACKUP.md) for a consistent private backup, executable replacement, failure rollback and restoration. Include externally referenced SSH keys and operator startup/proxy configuration. Keep absolute path and hostname references intact or review their relocation explicitly. Do not restore over live processes/sockets or rerun `init`. The disposable `make test-recovery` rehearsal can accept two verified native binaries; its default current-source fixtures do not prove published-release compatibility.

## 5. Verify and hand over

Check the approved service is running as the intended account and listening only on loopback. Verify both `/api/health` and the actual HTTPS browser route, including login and a WebSocket terminal. Connect to the chosen target, run a harmless command such as `pwd`, and check resizing. For persistence, create a disposable tmux session, disconnect and resume the same tab; test from a second device when available. Do not use or delete unrelated sessions to perform checks.

On iPhone, test Safari access while connected to the intended network, then use **Share → Add to Home Screen**. Actual keyboard, viewport and Home Screen behavior need physical-device verification. If the device is unavailable, say those checks remain pending.

Report the URL, installed release tag or source revision, executable/data paths, service name, startup behavior, backup/rollback approach and checks performed. Identify any remaining user actions or limits. Do not report remote access as working based only on a successful build or health response. Treat later automatic updates as a separate choice: they must select compatible releases, verify them, preserve private data and support recovery. No hosting product or update manager is required by Shellport's release format.
