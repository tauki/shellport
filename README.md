<p><img src="web/public/icon.svg" alt="Shellport logo" width="80" height="80"></p>

# Shellport

Your shell, anywhere. A private web terminal for your phone or computer, with saved computers, SSH, server terminals and optional tmux session persistence.

The Go server embeds the built TypeScript/xterm.js interface. The deployed computer needs no Node runtime. Shellport binds to loopback; a reverse proxy on the same computer provides HTTPS for your devices.

For help choosing and installing a setup, read [INSTALL.md](INSTALL.md). If an assistant is doing the installation, give it [llms.txt](llms.txt) and ask it to follow the linked guide: inspect the machine, propose a setup and confirm it with you before making changes. [HOWIUSEIT.md](HOWIUSEIT.md) describes my own setup as an optional example.

## Preview

Screens from a demonstration installation, including saved sessions and direct shells. [See the phone and desktop gallery](SCREENSHOTS.md).

<p><img src="assets/screenshots/desktop-terminal.jpg" alt="Shellport desktop workspace with saved computers and a connected terminal" width="960"></p>
<p><img src="assets/screenshots/phone-terminal.jpg" alt="Shellport phone layout with a connected terminal and keyboard controls" width="280"> <img src="assets/screenshots/phone-sessions.jpg" alt="Phone session picker with saved shell tabs and the Open direct shell action" width="280"></p>

## Build and verify

Building requires Node 22.12+ (or 24+), Go 1.26.9 or newer with current security patches, Python 3 and `make`. Install tmux for the terminal integration tests and tcsh for the non-POSIX SSH shell regression. Tests requiring a missing executable are skipped; GitHub Actions installs both test dependencies. Go's normal toolchain selection can download the required version. Build before running Go directly because the frontend is embedded.

```sh
npm ci
go mod download
make build
make test
make bundle
```

`make bundle` creates Linux ARM64 and ARMv7 binaries under `bundle/`. `make test` checks archive metadata, typechecks the interface, runs terminal-input tests, runs race-enabled Go tests and runs vet. Integration tests execute a real `/bin/sh` through SSH and WebSocket, exercise server PTY resizing and Ctrl-C, reject unauthenticated/cross-origin requests and changed keys, and revoke terminals on logout.

## Releases

GitHub Actions builds and tests source pushes and pull requests on Linux and macOS, including the real tmux integration tests. Pushing a version tag such as `v0.1.0` runs those checks again, then publishes five server archives and a `SHA256SUMS` file to GitHub Releases. Tags with a suffix such as `v0.1.0-rc.1` create prereleases. Ordinary source pushes do not publish a release or deploy an installation. [CHANGELOG.md](CHANGELOG.md) records changes and compatibility notes; release descriptions use the matching version section, or the Unreleased section when preparing a new version.

All releases, including beta and release candidates, sign `SHA256SUMS`, covering all five platform downloads, and include `SHA256SUMS.sig` plus the public `shellport-release-key.pem`. This is one Shellport release key pair for every platform and release channel, separate from SSH keys and installation credentials. Keep the private key outside source and distribute its public verification key through a trusted setup.

Releases publish automatically after tests and signing succeed for the repository owner's release tag; no manual signing approval is required. Before adding the signing key, enable GitHub rulesets for `main` and all `v*` tags that restrict creation, updates and deletion to the owner's individual user identity. This protects both the trusted signing source and every release tag, including prereleases.

Create the `release-signing` GitHub environment with no required reviewers or wait timer. Under Selected branches and tags, allow only a Tag rule matching `v*`, with no Branch rules. Store a dedicated base64 Ed25519 private key as that environment's `SHELLPORT_RELEASE_SIGNING_KEY` secret. Remove any repository-level copy and any organization-secret grant to this repository; those broad copies remain accessible to other workflows. The tag policy limits which runs may receive the key; owner-controlled tags and signing source establish the trust boundary. An environment name in YAML alone does not enable these protections.

Packaging runs without the key. Signing runs on a fresh runner for every release, requires the tagged commit to belong to default-branch history, compiles the signer from that branch without credentials or shared build caches, then gives the key only to the signer executable. Publication requires signature verification. Prereleases retain GitHub's prerelease label; a valid signature authenticates a download without declaring it stable. Deployment and automatic-update policy belong to the installation's operator or update manager.

With a trusted copy of the release public key, verify the checksum signature using OpenSSL 3, then check the archive you downloaded against `SHA256SUMS`:

```sh
openssl pkeyutl -verify -pubin -inkey shellport-release-key.pem \
  -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
```

Match the public key to a previously trusted copy; a key downloaded beside an archive does not establish the publisher's identity by itself.

The release public key is also kept in the repository as `shellport-release-key.pem`. Its SHA256 fingerprint, calculated over DER SubjectPublicKeyInfo, is `9b2162b5a5e6d7fbb5645d86cb28b9109bab05715379104bb679137aa8d76f4a`. Compare this with a copy or fingerprint obtained through a trusted channel:

```sh
openssl pkey -pubin -in shellport-release-key.pem -outform DER | openssl dgst -sha256
```

| Archive platform | Hosting computer |
| --- | --- |
| `linux-amd64` | Intel/AMD Linux computers and servers |
| `linux-arm64` | Raspberry Pi with a 64-bit OS and ARM64 Linux servers |
| `linux-armv7` | Raspberry Pi with a 32-bit ARMv7-compatible OS |
| `darwin-arm64` | Apple Silicon Macs |
| `darwin-amd64` | Intel Macs |

Phones and other browsers use the same web interface; they do not need a platform-specific download. Linux binaries are built without a C runtime dependency. Each archive contains the executable, project license, public release key, this README, the installation guide, assistant entry point, personal setup example, changelog, backup/recovery guide and third-party license notices. Extract the archive and use `./shellport` in the initialization commands below, keeping installation data outside the extracted release directory.

To prepare the same packages locally without publishing, run `npm ci`, `go mod download`, `make build`, then `python3 scripts/release.py v0.1.0`. Packages appear under `bundle/releases/v0.1.0/`. The script refuses to overwrite an existing version directory.

For a signed local package set, use `python3 scripts/release.py v0.1.0 --sign` with `SHELLPORT_RELEASE_SIGNING_KEY` supplied securely in the process environment. Only the final signer executable receives the key; Git, cross-builds and signer compilation use a sanitized environment. One signature covers the checksums of all five archives. Packaging never uploads files or publishes a release.

### Check the installed version

Run `shellport version` or `shellport --version` without an initialized installation. The output identifies the release, source commit and operating system/architecture. Release packaging embeds its tag and source commit in all five binaries. Ordinary source builds say `dev`, with Git revision/modified state when the Go build metadata is available; an unavailable revision is reported as `unknown`.

## Initialize an installation

Keep state outside release directories. Initialization asks for an app password, hashes it, generates a dedicated Ed25519 SSH key and refuses to overwrite an existing installation. Replace `https://shellport.example.com` with the exact HTTPS origin you will open in your browser, including its port if it uses one. An origin has no path or trailing slash.

```sh
./bin/shellport init --data-dir /absolute/private/shellport-data \
  --origin http://127.0.0.1:8088 \
  --origin https://shellport.example.com \
  --trusted-proxy 127.0.0.1
./bin/shellport public-key --data-dir /absolute/private/shellport-data
./bin/shellport serve --data-dir /absolute/private/shellport-data \
  --listen 127.0.0.1:8088
```

Authorize the public key on each SSH target. You may select an existing operator-owned key with `init --key-file /absolute/private/key`; encrypted key passphrases are requested per connection and not saved. SSH agent authentication is available when the operator configures `agentSocket` in the private configuration.

`--trusted-proxy` identifies the HTTPS proxy's TCP source address, not your phone's address. Repeat it for additional proxy IPs or CIDRs, such as `--trusted-proxy ::1` when the proxy also connects over IPv6. Omit it for local HTTP use without a proxy. To replace the list later, stop Shellport and run:

```sh
shellport setup-proxy --data-dir /absolute/private/shellport-data \
  --trusted-proxy 127.0.0.1 --trusted-proxy ::1
```

The command preserves the rest of your configuration and saved data. Start Shellport again after updating it. `setup-proxy --clear` removes all proxy trust; forwarded requests will then be rejected.

For unattended initialization, `--password-file` accepts an existing mode-600 file. The app itself does not save a plaintext password. Preserve or remove the operator's source file according to their credential-management policy.

To allow terminals on the hosting computer itself, add `--local-shell` during initialization. It is disabled by default. The terminal runs under the server's ordinary OS account, in its home directory. Local tmux defaults to an independent user service; initialization shows its plan and asks before installing it. Install tmux first. Use `--tmux-bin /absolute/path/to/tmux` when it is outside the setup command's PATH.

## Local session lifetime

Choose how local tmux runs when initializing with `--local-shell`:

| Mode | When the browser closes | When Shellport stops or restarts |
| --- | --- | --- |
| `independent` (default) | Shells keep running | Shells keep running in their own user service |
| `managed` | Shells keep running | Shellport's local tmux shells end |

These modes apply to terminals on the hosting computer. SSH targets keep their own tmux lifetimes. Direct shells without tmux end on disconnect. Reboots, power loss and stopping the tmux server end its running shells in either mode.

Both modes can run at the same time. **Workspace settings → Local sessions** shows the default for new sessions and each mode’s session count. Changing the default keeps existing sessions running on their original tmux server. Enabling another mode asks for confirmation first; independent mode creates its own user service, while managed mode starts a private server owned by Shellport. The server account needs access to the selected service manager when enabling independent mode.

The picker labels each local session **Independent** or **Managed**. Opening a session adds no mode prompt, and new tabs inherit their session’s mode. When both modes are enabled, expand **Advanced** to use the compact **Session lifetime** toggle during creation. Its explanation describes what happens when Shellport stops or restarts. Changing a default does not move or convert existing sessions.

Choose **Open direct shell**, below **Create and connect** in a computer's session picker, to use a normal shell without tmux for that connection. Its tab is labeled **Direct shell** and ends when you disconnect; reconnecting starts a new shell. The last selected saved session stays intact, so one saved computer supports both types of terminal.

Preview the default setup without writing files or changing services, then initialize normally:

```sh
./bin/shellport init --data-dir /absolute/private/shellport-data \
  --local-shell --origin https://shellport.example.com --dry-run
./bin/shellport init --data-dir /absolute/private/shellport-data \
  --local-shell --origin https://shellport.example.com
```

Add `--tmux-mode managed` to choose Shellport-owned processes instead. Independent setup installs an isolated systemd user service on Linux or a launchd user agent on macOS; it creates no network listener. Linux startup without login needs separately configured user lingering, and macOS needs a GUI login session. Setup reports unavailable service managers and preserves the selected mode rather than silently falling back. `--yes` supports unattended setup after reviewing the plan.

Local shell permissions follow the OS account and the service that launches them. On Linux, a service with `NoNewPrivileges=true` blocks sudo's usual privilege elevation. Settings reports this flag separately for direct shells and the configured tmux servers; it shows “Unknown” when it cannot check reliably. For a new independent Linux service, choose `--tmux-privileges account` (the new-service default) or `--tmux-privileges restricted` during setup. Existing owned policies are preserved when the option is omitted. Changes never clear restrictions on already-running shells or grant additional account permissions. See [local shell privileges](INSTALL.md#local-shell-privileges) for the setup choices and preservation limits.

Existing installations retain their operator-selected tmux behavior until explicitly changed. Stop Shellport, review `setup-tmux --data-dir /absolute/private/shellport-data --dry-run`, then run it with the chosen `--tmux-mode`. It defaults to independent. Setup refuses changes while Shellport is running or saved local sessions exist, preserves credentials and computers, and saves rollback snapshots under the private data directory's `tmux-backups/`. It replaces or removes only service files recorded as its own; operator-modified services require manual review.

Sessions and shell tabs are still created or attached automatically through the interface. For another local/SSH client to use the same installation's socket, use:

```sh
./bin/shellport tmux --data-dir /absolute/private/shellport-data -- ls
./bin/shellport tmux --data-dir /absolute/private/shellport-data -- attach-session -t work
./bin/shellport tmux --data-dir /absolute/private/shellport-data --tmux-mode managed -- ls
```

Both modes use a private socket. Clients refuse to start a replacement server when it is unavailable. Managed mode also watches its owning process so abrupt termination of Shellport closes its local tmux server. See [installation and migration guidance](INSTALL.md#choose-the-local-tmux-lifetime).

Without `--tmux-mode`, the CLI client keeps using the installation’s original pool. Choose the flag explicitly to inspect the other pool. Existing operator wrappers and services retain their behavior; their supervisor still determines restart survival, and settings marks those sessions as an operator setup.

## Add and use computers

Sign in, choose **Add computer**, enter its SSH address/user and select key or password authentication. Before the first connection, compare its displayed SHA256 host fingerprint with an independent trusted source on the computer. Shellport pins that exact key. Retargeting a saved address or port clears the prior trust. Changed keys are refused until explicitly verified again.

Password and key-passphrase inputs are used for that connection only. The browser stores only a text-size preference; no SSH key, password, shell transcript or app session token is stored in localStorage.

Selecting a computer checks whether tmux is available for that account. When it is, open an existing saved session or create a separate workspace. A name is optional; leaving it blank uses the exact six-character name shown in gray in the field, such as `a7c3e9`. Sessions created through other SSH clients appear when they use the same remote account and tmux server. **Open direct shell** is also available. If tmux is missing, a direct shell becomes the primary action and Shellport explains that saved sessions require installing tmux. Connection, permission and command errors remain explicit; they are not treated as missing tmux.

When you return to an open Shellport page or connectivity returns, the selected terminal checks its connection and automatically resumes the same saved tmux session and shell tab. Failed attempts slow down to one every 30 seconds; retries pause while the page is hidden. Other disconnected terminals resume when you select them. Automatic recovery does not open the phone keyboard or replay disconnected input. SSH passwords and encrypted-key passphrases must be entered again; expired app sign-ins, changed computer identities and ended shells need your attention. Direct shells require a manual reconnect, which opens a new shell. If the browser reloads or discards the page entirely, use the session picker's **Continue** action to resume your saved work.

Each session can contain multiple independent shell tabs, backed by tmux windows. Expand a session to resume an existing shell or choose **New tab** to create another. The plus beside open terminals also creates a new tab. **Rename session** and **Delete session** are under the session's **More options** button. Renaming changes the name on the computer while its shells keep running; connected devices update their terminal labels, and saved reconnect selections retain the same session and tab. Opening a session or tab already open in the current Shellport workspace focuses its existing terminal. Connections use temporary grouped tmux views so selecting a window on one connection does not switch another connection's window.

Each terminal reconnects to its selected session and shell tab. Shellport remembers the last selection for each saved computer on its server, so another signed-in device can choose **Continue** and the last used tab. Closing a terminal detaches its connection and leaves its shell running. Existing default Shellport sessions remain available. If a selected session or tab has ended, choose another or explicitly create one; Shellport does not silently recreate it. Sessions normally end when the remote computer reboots.

Each saved tab has its own **More options** menu. **Rename tab** saves the name in tmux and updates connected terminal labels across devices without interrupting the shell. **Close tab** requires confirmation and removes the tab from the selected session, disconnecting its terminals on every device. Its unshared shell and running commands end; tabs explicitly linked into other tmux sessions remain running there. Closing the last tab also ends the selected session. Other windows and remote files remain. Closing tabs in sessions grouped with other non-Shellport sessions requires ungrouping them in tmux first. Use the terminal strip's **×** to detach without ending its saved shell.

The session's **Delete** action requires confirmation and removes the tmux session on the target computer, including Shellport's temporary views, disconnecting its terminals on all devices. Its unshared windows and shells end; remote files remain. Windows explicitly linked or grouped into other non-Shellport tmux sessions follow tmux's normal rules and remain while those sessions own them. Deletion cannot restore unsaved terminal work.

Session creation accepts up to 64 letters, numbers, spaces, hyphens or underscores. **Open direct shell** starts a shell without tmux; reconnecting then starts a new shell.

The terminal accessory buttons keep the keyboard's current visibility: tapping an arrow or **Ctrl** does not open it. Ctrl stays selected across arrow taps and sends Ctrl+arrow to the remote program; a typed control chord consumes it, or tap Ctrl again to turn it off. **Select** shows a read-only snapshot of terminal text and scrollback. Use your phone's normal text-selection handles, or extend a selection with the arrows; Ctrl+left/right selects by word. Selection controls operate locally while the shell keeps running. **Copy** copies selected text, or opens selection mode when nothing is selected. **Done** returns to the live terminal without opening the keyboard.

Outside selection mode, **Ctrl C** sends an interrupt. **Paste** uses browser clipboard access, with a manual entry sheet when Safari requires it. Typing, Paste and interrupts are disabled while selecting text.

## Passkeys

Sign in with the key button, or choose **Use password instead**. On a new installation, the key button first asks for your password, then offers **Add passkey**. Tap that action to open your device’s passkey prompt; **Not now** continues without adding one. You can also add and view passkeys in **Workspace settings**. Each passkey's **More options** menu lets you rename its Shellport label or remove it. Renaming keeps the credential usable and does not rename its entry in your device's password manager. Your app password remains a fallback.

Passkeys require a supported browser and a stable HTTPS hostname (localhost HTTP works for development). Each hostname has its own passkeys, so use the same address on your devices. Your password manager may sync them between devices. Passkeys authenticate to Shellport; SSH authentication to your computers stays separate. Adding or removing a passkey requires a recent sign-in or password confirmation.

Back up the complete private data directory, including `passkeys.json` when present. It stores credential public keys and metadata; the private passkey stays in your device or password manager. Removing a passkey from Shellport prevents future sign-ins with it, but does not sign out existing devices or erase the entry from their password manager.

### Change your password

In **Workspace settings → Change password**, enter your current password, a new password and its confirmation. New passwords must be 12–72 bytes. Saving signs out every device and disconnects its terminals; direct shells end, while saved tmux sessions keep running. Sign in again with the new password or an existing passkey to resume your saved work. Passkeys, computers and SSH keys are preserved. Only the password hash is saved. If you keep a separate operator password file, update it yourself after changing the password.

### Recover a forgotten password

Recovery requires local OS access to the hosting computer, or an interactive SSH terminal, under the account that runs Shellport. Stop Shellport and pause its automatic restarter first. Independent local tmux sessions keep running; stopping Shellport ends its managed local sessions and direct shells. Preserve the private data directory; do not rerun `init`.

```sh
/absolute/path/to/shellport reset-password --data-dir /absolute/private/shellport-data
```

Enter the new password twice at the hidden prompts (12–72 bytes). The current password is not required. The command holds the installation lock, refuses to run against a running server or another setup/recovery operation, and atomically replaces only the password hash. It preserves other configuration fields, computers, SSH keys and passkeys. Cancelled, mismatched or invalid input leaves the current password unchanged. Recovery has no web endpoint and accepts no password argument or password file.

Restart Shellport, restore its normal startup policy and sign in with the new password or an existing passkey. Prior browser sign-ins expire on restart. Update any separate operator password file yourself. For an older binary that does not hold the installation lock, explicitly verify it has stopped before recovery.

## Upgrades and backups

Keep private data outside executable releases. [BACKUP.md](BACKUP.md) describes consistent backups, executable upgrades, rollback and restoration, including externally stored SSH keys and tmux lifetime limits. Run `make test-recovery` after building to rehearse these operations with disposable data. Default rehearsal builds use the same source; published-version compatibility requires verified release binaries.

## Networking and hosting

Shellport works independently of a particular hosting platform or VPN. For access from a phone or another computer, configure:

- **A reachable hostname.** DNS must resolve your chosen hostname to an address your device can reach over your home network or a private VPN. The server must stay powered on and connected.
- **An HTTPS reverse proxy on the hosting computer.** Use a certificate trusted by your devices and forward requests, including WebSocket upgrades, to `http://127.0.0.1:8088`. Set its source IPs or CIDRs with `init --trusted-proxy` or `setup-proxy`. Replace incoming `X-Forwarded-For` with the connecting client's single IP address, `X-Forwarded-Host` with the browser hostname and non-default port, and `X-Forwarded-Proto` with `https`. Other forwarding formats are ignored as identity sources. Trusting loopback also trusts other local processes that can connect from it; the [trusted proxy setup](INSTALL.md#configure-trusted-proxy-client-addresses) explains this boundary.
- **Matching allowed origins.** Pass the browser's exact HTTPS origin to `init --origin`, as shown above. Use the root of a dedicated hostname rather than hosting Shellport under a URL path.
- **A private access boundary.** Limit ingress to trusted devices through your network, VPN or an authenticated access gateway. Shellport's app password controls terminal access separately from network access; this version is intended for personal use within that boundary.
- **Reachable shell targets.** Each remote computer needs an SSH server, a username and a key or password. It must be reachable from the Shellport server. A terminal on the hosting computer uses the optional local-shell mode instead.

Use your operating system's service manager or another process supervisor to start Shellport on boot and restart it if it fails. Keep the persistent data directory private and back it up separately from the executable. The read-only `/api/health` endpoint is available for health checks without signing in.

Shellport allows 10 seconds to read each HTTP request, including its headers and body, and caps decoded JSON at 64 KiB. Successfully upgraded terminal WebSockets keep their existing lifetime. The HTTPS proxy must also enforce request-body timeouts and per-client and backend connection limits, so slow clients cannot exhaust proxy resources before reaching Shellport.

For persistent terminals on the hosting computer, use the default independent lifetime. A supervisor that stops an entire service group or container can stop a detached tmux server along with Shellport unless its ownership is separate. The [installation guide](INSTALL.md#choose-the-local-tmux-lifetime) covers automatic setup and existing operator configurations. Current sign-ins expire after a Shellport restart; saved tmux work survives in independent mode.

HTTPS protects the browser connection; DNS and network routing make the server reachable. A certificate alone does not provide a route to a private server. Local development can use loopback HTTP, while phone installation uses HTTPS.

### Optional: access through Tailscale

Tailscale can provide the private network between your devices and the hosting computer. Install it on both, connect them to the same tailnet, and allow access through your tailnet policy. The chosen HTTPS proxy must satisfy the generic [trusted client-address contract](INSTALL.md#configure-trusted-proxy-client-addresses): explicitly configured proxy peers and replaced, sanitized standard forwarding headers. A gateway that cannot provide that contract needs a proxy that can; passing its loopback address as every client's identity defeats client isolation. Include the exact HTTPS origin when initializing Shellport.

Tailscale is optional. Another private VPN or a correctly configured home-network route can provide the same connectivity.

## Install on an iPhone

Connect to the network that can reach your server, then open your Shellport HTTPS address in Safari and sign in. Use **Share → Add to Home Screen**, keeping **Open as Web App** enabled where offered. There is no Apple Developer Program membership or development-build expiry. The service worker deliberately does not cache APIs, credentials or terminal content. A network connection is required to operate a shell. [Apple's instructions](https://support.apple.com/en-lamr/guide/iphone/iphea86e5236/ios)

## Development preview

After building, `python3 scripts/preview.py` starts a disposable localhost-only installation under ignored `.work/preview`. Its synthetic password is `synthetic-preview-password`; this helper must never be used for a real installation or private/public hosting.

### Verify a configured installation

The optional smoke tool signs in through the actual HTTP/HTTPS and WebSocket route, checks the reported architecture and terminal resizing, and verifies reconnecting to the same tmux tab when persistence is enabled. Select an existing computer explicitly; its SSH identity must already be verified. For example, replace these values with your own:

```sh
go run ./scripts/smoke --url https://shellport.example.com \
  --password-file /absolute/private/app-password \
  --host-name "My server" --receipt /absolute/private/new-smoke-receipt.json
```

Use `--host-id` instead of `--host-name` when names are duplicated. `--expect-arch` optionally requires an exact `uname -m` result; otherwise the tool discovers it. Targets using an SSH password or encrypted key can supply `--ssh-password-file` or `--key-passphrase-file`. Credential files must be private and contain one nonempty line. The receipt path must be new; it is never overwritten.

This check creates a temporary saved computer and, when applicable, its own tmux session. It cleans them up and signs out on success or failure; cleanup errors are reported. Existing computers, selected sessions and running work are preserved. Run it only against an installation you operate, with room for one additional saved computer and terminal connection. The tool requires Go on the computer running the check; installed Shellport servers do not.

## Scope

Personal, single-owner use behind a trusted private-network boundary. The first version includes terminal operation, saved targets, keyboard controls, persistence and passkey sign-in. SFTP, Mosh, cloud synchronization and native app distribution are future work. Real phone keyboard, passkey prompts and Home Screen behavior still require device verification.
