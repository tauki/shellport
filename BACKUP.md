# Upgrades, backups and recovery

Keep executable releases separate from Shellport's private data. Use the same OS account, data directory and tmux sockets across an ordinary app upgrade. The steps below can be performed manually or by an approved deployment manager.

## Make a recoverable backup

1. Record `shellport version`, executable/data paths, OS account, browser origin, startup command and proxy configuration. Locate any SSH key outside the data directory through the private `keyFile` setting. Record operator tmux wrappers, sockets and service registrations too; do not print private keys or passwords.
2. Stop Shellport and pause its automatic restarter. Independent local tmux and tmux on SSH targets can remain running. Managed local shells and direct shells end when their owning Shellport process stops.
3. Copy the complete private data directory, including `config.json`, `hosts.json`, `passkeys.json` when present, tmux profiles, setup receipts and existing private rollback snapshots. Include externally stored SSH keys and their public keys, and the startup/proxy configuration needed to reconstruct this installation. An SSH agent socket is runtime state; arrange access to the agent's underlying keys separately.
4. Exclude runtime sockets and `server.lock`. Never replace a lock file while a process still holds it. Preserve file ownership and permissions: private directories should be accessible only to their owner; configuration, passkey state and private SSH keys must stay mode 600. Keep the backup private and encrypt it when storing it outside the trusted host.
5. Verify backup checksums and record the SSH **public** key fingerprint. Keep the previous executable or a verified copy of its release archive. Restart Shellport if the backup is not immediately followed by an upgrade.

A copy made while Shellport is writing files may combine different points in time. Stop the app for a consistent backup. Backups contain credentials and must not be committed, published or attached to a bug report.

## Upgrade the executable

1. Download a compatible candidate into a new release directory. Verify its signature/checksum as described in [INSTALL.md](INSTALL.md#verify-before-running-a-downloaded-binary), then run its `version` command. Read [CHANGELOG.md](CHANGELOG.md) for compatibility or migration requirements.
2. Make the backup above and keep the old release. Stop Shellport and its automatic restarter before switching the executable path. Do not run `init`, replace credentials, change tmux modes or move sockets as part of an ordinary executable update.
3. Point the startup command at the candidate, preserving the existing data path and account. Keep any executable or wrapper still referenced by an independent tmux service; a service/lifetime migration is a separate operation.
4. Start the candidate and check `/api/health`, password/passkey sign-in, and an actual WebSocket terminal. Confirm saved computers and their remembered session/tab selections. Resume a disposable independent session and check the same pane PID and a variable recorded before the update. A health response alone does not prove the terminal works.
5. Restore the usual startup policy after the checks pass. Browser sign-ins expire on restart; reload pages opened by an older frontend. Record the installed version, results and rollback location.

Independent tmux survival means its original server remains alive. It does not preserve a process through reboot, power loss or stopping that tmux server. Managed local work is expected to end during a Shellport restart.

## Roll back a failed upgrade

Stop the failed candidate and pause retries before switching anything. Preserve its logs and the current data privately. If the previous version supports the current data format, select that executable, reuse the same data directory and restart. Repeat login and terminal checks, including the original SSH identity and independent session.

If the upgrade migrated data into an incompatible format, executable-only rollback may not work. Follow the version's migration/rollback instructions and restore its matching pre-upgrade backup only after preserving the current state and agreeing to discard changes made since that backup. Do not use an older executable to rewrite newer data blindly. Before v1, compatibility between arbitrary versions is not guaranteed.

## Restore a private backup

Stop the app and automatic restarter. Move the current data aside without deleting it, then restore into an empty destination under the original account. Restore externally referenced SSH keys and the required operator configuration too. Prefer the original absolute paths; `keyFile`, tmux socket paths and service definitions may refer to them. Never overwrite a live tmux socket or blindly install a copied service over an unrelated service.

For another computer or directory, review those references and existing services before starting. Keep the original hostname and configure its exact allowed origin to reuse its passkeys. A different hostname requires separate passkey enrollment; password recovery remains available. Do not run `init` over restored data.

Check file ownership/modes, the SSH public-key fingerprint and backup integrity. Start a compatible executable and verify password/passkey login, saved computers, SSH host trust and real shell access. If the original independent or remote tmux server is still running, reconnect to its existing sessions. Restoring files cannot recreate shell processes lost in a reboot or stopped tmux server.

## Run the disposable rehearsal

After installing the build/test dependencies and running `make build`:

```sh
make test-recovery
```

The test is also included in `make test` and the existing Linux/macOS CI jobs. It starts actual server subprocesses, a private foreground tmux owner and a local SSH fixture. It creates its own passwords, SSH keys, synthetic passkey, data, operator configuration and loopback port. It installs no OS service and never reads an existing installation's credentials.

It checks executable replacement, a failed candidate and executable-only rollback, and restoration to the original fixture paths. Checks cover private-file hashes/modes, saved targets/selections, external SSH identity, signed passkey login, independent pane PIDs/variables, managed-session termination and fresh direct shells. Cleanup stops its own processes and removes its disposable files. The synthetic authenticator does not test a physical phone or password manager, and copying fixture service/proxy files does not test restoring an actual OS service or HTTPS proxy.

By default, two differently labeled binaries are built from the **same current source**. This qualifies the procedure, not compatibility between published releases. Once two verified native release binaries are available, repeat with:

```sh
SHELLPORT_REHEARSAL_FROM=/absolute/old-release/shellport \
SHELLPORT_REHEARSAL_TO=/absolute/candidate-release/shellport \
make test-recovery
```

Verify those binaries before running them. Both need the tested CLI, terminal/passkey APIs and tmux configuration support; incompatibilities should fail the rehearsal and require a migration plan. The files are copied into the fixture before execution. This command does not download, publish or deploy anything. Repeat against the actual installation's supervisor/proxy in a separately approved staging setup before claiming that hosting environment's update/rollback path has been verified.
