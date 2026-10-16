# Changelog

## [Unreleased]

## [1.0.0-beta.1] - 2026-10-16

Initial Shellport feature set.

- Browser terminal for phones and computers, with saved SSH targets and optional terminals on the hosting computer.
- Saved tmux sessions with independent shell tabs, resume across devices, renaming and explicit close/delete actions. Direct shells are also available from the same computer.
- Automatic reconnect to the selected saved shell, with explicit handling of expired sign-ins, credentials and changed SSH identities.
- Independent and managed local tmux lifetimes, password and passkey sign-in, and owner settings.
- Read-only local privilege diagnostics and an explicit account/restricted policy for new independent Linux tmux services. Existing services and saved sessions retain their policies; offline changes refuse to end saved work.
- Offline password recovery and installed-version reporting. Recovery preserves saved computers, SSH identities, passkeys and non-password configuration.
- Trusted HTTPS proxy setup through repeatable `init --trusted-proxy` flags or the offline `setup-proxy` command, without a shared proxy secret.
- Generic installation guidance, phone/desktop gallery, five platform archives, checksums and signatures for stable and prerelease downloads.
- Backup/restore and upgrade/rollback guidance with a disposable rehearsal covering external SSH keys, passkeys and tmux process survival.

### Compatibility

This is pre-v1 software; configuration, CLI and HTTP API compatibility are not yet guaranteed between releases. Back up the complete private data directory before upgrading.

- Live terminal connections use /api/terminals; tmux session and window management use their separate host-scoped endpoints. Pages open from an older build need a reload after upgrading.
- Running processes do not survive a computer reboot. Independent local tmux work survives Shellport restarts; managed local work ends when Shellport stops.
- Phones use the web interface. Native server archives target Linux AMD64, ARM64 and ARMv7, and macOS ARM64 and AMD64. Native validation on every target remains a release-readiness task.
