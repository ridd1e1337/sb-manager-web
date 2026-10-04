# Changelog

## Unreleased

## 0.1.0-alpha.26.1

- Migrate repository, installation and update URLs to ridd1e1337 on GitHub.
- Update the Go module path and build metadata for the new repository owner.

- Rework the WebUI around five task-oriented workspaces, a persistent navigation model, progressive node creation, explicit batch controls, human-readable task states and responsive mobile layouts.
- Add capability-gated remote Agent self-updates with per-server controls, gray batch rollout, atomic binary replacement, supervisor restart and heartbeat confirmation.
- Resume requeued local tasks after controller restarts, record their running timestamps, preserve the authenticated audit actor, and make local HTTPS status checks work with panel certificates.
- Build GitHub Release artifacts through the shared Makefile so both the WebUI and Agent receive the tagged version.
- Fix `systemd` status 203/EXEC by making the program directory traversable and verifying execution as the unprivileged service user before startup.
- Stop reusing stale ACME contact emails; public-IP issuance now registers without optional contact by default.
- Make automatic ACME setup transactional so registration/issuance failures do not modify the active panel configuration.
- Normalize ACME contact emails from interactive terminals before account registration.
- Require HTTPS for controller installs and make automatic public-IPv4 ACME the default certificate choice.
- Add an interactive `sb-web` management menu and safe Web-only uninstall, while keeping sb-manager data and the separate `sb` command untouched.
- Add panel TLS setup flows (self-signed IP SAN, ACME HTTP-01/DNS-01 and existing certificates), renewal scheduling, SSH install summary, and repeatable administrator account guidance.
- Let the Web installer bootstrap a missing sb-manager from its independent upstream installer, and avoid writing OpenRC scripts into Debian's SysV compatibility directory.
- Add optional controller-issued Agent mTLS certificates with automatic rotation, while retaining Ed25519 request signatures.
- Add state-file digest drift protection, task cancel/retry/requeue-on-restart, gray batch strategies and role-based users.
- Add dedicated server/node detail pages, node editor and user/permission page.
- Make installer binary replacement atomic and restore the previous binary when a post-install step fails.
- Add the embedded Go WebUI with Argon2id login, sessions and CSRF protection.
- Add the fixed sb-manager CLI runner, local task execution and node/system management actions.
- Add SQLite server/task/audit storage with WAL mode, single-use Agent enrollment and signed Agent task delivery.
- Add server inventory, batch actions, BBR/Hysteria2 tuning, core, backup, health and safe repair controls.
- Add systemd/OpenRC services, isolated install smoke coverage and static amd64/arm64/armv7 builds.
