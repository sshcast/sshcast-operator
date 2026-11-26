# Security Policy

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues, pull requests, or discussions.

Instead, report suspected vulnerabilities privately using one of the following channels:

- **Email**: [security@sshcast.net](mailto:security@sshcast.net)
- **GitHub Security Advisories**: [https://github.com/sshcast/sshcast-operator/security/advisories/new](https://github.com/sshcast/sshcast-operator/security/advisories/new)

When submitting a report, please include:

- A description of the vulnerability and its potential impact.
- Affected `sshcast-operator` version(s) or commit SHA.
- Configuration and deployment context (systemd unit configuration, reverse proxy setup, etc.).
- Step-by-step reproduction instructions or a minimal proof of concept.

We will acknowledge receipt promptly and work with you on a coordinated remediation and disclosure timeline before public announcement.

## Operator Signing Key Security

`sshcast-operator` acts as the offline/out-of-band user certificate signing authority for a swarm of autonomous `sshcast-server` coordinators:

- **Root of Trust (`SSHCAST_OPERATOR_KEY`)**: The Ed25519 operator private key (`sc_op_priv_<64-hex>`) signs `UserCert` (`sc_cert_...`) tokens binding user root public keys (`sc_pub_...`) to user IDs and optional expiration timestamps.
- **Swarm-Wide Authority**: Every `sshcast-server` configured with `trusted_operator_pubkeys = ["sc_op_pub_..."]` verifies `UserCert` signatures locally without contacting `sshcast-operator` or a central database. Anyone who obtains `SSHCAST_OPERATOR_KEY` can mint valid `UserCert` tokens accepted across the entire swarm.
- **Storage & File Permissions**:
  - Store `SSHCAST_OPERATOR_KEY` in `/etc/sysconfig/sshcast-operator` with `0600` (`root:root`) permissions (initialized via `sshcast-operator --init-sysconfig /etc/sysconfig/sshcast-operator` or `sshcast-operator --keygen`).
  - Under systemd, `sshcast-operator.service` reads `/etc/sysconfig/sshcast-operator` via `EnvironmentFile=` while dropping privileges (`DynamicUser=yes`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `ConfigurationDirectory=sshcast::ro`).
- **Lifetime & Key Rotation**:
  - Prefer bounded certificate lifetimes (`default_expires_days = 365` by default; avoid `0` / non-expiring certificates unless operationally required).
  - Because coordinators verify certificates autonomously, revoking a compromised operator key requires removing its `sc_op_pub_...` entry from `trusted_operator_pubkeys` on every `sshcast-server` node and issuing new `UserCert` tokens from a newly generated operator key.

## `/console/` Isolation Model

The operator web console (`/console/`) is designed as an isolated administrative endpoint behind a TLS-terminating reverse proxy:

- **Local-Only Socket Binding**:
  - `sshcast-operator.socket` binds a Unix domain socket at `/run/sshcast-operator/operator.sock` inside `RuntimeDirectory=sshcast-operator` (`SocketMode=0666` so an unprivileged reverse proxy such as Nginx can connect).
  - `sshcast-operator-tcp@.socket` binds strictly to loopback (`127.0.0.1:%i`).
  - Do not expose `sshcast-operator` directly on public network interfaces; terminate HTTPS/TLS and enforce additional network controls (VPN, private management VLAN, IP allowlisting, or mutual TLS) at the reverse proxy.
  - Note: Because `/run/sshcast-operator/operator.sock` is `0666` by default for reverse-proxy interoperability, ensure untrusted local users do not have access to the host socket or loopback port.
- **Authentication & Session Handling**:
  - All signing routes (`/console/`, `/console/sign`, `/console/api/sign`) require an authenticated session configured via `/etc/sshcast/operator.toml` (`[[users]]` / `[user_passwords]`). Only `/healthz` (and `<base_path>/healthz`) is unauthenticated.
  - Always configure bcrypt password hashes generated with `sshcast-operator --hash-password` rather than plain SHA-256 hashes.
  - Authenticated sessions use HMAC-SHA256 signed cookies (`sshcast_operator_session`) with `HttpOnly` and `SameSite=Lax` attributes, a 12-hour expiration window, and an ephemeral per-process random salt mixed with the operator key (sessions are invalidated on service restart).
  - Responses include `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`.

## Verifying Releases and Build Provenance

Before deploying prebuilt binaries, source archives, or RPM packages from GitHub Releases:

1. **SHA256 Checksum Verification**:
   Download the release artifact along with its checksum manifest (for example `SHA256SUMS`) and verify integrity locally:
   ```bash
   sha256sum -c SHA256SUMS --ignore-missing
   ```

2. **GitHub Build Provenance Attestation**:
   Verify that release artifacts were built by the official GitHub Actions workflow in `sshcast/sshcast-operator` using the GitHub CLI:
   ```bash
   gh attestation verify <artifact-file> --repo sshcast/sshcast-operator
   ```

3. **Source / RPM Verification**:
   When building from source, verify the Git tag/commit and build with read-only module verification (`go build -mod=readonly -trimpath ...`), or inspect and build directly from `sshcast-operator.spec`.
