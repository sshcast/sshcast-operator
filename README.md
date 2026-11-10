# sshcast-operator (`stingr.net/go/sshcast-operator`)

Operator Console & User Key Signing Authority for autonomous Sshcast coordinator swarms.

## Overview

`sshcast-operator` allows an operator to authorize users across an entire swarm of `sshcast-server` coordinators without requiring central database access from coordinator nodes or manual per-user edits in `/etc/sshcast/server.toml`:

1. **Operator Key (`SSHCAST_OPERATOR_KEY`)**: Stored in `/etc/sysconfig/sshcast-operator` (`sc_op_priv_<64-hex>`).
2. **Coordinator Trust (`trusted_operator_pubkeys`)**: Each `sshcast-server` node configures `trusted_operator_pubkeys = ["sc_op_pub_<64-hex>"]` in `/etc/sshcast/server.toml`.
3. **Web Console (`/console/`)**: Served behind Nginx via systemd socket activation (`/run/sshcast/operator.sock`), authenticated against user/password hashes in `/etc/sshcast/operator.toml`.
4. **Signing a User Key**: Paste a user's `sc_pub_...` key into `/console/` to mint an `sc_cert_<base64>` certificate token. The user imports it once with:
   ```bash
   sshcast-client import-cert --cert sc_cert_...
   ```
   All existing and future `NodeGrant`s minted by that user carry the `UserCert` and are verified autonomously by every coordinator in the swarm.

## Quick Setup

1. **Generate or inspect the Operator Keypair**:
   ```bash
   sshcast-operator --keygen
   # Or inspect the active public key from /etc/sysconfig/sshcast-operator:
   sudo sshcast-operator --print-pubkey
   ```

2. **Add an Admin User to `/etc/sshcast/operator.toml`**:
   ```bash
   sshcast-operator --hash-password 'your-password'
   ```
   Add to `/etc/sshcast/operator.toml`:
   ```toml
   [[users]]
   username = "admin"
   password_hash = "$2a$10$..."
   ```

3. **Enable the Socket Listener**:
   ```bash
   sudo systemctl enable --now sshcast-operator.socket
   ```

4. **Nginx Configuration (`/console/`)**:
   ```nginx
   location /console/ {
       proxy_pass http://unix:/run/sshcast/operator.sock;
       proxy_set_header Host $host;
       proxy_set_header X-Real-IP $remote_addr;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;
   }
   ```
