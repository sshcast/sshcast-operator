#!/bin/sh
set -e

case "${1:-}" in
    0|remove|deconfigure)
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            systemctl --no-reload disable --now sshcast-operator.socket sshcast-operator.service >/dev/null 2>&1 || true
        fi
        if command -v deb-systemd-helper >/dev/null 2>&1; then
            deb-systemd-helper mask sshcast-operator.socket sshcast-operator.service >/dev/null 2>&1 || true
        fi
        ;;
esac
