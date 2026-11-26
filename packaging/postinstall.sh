#!/bin/sh
set -e

/usr/bin/sshcast-operator --init-sysconfig /etc/sysconfig/sshcast-operator >/dev/null 2>&1 || true

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

if command -v deb-systemd-helper >/dev/null 2>&1; then
    deb-systemd-helper unmask sshcast-operator.socket sshcast-operator.service >/dev/null 2>&1 || true
    if deb-systemd-helper --quiet was-enabled sshcast-operator.socket >/dev/null 2>&1; then
        deb-systemd-helper enable sshcast-operator.socket >/dev/null 2>&1 || true
    else
        deb-systemd-helper update-state sshcast-operator.socket >/dev/null 2>&1 || true
    fi
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet sshcast-operator.service; then
        systemctl try-restart sshcast-operator.service >/dev/null 2>&1 || true
    fi
fi
