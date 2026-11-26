%global debug_package %{nil}

Name:           sshcast-operator
Version:        0.1.0
Release:        1%{?dist}
Summary:        Operator Console & User Key Signing Authority for Sshcast Swarm
License:        MIT OR Apache-2.0
URL:            https://github.com/sshcast/sshcast-operator
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang
BuildRequires:  systemd-rpm-macros
Requires:       systemd

%description
Sshcast Operator Console (sshcast-operator) provides web-based user key
signing (/console/) for autonomous Sshcast coordinator server swarms.
Coordinator servers only need the operator's Ed25519 public key
(trusted_operator_pubkeys) in /etc/sshcast/server.toml and continue operating
autonomously without any database dependency.

%prep
%autosetup -n %{name}-%{version}

%build
go build -mod=readonly -trimpath -ldflags="-s -w" -o sshcast-operator ./cmd/sshcast-operator

%check
go test -mod=readonly ./...

%install
install -D -m 0755 sshcast-operator %{buildroot}%{_bindir}/sshcast-operator
install -D -m 0644 systemd/sshcast-operator.service %{buildroot}%{_unitdir}/sshcast-operator.service
install -D -m 0644 systemd/sshcast-operator.socket %{buildroot}%{_unitdir}/sshcast-operator.socket
install -D -m 0644 systemd/sshcast-operator-tcp@.socket %{buildroot}%{_unitdir}/sshcast-operator-tcp@.socket
install -D -m 0644 systemd/operator.toml %{buildroot}%{_sysconfdir}/sshcast/operator.toml
install -D -m 0600 systemd/sshcast-operator.sysconfig %{buildroot}%{_sysconfdir}/sysconfig/sshcast-operator

%post
%{_bindir}/sshcast-operator --init-sysconfig %{_sysconfdir}/sysconfig/sshcast-operator >/dev/null 2>&1 || :
%systemd_post sshcast-operator.socket sshcast-operator.service

%preun
%systemd_preun sshcast-operator.socket sshcast-operator.service

%postun
%systemd_postun_with_restart sshcast-operator.socket sshcast-operator.service

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md
%{_bindir}/sshcast-operator
%{_unitdir}/sshcast-operator.service
%{_unitdir}/sshcast-operator.socket
%{_unitdir}/sshcast-operator-tcp@.socket
%dir %attr(0755,root,root) %{_sysconfdir}/sshcast
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sshcast/operator.toml
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/sshcast-operator

%changelog
* Tue Nov 10 2026 Paul Komkoff <i@stingr.net> - 0.1.0-1
- Initial Fedora RPM package for sshcast-operator
