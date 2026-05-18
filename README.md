# sec-audit

Linux privacy and security auditor.
Run as root for full coverage.

## Install
**Arch Linux (AUR):**
```sh
yay -S sec-audit-git
```

**Any Linux — pre-built binary:**
```sh
curl -L https://github.com/ungaul/sec-audit/releases/latest/download/sec-audit-linux-x86_64 \
     -o sec-audit
sudo install -m755 sec-audit /usr/local/bin/sec-audit
```
Replace `linux-x86_64` with `linux-aarch64` on ARM.

### Alternatively, build from source:
```sh
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja -C build
sudo install -m755 build/sec-audit /usr/local/bin/sec-audit
```
Requires `cmake`, `ninja`, `g++ ≥ 11` (C++23).

## Usage

```bash
sec-audit              # full audit
sec-audit --check ssh  # single check
sec-audit --offline    # skip external IP lookup
```

## Checks

| Check | What it audits |
|---|---|
| `exposure` | External IP, ISP, geolocation, IPv6 direct reachability, location services (GeoClue2, GPS) |
| `telemetry` | Active connections to known tracking/analytics endpoints |
| `dns` | Resolver config, DNS-over-TLS, DNSSEC |
| `ports` | Listening ports, exposed services, loopback vs. wildcard |
| `firewall` | iptables / nftables / ufw / firewalld rules and IPv6 coverage |
| `ssh` | `sshd_config` — PasswordAuthentication, PermitRootLogin, ciphers, AllowUsers, etc. |
| `systemd` | Suspicious or telemetry-related services and timers |
| `kernel` | sysctl — ASLR, kptr_restrict, SYN cookies, BPF, ICMP redirects, core dumps |
| `filesystem` | SUID/SGID binaries, world-writable dirs, `/tmp` and `/proc` mount options |
| `users` | UID 0 accounts, empty passwords, sudoers NOPASSWD, shadow perms, password policy |
| `software` | Pending updates, AppArmor/SELinux, auditd, fail2ban, compiler access |
| `usb` | USBGuard policy, `usb_storage` module, Thunderbolt security level |
| `cron` | Cron file permissions, world-writable scripts, suspicious entries |
| `credentials` | Secrets and tokens in shell history and config files (redacted in output) |
| `processes` | Processes making external network connections from unexpected paths |