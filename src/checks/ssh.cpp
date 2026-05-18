#include "types.hpp"
#include "util.hpp"
#include <regex>
#include <map>

// Parse sshd_config into a key→value map (last value wins, case-insensitive keys)
static std::map<std::string, std::string> parse_sshd_config(const std::string& content) {
    std::map<std::string, std::string> cfg;
    for (const auto& line : util::split_lines(content)) {
        std::string trimmed = util::trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;
        size_t sp = trimmed.find_first_of(" \t");
        if (sp == std::string::npos) continue;
        std::string key = trimmed.substr(0, sp);
        std::string val = util::trim(trimmed.substr(sp));
        // Strip inline comments
        size_t hash = val.find('#');
        if (hash != std::string::npos) val = util::trim(val.substr(0, hash));
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        cfg[key] = val;
    }
    return cfg;
}

static std::string get(const std::map<std::string, std::string>& cfg,
                       const std::string& key, const std::string& def = "") {
    auto it = cfg.find(key);
    return it != cfg.end() ? it->second : def;
}

static bool sshd_running() {
    std::string out = util::exec("systemctl is-active sshd ssh 2>/dev/null");
    return out.find("active") != std::string::npos;
}

CheckResult check_ssh() {
    CheckResult result;
    result.name = "SSH Server Hardening";

    // Only relevant if sshd is running
    if (!sshd_running()) {
        result.findings.push_back({
            Severity::INFO,
            "SSH",
            "sshd is not running — check skipped",
            ""
        });
        return result;
    }

    // Find sshd_config
    std::vector<std::string> config_paths = {
        "/etc/ssh/sshd_config",
        "/etc/sshd_config",
    };
    // Include drop-in files
    for (const auto& f : util::glob_files("/etc/ssh/sshd_config.d/*.conf")) {
        config_paths.push_back(f);
    }

    std::string combined_config;
    std::string primary_path;
    for (const auto& path : config_paths) {
        auto content = util::read_file(path);
        if (content) {
            if (primary_path.empty()) primary_path = path;
            combined_config += *content + "\n";
        }
    }

    if (combined_config.empty()) {
        result.findings.push_back({
            Severity::MEDIUM,
            "SSH",
            "Cannot read /etc/ssh/sshd_config",
            "Run as root for complete SSH audit"
        });
        return result;
    }

    auto cfg = parse_sshd_config(combined_config);

    // ── Port ──────────────────────────────────────────────────────────────────
    std::string port = get(cfg, "port", "22");
    if (port == "22") {
        result.findings.push_back({
            Severity::LOW,
            "SSH",
            "SSH running on default port 22",
            "Non-default port reduces automated scan noise, though not a security control"
        });
    } else {
        result.findings.push_back({
            Severity::INFO,
            "SSH",
            "SSH on non-default port: " + port,
            ""
        });
    }

    // ── PermitRootLogin ───────────────────────────────────────────────────────
    std::string root_login = get(cfg, "permitrootlogin", "prohibit-password");
    std::transform(root_login.begin(), root_login.end(), root_login.begin(), ::tolower);
    if (root_login == "yes") {
        result.findings.push_back({
            Severity::CRITICAL,
            "SSH",
            "PermitRootLogin yes — root can log in directly over SSH",
            "Set PermitRootLogin no in /etc/ssh/sshd_config"
        });
    } else if (root_login == "prohibit-password" || root_login == "without-password") {
        result.findings.push_back({
            Severity::LOW,
            "SSH",
            "PermitRootLogin prohibit-password (key-only root login allowed)",
            "Prefer PermitRootLogin no and use sudo instead"
        });
    } else {
        result.findings.push_back({
            Severity::INFO,
            "SSH",
            "PermitRootLogin " + root_login,
            ""
        });
    }

    // ── PasswordAuthentication ────────────────────────────────────────────────
    std::string pwd_auth = get(cfg, "passwordauthentication", "yes");
    std::transform(pwd_auth.begin(), pwd_auth.end(), pwd_auth.begin(), ::tolower);
    if (pwd_auth != "no") {
        result.findings.push_back({
            Severity::HIGH,
            "SSH",
            "PasswordAuthentication yes — brute-force attacks are possible",
            "Set PasswordAuthentication no and use public key authentication only"
        });
    } else {
        result.findings.push_back({
            Severity::INFO,
            "SSH",
            "PasswordAuthentication no (keys only) — good",
            ""
        });
    }

    // ── PubkeyAuthentication ──────────────────────────────────────────────────
    std::string pubkey = get(cfg, "pubkeyauthentication", "yes");
    std::transform(pubkey.begin(), pubkey.end(), pubkey.begin(), ::tolower);
    if (pubkey == "no") {
        result.findings.push_back({
            Severity::HIGH,
            "SSH",
            "PubkeyAuthentication no — public key login disabled",
            ""
        });
    }

    // ── MaxAuthTries ──────────────────────────────────────────────────────────
    std::string max_tries = get(cfg, "maxauthtries", "6");
    try {
        int n = std::stoi(max_tries);
        if (n > 3) {
            result.findings.push_back({
                Severity::MEDIUM,
                "SSH",
                "MaxAuthTries " + max_tries + " — consider reducing to 3",
                "High MaxAuthTries gives attackers more password attempts per connection"
            });
        } else {
            result.findings.push_back({Severity::INFO, "SSH", "MaxAuthTries " + max_tries, ""});
        }
    } catch (...) {}

    // ── PermitEmptyPasswords ──────────────────────────────────────────────────
    std::string empty_pwd = get(cfg, "permitemptypasswords", "no");
    std::transform(empty_pwd.begin(), empty_pwd.end(), empty_pwd.begin(), ::tolower);
    if (empty_pwd == "yes") {
        result.findings.push_back({
            Severity::CRITICAL,
            "SSH",
            "PermitEmptyPasswords yes — accounts with blank passwords can log in",
            "Set PermitEmptyPasswords no immediately"
        });
    }

    // ── X11Forwarding ─────────────────────────────────────────────────────────
    std::string x11 = get(cfg, "x11forwarding", "no");
    std::transform(x11.begin(), x11.end(), x11.begin(), ::tolower);
    if (x11 == "yes") {
        result.findings.push_back({
            Severity::MEDIUM,
            "SSH",
            "X11Forwarding yes — X11 sessions can be hijacked by remote host",
            "Set X11Forwarding no unless you specifically need remote X11 apps"
        });
    }

    // ── AllowTcpForwarding ────────────────────────────────────────────────────
    std::string tcp_fwd = get(cfg, "allowtcpforwarding", "yes");
    std::transform(tcp_fwd.begin(), tcp_fwd.end(), tcp_fwd.begin(), ::tolower);
    if (tcp_fwd == "yes") {
        result.findings.push_back({
            Severity::LOW,
            "SSH",
            "AllowTcpForwarding yes — users can tunnel arbitrary TCP connections",
            "Set AllowTcpForwarding no if port forwarding is not required"
        });
    }

    // ── UsePAM ────────────────────────────────────────────────────────────────
    std::string pam = get(cfg, "usepam", "yes");
    std::transform(pam.begin(), pam.end(), pam.begin(), ::tolower);
    if (pam == "no" && pwd_auth != "no") {
        result.findings.push_back({
            Severity::MEDIUM,
            "SSH",
            "UsePAM no with PasswordAuthentication enabled — PAM account checks bypassed",
            ""
        });
    }

    // ── LoginGraceTime ────────────────────────────────────────────────────────
    std::string grace = get(cfg, "logingracetime", "120");
    // strip trailing 's' or 'm'
    std::string grace_num = grace;
    if (!grace_num.empty() && !std::isdigit(grace_num.back()))
        grace_num.pop_back();
    try {
        int n = std::stoi(grace_num);
        if (n > 30) {
            result.findings.push_back({
                Severity::LOW,
                "SSH",
                "LoginGraceTime " + grace + " — reduce to 20-30s",
                "Longer grace times allow connection slot exhaustion attacks"
            });
        }
    } catch (...) {}

    // ── AllowUsers / AllowGroups (good if set) ────────────────────────────────
    std::string allow_users  = get(cfg, "allowusers");
    std::string allow_groups = get(cfg, "allowgroups");
    if (allow_users.empty() && allow_groups.empty()) {
        result.findings.push_back({
            Severity::LOW,
            "SSH",
            "No AllowUsers or AllowGroups — any system account can attempt SSH login",
            "Consider setting AllowUsers or AllowGroups to restrict access"
        });
    } else {
        result.findings.push_back({
            Severity::INFO,
            "SSH",
            "SSH access restricted by AllowUsers/AllowGroups",
            "AllowUsers=" + allow_users + "  AllowGroups=" + allow_groups
        });
    }

    // ── Ciphers / MACs (check for weak ones) ──────────────────────────────────
    std::string ciphers = get(cfg, "ciphers");
    if (!ciphers.empty()) {
        bool weak = ciphers.find("arcfour") != std::string::npos ||
                    ciphers.find("3des") != std::string::npos ||
                    ciphers.find("des") != std::string::npos ||
                    ciphers.find("blowfish") != std::string::npos ||
                    ciphers.find("cast128") != std::string::npos;
        if (weak) {
            result.findings.push_back({
                Severity::HIGH,
                "SSH",
                "Weak ciphers configured: " + ciphers.substr(0, 80),
                "Remove arcfour, 3des-*, blowfish-*, cast128-* from Ciphers"
            });
        }
    }

    return result;
}
