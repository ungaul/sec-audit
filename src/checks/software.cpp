#include "types.hpp"
#include "util.hpp"
#include <regex>
#include <filesystem>

namespace fs = std::filesystem;

static bool binary_exists(const std::string& name) {
    return !util::trim(util::exec("which " + name + " 2>/dev/null")).empty();
}

static bool service_active(const std::string& name) {
    return util::trim(util::exec("systemctl is-active " + name + " 2>/dev/null")) == "active";
}

static bool service_enabled(const std::string& name) {
    return util::trim(util::exec("systemctl is-enabled " + name + " 2>/dev/null")) == "enabled";
}

CheckResult check_software() {
    CheckResult result;
    result.name = "Software Security (Updates, MAC, Security Tools)";

    // ── Pending security updates ──────────────────────────────────────────────
    // Detect package manager and check for updates
    {
        if (binary_exists("pacman")) {
            // Arch Linux
            std::string updates = util::exec(
                "pacman -Qu 2>/dev/null | wc -l");
            int n = 0;
            try { n = std::stoi(util::trim(updates)); } catch (...) {}
            if (n > 0) {
                result.findings.push_back({Severity::MEDIUM, "Software",
                    std::to_string(n) + " package update(s) available",
                    "Run: sudo pacman -Syu  |  Check for security advisories: "
                    "https://security.archlinux.org"});
            } else {
                result.findings.push_back({Severity::INFO, "Software",
                    "System is up to date (pacman)", ""});
            }
        } else if (binary_exists("apt-get")) {
            // Debian / Ubuntu
            util::exec("apt-get update -qq 2>/dev/null");
            std::string out = util::exec(
                "apt-get -s upgrade 2>/dev/null | grep '^[0-9]' | head -1");
            if (out.find("0 upgraded") == std::string::npos && !out.empty()) {
                result.findings.push_back({Severity::MEDIUM, "Software",
                    "Pending package updates detected",
                    out + "  |  Run: sudo apt-get upgrade"});
            } else {
                result.findings.push_back({Severity::INFO, "Software",
                    "System is up to date (apt)", ""});
            }
        } else if (binary_exists("dnf")) {
            std::string out = util::exec("dnf check-update --quiet 2>/dev/null | wc -l");
            int n = 0;
            try { n = std::stoi(util::trim(out)); } catch (...) {}
            if (n > 0)
                result.findings.push_back({Severity::MEDIUM, "Software",
                    std::to_string(n) + " package update(s) available (dnf)",
                    "Run: sudo dnf upgrade"});
        } else {
            result.findings.push_back({Severity::INFO, "Software",
                "No known package manager detected — update check skipped", ""});
        }
    }

    // ── AppArmor ──────────────────────────────────────────────────────────────
    {
        bool aa_loaded = fs::exists("/sys/kernel/security/apparmor");
        if (aa_loaded) {
            std::string mode = util::trim(util::exec(
                "cat /sys/kernel/security/apparmor/profiles 2>/dev/null | "
                "grep -c '(enforce)' 2>/dev/null"));
            std::string complain = util::trim(util::exec(
                "cat /sys/kernel/security/apparmor/profiles 2>/dev/null | "
                "grep -c '(complain)' 2>/dev/null"));
            int enforcing = 0, complaining = 0;
            try { enforcing  = std::stoi(mode); } catch (...) {}
            try { complaining = std::stoi(complain); } catch (...) {}
            result.findings.push_back({Severity::INFO, "Software",
                "AppArmor active — " + std::to_string(enforcing) +
                " profile(s) enforcing, " + std::to_string(complaining) + " complaining",
                ""});
        } else if (fs::exists("/sys/kernel/security/selinux")) {
            // SELinux
            std::string mode = util::trim(util::exec("getenforce 2>/dev/null"));
            if (mode == "Enforcing") {
                result.findings.push_back({Severity::INFO, "Software",
                    "SELinux is Enforcing", ""});
            } else if (mode == "Permissive") {
                result.findings.push_back({Severity::MEDIUM, "Software",
                    "SELinux is Permissive — MAC not enforcing",
                    "Run: setenforce 1  and set SELINUX=enforcing in /etc/selinux/config"});
            } else {
                result.findings.push_back({Severity::HIGH, "Software",
                    "SELinux is Disabled",
                    "Mandatory access control is off. Enable in /etc/selinux/config"});
            }
        } else {
            result.findings.push_back({Severity::MEDIUM, "Software",
                "No mandatory access control (AppArmor / SELinux) detected",
                "MAC provides defence-in-depth against exploits. Consider enabling AppArmor."});
        }
    }

    // ── auditd ────────────────────────────────────────────────────────────────
    {
        bool running = service_active("auditd");
        if (!running) {
            result.findings.push_back({Severity::LOW, "Software",
                "auditd is not running",
                "Linux Audit daemon provides syscall-level logging. "
                "Install and enable: sudo pacman -S audit && systemctl enable --now auditd"});
        } else {
            result.findings.push_back({Severity::INFO, "Software",
                "auditd is running — syscall audit logging active", ""});
        }
    }

    // ── fail2ban / sshguard ───────────────────────────────────────────────────
    {
        bool f2b  = service_active("fail2ban") || binary_exists("fail2ban-client");
        bool sshg = service_active("sshguard") || binary_exists("sshguard");
        if (!f2b && !sshg) {
            result.findings.push_back({Severity::LOW, "Software",
                "No brute-force protection (fail2ban / sshguard) detected",
                "Protects SSH and other services from credential stuffing. "
                "Install: sudo pacman -S fail2ban"});
        } else {
            std::string which = f2b ? "fail2ban" : "sshguard";
            result.findings.push_back({Severity::INFO, "Software",
                which + " is active — brute-force protection enabled", ""});
        }
    }

    // ── Compiler availability ────────────────────────────────────────────────
    {
        std::vector<std::string> compilers;
        for (const auto& c : {"gcc", "cc", "g++", "clang", "clang++"}) {
            if (binary_exists(c)) compilers.push_back(c);
        }
        if (!compilers.empty()) {
            std::string list;
            for (size_t i = 0; i < compilers.size(); ++i) {
                if (i) list += ", ";
                list += compilers[i];
            }
            result.findings.push_back({Severity::LOW, "Software",
                "Compiler(s) installed and accessible: " + list,
                "Compilers let any user compile and run exploit code locally. "
                "Remove if not needed for development: sudo pacman -Rs gcc"});
        }
    }

    // ── Security / integrity tools ────────────────────────────────────────────
    {
        struct { const char* name; const char* install; } tools[] = {
            {"rkhunter",  "rkhunter"},
            {"chkrootkit","chkrootkit"},
            {"aide",      "aide"},
            {"tripwire",  "tripwire"},
            {"clamav",    "clamav"},
        };
        std::vector<std::string> present, absent;
        for (const auto& t : tools) {
            if (binary_exists(t.name)) present.push_back(t.name);
            else absent.push_back(t.name);
        }
        if (!absent.empty()) {
            std::string list;
            for (size_t i = 0; i < absent.size(); ++i) {
                if (i) list += ", ";
                list += absent[i];
            }
            result.findings.push_back({Severity::INFO, "Software",
                "Security tools not installed: " + list,
                "Consider installing: rkhunter (rootkit scanner), "
                "aide (file integrity monitoring), clamav (malware scanner)"});
        }
        if (!present.empty()) {
            std::string list;
            for (size_t i = 0; i < present.size(); ++i) {
                if (i) list += ", ";
                list += present[i];
            }
            result.findings.push_back({Severity::INFO, "Software",
                "Security tools present: " + list, ""});
        }
    }

    // ── Automatic security updates ────────────────────────────────────────────
    {
        bool unattended = service_enabled("unattended-upgrades") ||
                          fs::exists("/etc/apt/apt.conf.d/20auto-upgrades") ||
                          service_enabled("paccache.timer") ||
                          fs::exists("/etc/pacman.d/hooks/");
        if (!unattended) {
            result.findings.push_back({Severity::LOW, "Software",
                "No automatic update mechanism detected",
                "Consider enabling automatic security updates"});
        }
    }

    return result;
}
