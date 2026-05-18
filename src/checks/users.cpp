#include "types.hpp"
#include "util.hpp"
#include <pwd.h>
#include <shadow.h>
#include <grp.h>
#include <sys/stat.h>
#include <regex>
#include <set>

static bool has_login_shell(const std::string& shell) {
    static const std::set<std::string> NOLOGIN = {
        "/sbin/nologin", "/usr/sbin/nologin",
        "/bin/false", "/usr/bin/false",
        "/bin/nologin",
    };
    return NOLOGIN.find(shell) == NOLOGIN.end() && !shell.empty();
}

CheckResult check_users() {
    CheckResult result;
    result.name = "User Account Security";

    // ── UID 0 accounts (other than root) ─────────────────────────────────────
    {
        std::vector<std::string> uid0;
        setpwent();
        struct passwd* pw;
        while ((pw = getpwent()) != nullptr) {
            if (pw->pw_uid == 0 && std::string(pw->pw_name) != "root")
                uid0.push_back(pw->pw_name);
        }
        endpwent();
        for (const auto& u : uid0)
            result.findings.push_back({
                Severity::CRITICAL, "Users",
                "Non-root account with UID 0: " + u,
                "Any UID 0 account has full root privileges. Remove or investigate immediately."
            });
    }

    // ── Accounts with empty passwords ────────────────────────────────────────
    if (util::is_root()) {
        setspent();
        struct spwd* sp;
        while ((sp = getspent()) != nullptr) {
            std::string pw_hash = sp->sp_pwdp ? sp->sp_pwdp : "";
            // Empty or explicitly disabled ("")
            if (pw_hash.empty()) {
                result.findings.push_back({
                    Severity::CRITICAL, "Users",
                    "Account with empty password: " + std::string(sp->sp_namp),
                    "Anyone can log in as this user without a password. Lock: passwd -l " +
                    std::string(sp->sp_namp)
                });
            }
        }
        endspent();
    } else {
        result.findings.push_back({
            Severity::INFO, "Users",
            "Shadow password check skipped — requires root",
            ""
        });
    }

    // ── /etc/shadow permissions ───────────────────────────────────────────────
    {
        struct stat st{};
        if (stat("/etc/shadow", &st) == 0) {
            mode_t m = st.st_mode & 0777;
            if (m & 0004) { // world-readable
                char buf[8];
                snprintf(buf, sizeof(buf), "%04o", m);
                result.findings.push_back({
                    Severity::CRITICAL, "Users",
                    "/etc/shadow is world-readable (mode " + std::string(buf) + ")",
                    "Shadow file contains password hashes. Run: chmod 640 /etc/shadow"
                });
            } else if (m & 0040) { // group-readable — warn but less severe
                char buf[8];
                snprintf(buf, sizeof(buf), "%04o", m);
                result.findings.push_back({
                    Severity::LOW, "Users",
                    "/etc/shadow is group-readable (mode " + std::string(buf) + ")",
                    "Typically only root (or shadow group) should read /etc/shadow"
                });
            } else {
                result.findings.push_back({
                    Severity::INFO, "Users", "/etc/shadow permissions are correct", ""
                });
            }
        }
    }

    // ── /etc/passwd world-writable ────────────────────────────────────────────
    {
        struct stat st{};
        if (stat("/etc/passwd", &st) == 0 && (st.st_mode & 0002)) {
            result.findings.push_back({
                Severity::CRITICAL, "Users",
                "/etc/passwd is world-writable",
                "Any user can modify the password database. Fix: chmod 644 /etc/passwd"
            });
        }
    }

    // ── Sudoers: NOPASSWD and dangerous rules ─────────────────────────────────
    {
        std::vector<std::string> sudoers_files = {"/etc/sudoers"};
        for (const auto& f : util::glob_files("/etc/sudoers.d/*"))
            sudoers_files.push_back(f);

        std::regex nopasswd_re(R"(\bNOPASSWD\b)", std::regex_constants::icase);
        std::regex all_all_re(R"(\(ALL\s*:\s*ALL\)\s*ALL)");
        std::regex wildcard_re(R"(\*|/\*$)");

        for (const auto& path : sudoers_files) {
            auto content = util::read_file(path);
            if (!content) continue;
            auto lines = util::split_lines(*content);
            for (size_t i = 0; i < lines.size(); ++i) {
                const auto& line = lines[i];
                if (line.empty() || line[0] == '#') continue;

                std::smatch m;
                if (std::regex_search(line, m, nopasswd_re)) {
                    result.findings.push_back({
                        Severity::HIGH, "Users",
                        "NOPASSWD sudo rule in " + path + ":" + std::to_string(i+1),
                        util::trim(line)
                    });
                } else if (std::regex_search(line, m, all_all_re)) {
                    result.findings.push_back({
                        Severity::MEDIUM, "Users",
                        "Broad sudo rule (ALL:ALL) in " + path + ":" + std::to_string(i+1),
                        util::trim(line)
                    });
                }
            }
        }
    }

    // ── Password policy (login.defs) ──────────────────────────────────────────
    {
        auto content = util::read_file("/etc/login.defs");
        if (content) {
            std::regex max_re(R"(^\s*PASS_MAX_DAYS\s+(\d+))");
            std::regex min_re(R"(^\s*PASS_MIN_LEN\s+(\d+))");
            std::regex warn_re(R"(^\s*PASS_WARN_AGE\s+(\d+))");
            std::regex hash_re(R"(^\s*ENCRYPT_METHOD\s+(\S+))");

            for (const auto& line : util::split_lines(*content)) {
                std::smatch m;
                if (std::regex_search(line, m, max_re)) {
                    int days = std::stoi(m[1].str());
                    if (days > 90 || days == 99999)
                        result.findings.push_back({Severity::LOW, "Users",
                            "PASS_MAX_DAYS=" + m[1].str() + " — passwords never/rarely expire",
                            "Consider setting PASS_MAX_DAYS to 90 in /etc/login.defs"});
                }
                if (std::regex_search(line, m, min_re)) {
                    int len = std::stoi(m[1].str());
                    if (len < 12)
                        result.findings.push_back({Severity::LOW, "Users",
                            "PASS_MIN_LEN=" + m[1].str() + " — minimum password length is low",
                            "Consider setting PASS_MIN_LEN to at least 12"});
                }
                if (std::regex_search(line, m, hash_re)) {
                    std::string method = m[1].str();
                    std::transform(method.begin(), method.end(), method.begin(), ::toupper);
                    if (method == "MD5" || method == "DES" || method == "SHA256") {
                        result.findings.push_back({Severity::HIGH, "Users",
                            "Weak password hash algorithm: " + m[1].str(),
                            "Use ENCRYPT_METHOD YESCRYPT or SHA512 in /etc/login.defs"});
                    } else {
                        result.findings.push_back({Severity::INFO, "Users",
                            "Password hash algorithm: " + m[1].str(), ""});
                    }
                }
            }
        }
    }

    // ── Default umask ─────────────────────────────────────────────────────────
    {
        // Check /etc/profile, /etc/login.defs, /etc/bashrc for umask
        std::vector<std::string> umask_sources = {
            "/etc/profile", "/etc/bashrc", "/etc/bash.bashrc",
            "/etc/login.defs", "/etc/pam.d/common-session"
        };
        std::regex umask_re(R"(umask\s+([0-7]{3,4}))", std::regex_constants::icase);
        bool found_umask = false;
        for (const auto& path : umask_sources) {
            auto c = util::read_file(path);
            if (!c) continue;
            for (const auto& line : util::split_lines(*c)) {
                if (line.empty() || line[0] == '#') continue;
                std::smatch m;
                if (std::regex_search(line, m, umask_re)) {
                    std::string mask = m[1].str();
                    // umask 022 = files get 644, dirs 755 — acceptable
                    // umask 027 = files get 640, dirs 750 — good
                    // umask 002 = world can write — bad
                    if (mask == "002" || mask == "0002") {
                        result.findings.push_back({Severity::MEDIUM, "Users",
                            "Permissive default umask " + mask + " in " + path,
                            "umask 002 makes new files group-writable. Prefer 022 or 027."});
                    } else {
                        result.findings.push_back({Severity::INFO, "Users",
                            "Default umask: " + mask + " (in " + path + ")", ""});
                    }
                    found_umask = true;
                    break;
                }
            }
            if (found_umask) break;
        }
    }

    // ── Accounts with login shell but locked password ─────────────────────────
    // (potential for SSH key login even with locked password)
    if (util::is_root()) {
        setpwent();
        struct passwd* pw;
        while ((pw = getpwent()) != nullptr) {
            if (!has_login_shell(pw->pw_shell)) continue;
            if (pw->pw_uid < 1000 && pw->pw_uid != 0) continue; // skip system accounts
            // Check if SSH authorized_keys exists for this user
            std::string ak = std::string(pw->pw_dir) + "/.ssh/authorized_keys";
            if (util::file_readable(ak)) {
                // Check if password is locked in shadow
                struct spwd* sp = getspnam(pw->pw_name);
                if (sp) {
                    std::string hash = sp->sp_pwdp ? sp->sp_pwdp : "";
                    if (!hash.empty() && hash[0] == '!') {
                        result.findings.push_back({Severity::INFO, "Users",
                            "Locked account with SSH authorized_keys: " + std::string(pw->pw_name),
                            "Password login is disabled but SSH key login may still work — "
                            "verify this is intentional"});
                    }
                }
            }
        }
        endpwent();
    }

    return result;
}
