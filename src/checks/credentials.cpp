#include "types.hpp"
#include "util.hpp"
#include <regex>
#include <set>
#include <filesystem>
#include <pwd.h>
#include <sys/stat.h>

namespace fs = std::filesystem;

struct SecretPattern {
    std::string name;
    std::regex re;
    Severity severity;
};

static std::vector<SecretPattern> build_patterns() {
    using R = std::regex;
    using F = std::regex_constants::syntax_option_type;
    constexpr F I = std::regex_constants::icase;
    return {
        {"AWS Access Key",       R(R"(AKIA[0-9A-Z]{16})"),                                                   Severity::CRITICAL},
        {"AWS Secret Key",       R(R"(aws.{0,20}secret.{0,20}['""][0-9a-zA-Z/+]{40}['"])", I),              Severity::CRITICAL},
        // Require quotes so we don't catch URL query params like ?api_key=xxx
        {"Generic API Key",      R(R"((api[_-]?key|apikey)\s*[=:]\s*['"][a-zA-Z0-9\-_]{20,}['"])", I),    Severity::HIGH},
        {"Generic Secret",       R(R"((secret|password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"])", I),         Severity::HIGH},
        {"Private Key Header",   R(R"(-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),               Severity::CRITICAL},
        {"GitHub Token",         R(R"(gh[ps]_[a-zA-Z0-9]{36})"),                                            Severity::CRITICAL},
        {"GitHub OAuth Token",   R(R"(gho_[a-zA-Z0-9]{36})"),                                               Severity::CRITICAL},
        {"Slack Token",          R(R"(xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32})"),          Severity::CRITICAL},
        {"Slack Webhook",        R(R"(hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+)"), Severity::HIGH},
        {"Google API Key",       R(R"(AIza[0-9A-Za-z\-_]{35})"),                                            Severity::HIGH},
        {"JWT Token",            R(R"(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)"),            Severity::MEDIUM},
        {"SSH Private Key path", R(R"(IdentityFile\s+(.+\.pem|.+_rsa|.+_ecdsa|.+_ed25519))"),              Severity::LOW},
        {"Bearer Token",         R(R"(bearer\s+[a-zA-Z0-9\-_.]{20,})", I),                                  Severity::HIGH},
        {"Database URL",         R(R"((postgres|mysql|mongodb|redis)://[^@\s]+:[^@\s]+@)"),                  Severity::CRITICAL},
    };
}

// Returns home directories to audit. When root, returns ALL users' homes.
static std::vector<std::pair<std::string,std::string>> get_user_homes() {
    std::vector<std::pair<std::string,std::string>> homes; // {home_dir, username}
    std::set<std::string> seen;

    auto add = [&](const std::string& dir, const std::string& user) {
        if (dir.empty() || dir == "/" || !util::file_readable(dir)) return;
        if (seen.insert(dir).second) homes.push_back({dir, user});
    };

    if (util::is_root()) {
        // Enumerate every real user account
        setpwent();
        struct passwd* pw;
        while ((pw = getpwent()) != nullptr) {
            if (!pw->pw_dir) continue;
            // Skip system accounts with no real home
            std::string dir = pw->pw_dir;
            if (dir == "/" || dir == "/var/empty" || dir == "/dev/null") continue;
            // Skip service accounts (UID < 1000 and not root), except root itself
            if (pw->pw_uid > 0 && pw->pw_uid < 1000) continue;
            add(dir, pw->pw_name ? pw->pw_name : "");
        }
        endpwent();
    } else {
        const char* home = getenv("HOME");
        const char* user = getenv("USER");
        if (home) add(home, user ? user : "");
    }

    return homes;
}

static std::vector<std::string> history_files_for_home(const std::string& home) {
    std::vector<std::string> result;
    static const std::vector<std::string> HIST_PATHS = {
        ".bash_history",
        ".zsh_history",
        ".zhistory",
        ".sh_history",
        ".fish_history",
        ".local/share/fish/fish_history",
        ".config/fish/fish_history",
        ".history",
        ".ksh_history",
    };
    for (const auto& h : HIST_PATHS) {
        std::string path = home + "/" + h;
        if (util::file_readable(path)) result.push_back(path);
    }
    return result;
}

static std::vector<std::string> config_files_for_home(const std::string& home) {
    std::vector<std::string> result;
    auto add = [&](const std::string& rel) {
        std::string path = home + "/" + rel;
        if (util::file_readable(path)) result.push_back(path);
    };

    add(".bashrc"); add(".bash_profile"); add(".zshrc"); add(".zprofile");
    add(".profile"); add(".config/fish/config.fish");
    add(".env"); add(".envrc");
    add(".netrc"); add(".npmrc"); add(".pypirc"); add(".pip/pip.conf");
    add(".aws/credentials"); add(".aws/config");
    add(".docker/config.json");
    add(".ssh/config");
    add(".gitconfig"); add(".git-credentials");
    add(".config/gh/config.yml");
    add(".kube/config");
    add(".config/gcloud/credentials.db");
    add(".config/gcloud/application_default_credentials.json");
    add(".password-store/.gpg-id"); // pass store
    add(".vault-token");
    add(".terraform.d/credentials.tfrc.json");

    // Scan .ssh/ for private key files
    for (const auto& kf : util::glob_files(home + "/.ssh/*")) {
        if (!util::file_readable(kf)) continue;
        auto content = util::read_file(kf);
        if (content && content->find("PRIVATE KEY") != std::string::npos)
            result.push_back(kf);
    }

    return result;
}

static void scan_content(const std::string& path, const std::string& content,
                          const std::vector<SecretPattern>& patterns,
                          std::vector<Finding>& findings) {
    auto lines = util::split_lines(content);
    std::set<std::string> seen_titles;

    for (size_t i = 0; i < lines.size(); ++i) {
        for (const auto& pat : patterns) {
            std::smatch m;
            if (std::regex_search(lines[i], m, pat.re)) {
                std::string title = pat.name + " in " + path;
                if (seen_titles.count(title)) continue;
                seen_titles.insert(title);
                std::string snippet = util::trim(lines[i]).substr(0, 80);
                std::string redacted = std::regex_replace(snippet, pat.re,
                                                          "[" + pat.name + " REDACTED]");
                findings.push_back({
                    pat.severity,
                    "Credentials",
                    pat.name + " found in: " + path,
                    "Line ~" + std::to_string(i+1) + ": " + redacted
                });
            }
        }
    }
}

static void check_key_permissions(const std::string& path, std::vector<Finding>& findings) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return;
    mode_t perms = st.st_mode & 0777;
    if (perms & 0044) {
        char perm_str[16];
        snprintf(perm_str, sizeof(perm_str), "%04o", perms);
        findings.push_back({
            Severity::HIGH,
            "Credentials",
            "Private key world/group-readable: " + path,
            "Permissions: " + std::string(perm_str) + " (should be 0600). Run: chmod 600 " + path
        });
    }
}

CheckResult check_credentials() {
    CheckResult result;
    result.name = "Credential & Token Leaks in Shell History / Config Files";

    auto patterns = build_patterns();
    auto user_homes = get_user_homes();

    if (!util::is_root()) {
        result.findings.push_back({
            Severity::INFO,
            "Credentials",
            "Scanning current user only — run as root to scan all accounts",
            ""
        });
    }

    if (util::is_root() && user_homes.size() > 1) {
        result.findings.push_back({
            Severity::INFO,
            "Credentials",
            "Scanning " + std::to_string(user_homes.size()) + " user home directories",
            [&]() {
                std::string s;
                for (const auto& [dir, user] : user_homes) {
                    if (!s.empty()) s += ", ";
                    s += user.empty() ? dir : user + "(" + dir + ")";
                }
                return s;
            }()
        });
    }

    for (const auto& [home, username] : user_homes) {
        // Shell histories
        for (const auto& path : history_files_for_home(home)) {
            auto content = util::read_file(path);
            if (!content) continue;
            scan_content(path, *content, patterns, result.findings);
        }

        // Config files
        for (const auto& path : config_files_for_home(home)) {
            auto content = util::read_file(path);
            if (!content) continue;
            bool is_ssh_key = path.find("/.ssh/") != std::string::npos &&
                              content->find("PRIVATE KEY") != std::string::npos;
            if (is_ssh_key) {
                // ~/.ssh/ private key files: check permissions only, don't pattern-scan
                // Finding a key header here is expected — what matters is mode 0600
                check_key_permissions(path, result.findings);
                continue;
            }
            if (content->find("PRIVATE KEY") != std::string::npos)
                check_key_permissions(path, result.findings);
            scan_content(path, *content, patterns, result.findings);
        }

        // .git-credentials plaintext store
        std::string gc = home + "/.git-credentials";
        if (util::file_readable(gc)) {
            result.findings.push_back({
                Severity::HIGH,
                "Credentials",
                "Plaintext git credentials: " + gc,
                "git credential.helper=store saves passwords in plaintext. Use libsecret or pass."
            });
        }

        // .netrc world-readable
        std::string netrc = home + "/.netrc";
        if (util::file_readable(netrc)) {
            struct stat st{};
            if (stat(netrc.c_str(), &st) == 0 && (st.st_mode & 044)) {
                result.findings.push_back({
                    Severity::HIGH,
                    "Credentials",
                    "~/.netrc is group/world readable: " + netrc,
                    "May contain plaintext FTP/HTTP credentials. Run: chmod 600 " + netrc
                });
            }
        }
    }

    // System-wide
    for (const auto& path : {"/etc/environment", "/etc/openvpn/credentials",
                              "/etc/wpa_supplicant/wpa_supplicant.conf"}) {
        if (!util::file_readable(path)) continue;
        auto content = util::read_file(path);
        if (content) scan_content(path, *content, patterns, result.findings);
    }

    return result;
}
