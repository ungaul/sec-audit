#include "types.hpp"
#include "util.hpp"
#include <filesystem>
#include <sys/stat.h>
#include <pwd.h>
#include <regex>

namespace fs = std::filesystem;

static std::string owner_name(const std::string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return "?";
    struct passwd* pw = getpwuid(st.st_uid);
    return pw ? pw->pw_name : std::to_string(st.st_uid);
}

static bool is_world_writable(const std::string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0 && (st.st_mode & 0002);
}

static bool is_root_owned(const std::string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0 && st.st_uid == 0;
}

// Scan a cron file for suspicious patterns
static void scan_cron_content(const std::string& path,
                               const std::string& content,
                               std::vector<Finding>& findings) {
    // Suspicious: scripts run from /tmp, curl|bash, wget|sh, pipe to shell
    std::vector<std::pair<std::regex, std::string>> suspicious = {
        {std::regex(R"(/tmp/[^\s]+\.(sh|py|pl|rb|bin))"),       "Executes script from /tmp"},
        {std::regex(R"(curl.+\|\s*(ba)?sh)"),                    "curl piped to shell (remote code exec)"},
        {std::regex(R"(wget.+\|\s*(ba)?sh)"),                    "wget piped to shell (remote code exec)"},
        {std::regex(R"(curl.+-o\s+/tmp/)"),                      "Downloads file to /tmp"},
        {std::regex(R"(\bchmod\b.*\+s\b)"),                      "Sets SUID bit in cron job"},
        {std::regex(R"(\bnc\b.*-e\b|\bncat\b.*-e\b)"),          "Reverse shell via netcat"},
        {std::regex(R"(python.*-c.*socket)"),                     "Potential Python reverse shell"},
        {std::regex(R"(base64\s+-d.*\|\s*(ba)?sh)"),             "Base64-decoded script piped to shell"},
    };

    auto lines = util::split_lines(content);
    for (size_t i = 0; i < lines.size(); ++i) {
        const auto& line = lines[i];
        if (line.empty() || line[0] == '#') continue;
        // Skip variable assignments (e.g. MAILTO=, SHELL=)
        if (line.find('=') != std::string::npos &&
            line.find('/') == std::string::npos) continue;

        for (const auto& [re, desc] : suspicious) {
            std::smatch m;
            if (std::regex_search(line, m, re)) {
                findings.push_back({Severity::HIGH, "Cron",
                    desc + " in " + path + ":" + std::to_string(i+1),
                    util::trim(line).substr(0, 120)});
                break;
            }
        }
    }
}

static void audit_cron_file(const std::string& path,
                             std::vector<Finding>& findings) {
    if (!util::file_readable(path)) return;

    // Check permissions
    if (is_world_writable(path)) {
        findings.push_back({Severity::CRITICAL, "Cron",
            "World-writable cron file: " + path,
            "Any user can modify this cron job. Fix: chmod 644 " + path});
    }

    // Check owner (cron files in system dirs should be root-owned)
    if (path.rfind("/etc/", 0) == 0 && !is_root_owned(path)) {
        findings.push_back({Severity::HIGH, "Cron",
            "System cron file not owned by root: " + path,
            "Owner: " + owner_name(path)});
    }

    // Scan content
    auto content = util::read_file(path);
    if (content) {
        scan_cron_content(path, *content, findings);

        // Check if scripts referenced in cron file are world-writable
        std::regex script_re(R"((?:^|\s)(/(?:usr/|home/|etc/|opt/|bin/|sbin/)\S+\.(?:sh|py|pl|rb)))");
        for (const auto& line : util::split_lines(*content)) {
            if (line.empty() || line[0] == '#') continue;
            std::smatch m;
            std::string tmp = line;
            while (std::regex_search(tmp, m, script_re)) {
                std::string script = m[1].str();
                if (is_world_writable(script)) {
                    findings.push_back({Severity::CRITICAL, "Cron",
                        "Cron job runs world-writable script: " + script,
                        "Referenced in " + path + ". Any user can modify this script."});
                } else if (!is_root_owned(script) && path.rfind("/etc/", 0) == 0) {
                    findings.push_back({Severity::MEDIUM, "Cron",
                        "System cron runs non-root-owned script: " + script,
                        "Owner: " + owner_name(script) + " (referenced in " + path + ")"});
                }
                tmp = m.suffix().str();
            }
        }
    }
}

CheckResult check_cron() {
    CheckResult result;
    result.name = "Scheduled Tasks (cron / systemd timers)";

    int files_checked = 0;

    // System crontab
    audit_cron_file("/etc/crontab", result.findings);
    if (util::file_readable("/etc/crontab")) ++files_checked;

    // /etc/cron.d/
    for (const auto& f : util::glob_files("/etc/cron.d/*")) {
        audit_cron_file(f, result.findings);
        ++files_checked;
    }

    // /etc/cron.{daily,weekly,monthly,hourly}/
    for (const auto& dir : {"/etc/cron.daily", "/etc/cron.weekly",
                             "/etc/cron.monthly", "/etc/cron.hourly"}) {
        for (const auto& f : util::glob_files(std::string(dir) + "/*")) {
            audit_cron_file(f, result.findings);
            ++files_checked;
        }
    }

    // User crontabs in /var/spool/cron/
    if (util::is_root()) {
        for (const auto& f : util::glob_files("/var/spool/cron/*")) {
            audit_cron_file(f, result.findings);
            ++files_checked;
        }
        // Also /var/spool/cron/crontabs/ (Debian path)
        for (const auto& f : util::glob_files("/var/spool/cron/crontabs/*")) {
            audit_cron_file(f, result.findings);
            ++files_checked;
        }
    }

    // Check /etc/cron.allow and /etc/cron.deny for overly permissive config
    {
        bool has_allow = util::file_readable("/etc/cron.allow");
        bool has_deny  = util::file_readable("/etc/cron.deny");
        if (!has_allow && !has_deny) {
            result.findings.push_back({Severity::LOW, "Cron",
                "No /etc/cron.allow or /etc/cron.deny — any user can schedule cron jobs",
                "Create /etc/cron.allow with allowed usernames to restrict cron access"});
        } else if (has_deny) {
            auto deny = util::read_file("/etc/cron.deny");
            if (deny && util::trim(*deny).empty()) {
                result.findings.push_back({Severity::LOW, "Cron",
                    "/etc/cron.deny exists but is empty — all users can use cron", ""});
            }
        }
    }

    if (files_checked == 0) {
        result.findings.push_back({Severity::INFO, "Cron",
            "No cron files found", ""});
    } else {
        // Only add summary if no issues found
        bool has_issues = false;
        for (const auto& f : result.findings)
            if (f.severity >= Severity::MEDIUM) { has_issues = true; break; }
        if (!has_issues) {
            result.findings.push_back({Severity::INFO, "Cron",
                std::to_string(files_checked) + " cron file(s) checked — no issues found",
                ""});
        }
    }

    return result;
}
