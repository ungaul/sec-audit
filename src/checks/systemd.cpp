#include "types.hpp"
#include "util.hpp"
#include <regex>
#include <set>
#include <filesystem>
#include <sstream>
#include <algorithm>

namespace fs = std::filesystem;

// Patterns in unit names that suggest telemetry/tracking
static const std::vector<std::string> SUSPICIOUS_UNIT_PATTERNS = {
    "telemetry", "tracking", "beacon", "analytics", "spyware", "keylog",
    "monitor", "snoop", "capture", "spy", "record",
    // Specific known bad services
    "fwupd-refresh",  // unnecessary on desktop
    "apport",         // Ubuntu crash reporter
    "whoopsie",       // Ubuntu error reporting
    "kerneloops",     // kernel oops reporter
    "ubuntu-report",
    "popularity-contest",
    "abrtd",          // Fedora automatic bug reporting
    "abrt-oops",
    "abrt-xorg",
    "abrt-journal-core",
    "samba-ad-dc",    // unexpected on desktop
};

// Services that run as root with network access but are unexpected
static const std::vector<std::string> NETWORK_SUSPICIOUS = {
    "ncat", "netcat", "nc.service", "socat",
    "msfconsole", "metasploit",
};

struct UnitInfo {
    std::string name;
    std::string load;
    std::string active;
    std::string sub;
    std::string description;
};

static std::vector<UnitInfo> list_units(const std::string& type) {
    std::vector<UnitInfo> units;
    std::string cmd = "systemctl list-units --type=" + type + " --all --no-legend --no-pager";
    auto lines = util::split_lines(util::exec(cmd));
    for (const auto& line : lines) {
        std::istringstream iss(line);
        std::string name, load, active, sub;
        iss >> name >> load >> active >> sub;
        std::string desc;
        std::getline(iss, desc);
        desc = util::trim(desc);
        // Strip leading '●' bullet if present
        if (!name.empty() && (unsigned char)name[0] > 127) name = name.substr(3);
        if (!name.empty()) units.push_back({name, load, active, sub, desc});
    }
    return units;
}

static std::vector<UnitInfo> list_timers() {
    std::vector<UnitInfo> units;
    std::string cmd = "systemctl list-timers --all --no-legend --no-pager";
    auto lines = util::split_lines(util::exec(cmd));
    for (const auto& line : lines) {
        // Format: NEXT LEFT LAST PASSED UNIT ACTIVATES
        std::istringstream iss(line);
        std::string t1, t2, t3, t4, t5, unit;
        // Skip date/time columns (variable count), find the unit column
        std::vector<std::string> tokens;
        std::string tok;
        while (iss >> tok) tokens.push_back(tok);
        // Unit name is usually 5th or 6th token and ends with .timer
        for (const auto& t : tokens) {
            if (t.size() > 6 && t.rfind(".timer") == t.size() - 6) {
                units.push_back({t, "", "active", "waiting", ""});
                break;
            }
        }
    }
    return units;
}

static bool has_suspicious_pattern(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (const auto& pat : SUSPICIOUS_UNIT_PATTERNS) {
        if (lower.find(pat) != std::string::npos) return true;
    }
    return false;
}

static std::string get_unit_exec(const std::string& unit) {
    return util::trim(util::exec("systemctl show -p ExecStart --value " + unit));
}

CheckResult check_systemd() {
    CheckResult result;
    result.name = "Suspicious systemd Services & Timers";

    // Check services
    auto services = list_units("service");
    for (const auto& svc : services) {
        if (svc.active != "active" && svc.load != "loaded") continue;
        if (!has_suspicious_pattern(svc.name)) continue;

        std::string exec_cmd = get_unit_exec(svc.name);
        Severity sev = Severity::MEDIUM;

        // Known telemetry reporters are HIGH
        if (svc.name.find("telemetry") != std::string::npos ||
            svc.name.find("whoopsie") != std::string::npos ||
            svc.name.find("ubuntu-report") != std::string::npos ||
            svc.name.find("popularity-contest") != std::string::npos ||
            svc.name.find("apport") != std::string::npos) {
            sev = Severity::HIGH;
        }

        result.findings.push_back({
            sev,
            "systemd",
            "Suspicious service: " + svc.name,
            "State: " + svc.active + "/" + svc.sub +
            (exec_cmd.empty() ? "" : " | ExecStart: " + exec_cmd.substr(0, 80))
        });
    }

    // Check timers
    auto timers = list_timers();
    for (const auto& t : timers) {
        if (!has_suspicious_pattern(t.name)) continue;
        std::string svc_name = t.name.substr(0, t.name.size() - 6) + ".service";
        result.findings.push_back({
            Severity::MEDIUM,
            "systemd",
            "Suspicious timer: " + t.name,
            "Associated service: " + svc_name
        });
    }

    // Check for units loaded from unexpected locations
    auto unit_files = util::split_lines(util::exec(
        "systemctl list-unit-files --type=service --no-legend --no-pager --state=enabled,static"));
    for (const auto& line : unit_files) {
        std::istringstream iss(line);
        std::string name, state, preset;
        iss >> name >> state;
        if (name.empty()) continue;

        // Check if unit file is in a non-standard location
        std::string path = util::trim(util::exec("systemctl show -p FragmentPath --value " + name));
        if (!path.empty() &&
            path.find("/usr/lib/systemd/") == std::string::npos &&
            path.find("/lib/systemd/") == std::string::npos &&
            path.find("/etc/systemd/") == std::string::npos) {
            result.findings.push_back({
                Severity::HIGH,
                "systemd",
                "Service unit from unexpected path: " + name,
                "Path: " + path
            });
        }
    }

    // Check for world-writable unit files
    for (const auto& dir : {"/etc/systemd/system", "/usr/local/lib/systemd/system"}) {
        if (!fs::exists(dir)) continue;
        try {
            for (const auto& entry : fs::recursive_directory_iterator(
                    dir, fs::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;
                auto perms = entry.status().permissions();
                if ((perms & fs::perms::others_write) != fs::perms::none) {
                    result.findings.push_back({
                        Severity::CRITICAL,
                        "systemd",
                        "World-writable systemd unit file: " + entry.path().string(),
                        "Any user can modify this unit — privilege escalation risk"
                    });
                }
            }
        } catch (...) {}
    }

    if (result.findings.empty()) {
        // No suspicious findings — just report count
        result.findings.push_back({
            Severity::INFO,
            "systemd",
            "No suspicious services or timers detected (" +
                std::to_string(services.size()) + " services checked)",
            ""
        });
    }

    return result;
}
