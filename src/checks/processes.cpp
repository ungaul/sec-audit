#include "types.hpp"
#include "util.hpp"
#include <filesystem>
#include <set>
#include <map>
#include <regex>
#include <dirent.h>
#include <fstream>
#include <unistd.h>
#include <pwd.h>

namespace fs = std::filesystem;

static std::string read_proc_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string read_proc_str(const std::string& path) {
    // cmdline uses null separators
    std::ifstream f(path);
    if (!f) return {};
    std::string s;
    std::getline(f, s, '\0');
    return s;
}

static std::map<long, std::string> build_inode_map() {
    std::map<long, std::string> inode_to_remote;

    auto parse = [&](const std::string& path, bool ipv6) {
        auto content = util::read_file(path);
        if (!content) return;
        for (const auto& line : util::split_lines(*content)) {
            std::istringstream iss(line);
            std::string sl, local, remote, state;
            std::string rest;
            iss >> sl >> local >> remote >> state;
            std::getline(iss, rest);

            // ESTABLISHED only
            if (state != "01") continue;

            auto rparts = util::split(remote, ':');
            if (rparts.size() != 2) continue;

            // Find inode (9th field)
            std::istringstream iss2(rest);
            std::string tx, tr, retr, uid, timeout, inode_s;
            iss2 >> tx >> tr >> retr >> uid >> timeout >> inode_s;
            if (inode_s.empty() || !std::isdigit(inode_s[0])) continue;
            long inode = std::stol(inode_s);

            std::string remote_str;
            if (!ipv6 && rparts[0].size() == 8) {
                unsigned int addr = std::stoul(rparts[0], nullptr, 16);
                remote_str = std::to_string(addr & 0xff) + "." +
                             std::to_string((addr >> 8) & 0xff) + "." +
                             std::to_string((addr >> 16) & 0xff) + "." +
                             std::to_string((addr >> 24) & 0xff);
            } else {
                remote_str = rparts[0]; // IPv6 simplified
            }
            int port = std::stoi(rparts[1], nullptr, 16);
            inode_to_remote[inode] = remote_str + ":" + std::to_string(port);
        }
    };

    parse("/proc/net/tcp",  false);
    parse("/proc/net/tcp6", true);
    return inode_to_remote;
}

static std::map<int, std::vector<std::string>> map_pid_to_connections(
    const std::map<long, std::string>& inode_map)
{
    std::map<int, std::vector<std::string>> pid_conns;
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return pid_conns;

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        if (!std::isdigit(entry->d_name[0])) continue;
        int pid = std::atoi(entry->d_name);
        if (pid <= 0) continue;

        std::string fd_dir = "/proc/" + std::to_string(pid) + "/fd";
        DIR* fds = opendir(fd_dir.c_str());
        if (!fds) continue;

        struct dirent* fd_e;
        while ((fd_e = readdir(fds)) != nullptr) {
            if (fd_e->d_name[0] == '.') continue;
            std::string fd_path = fd_dir + "/" + fd_e->d_name;
            char link_buf[256] = {};
            ssize_t len = readlink(fd_path.c_str(), link_buf, sizeof(link_buf) - 1);
            if (len <= 0) continue;
            std::string link(link_buf, len);
            if (link.rfind("socket:[", 0) != 0) continue;
            long inode = std::stol(link.substr(8, link.size() - 9));
            auto it = inode_map.find(inode);
            if (it != inode_map.end())
                pid_conns[pid].push_back(it->second);
        }
        closedir(fds);
    }
    closedir(proc_dir);
    return pid_conns;
}

// Standard binary locations — any exe rooted here is presumed legitimate
static bool is_standard_path(const std::string& exe) {
    if (exe.empty()) return false;
    static const std::vector<std::string> GOOD_PREFIXES = {
        "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/",
        "/opt/", "/app/", "/snap/", "/var/lib/flatpak/",
        "/home/", "/root/",
        "/proc/self/exe", // self-exec (common in Electron apps)
    };
    for (const auto& p : GOOD_PREFIXES)
        if (exe.rfind(p, 0) == 0) return true;
    return false;
}

// Paths that are outright suspicious for executables
static bool is_suspicious_path(const std::string& exe) {
    static const std::vector<std::string> BAD_PREFIXES = {
        "/tmp/", "/dev/shm/", "/run/user/", "/var/tmp/",
    };
    for (const auto& p : BAD_PREFIXES)
        if (exe.rfind(p, 0) == 0) return true;
    return false;
}

static bool is_shell(const std::string& name) {
    static const std::set<std::string> SHELLS = {
        "bash", "sh", "dash", "zsh", "fish", "ksh", "tcsh", "csh"
    };
    return SHELLS.count(name) > 0;
}

static bool is_loopback_only(const std::vector<std::string>& conns) {
    for (const auto& c : conns) {
        if (c.rfind("127.", 0) != 0 && c != "::1" && !c.empty())
            return false;
    }
    return true;
}

static std::string uid_to_name(const std::string& uid_str) {
    try {
        uid_t uid = std::stoul(uid_str);
        struct passwd* pw = getpwuid(uid);
        return pw ? pw->pw_name : uid_str;
    } catch (...) { return uid_str; }
}

CheckResult check_processes() {
    CheckResult result;
    result.name = "Processes Making Unexpected Network Connections";

    if (!util::is_root()) {
        result.findings.push_back({
            Severity::INFO,
            "Processes",
            "Limited visibility without root — only your own processes visible",
            "Run as root to inspect all process network connections"
        });
    }

    auto inode_map  = build_inode_map();
    auto pid_conns  = map_pid_to_connections(inode_map);

    if (pid_conns.empty()) {
        result.findings.push_back({
            Severity::INFO, "Processes",
            "No established TCP connections found in /proc/net/tcp", ""
        });
        return result;
    }

    std::set<std::string> reported; // key: name+uid to avoid duplicate reporting
    std::vector<std::string> normal_procs; // processes from standard paths — summarised at end

    for (const auto& [pid, conns] : pid_conns) {
        if (conns.empty()) continue;

        // Skip loopback-only connections — not an exposure
        if (is_loopback_only(conns)) continue;

        std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
        std::string name = util::trim(read_proc_file(comm_path));
        if (name.empty()) name = "(unknown)";

        // Read exe symlink
        std::string exe_path_link = "/proc/" + std::to_string(pid) + "/exe";
        char exe_buf[512] = {};
        ssize_t exe_len = readlink(exe_path_link.c_str(), exe_buf, sizeof(exe_buf) - 1);
        if (exe_len > 0) exe_buf[exe_len] = '\0';
        std::string exe(exe_len > 0 ? exe_buf : "");

        // Read cmdline
        std::string cmdline_raw = read_proc_str("/proc/" + std::to_string(pid) + "/cmdline");
        std::replace(cmdline_raw.begin(), cmdline_raw.end(), '\0', ' ');
        std::string cmdline = util::trim(cmdline_raw).substr(0, 100);

        // Read UID from /proc/<pid>/status
        std::string status = read_proc_file("/proc/" + std::to_string(pid) + "/status");
        std::string uid_str;
        std::regex uid_re(R"(^Uid:\s*(\d+))");
        for (const auto& line : util::split_lines(status)) {
            std::smatch m;
            if (std::regex_search(line, m, uid_re)) { uid_str = m[1].str(); break; }
        }
        std::string username = uid_to_name(uid_str);
        bool is_root_proc = (uid_str == "0");

        std::string key = name + ":" + uid_str;
        if (reported.count(key)) continue;
        reported.insert(key);

        std::string conn_str;
        for (size_t i = 0; i < std::min(conns.size(), size_t(3)); ++i) {
            if (i) conn_str += ", ";
            conn_str += conns[i];
        }
        if (conns.size() > 3)
            conn_str += " (+" + std::to_string(conns.size()-3) + " more)";

        bool exe_deleted = exe.find("(deleted)") != std::string::npos;

        // ── Deleted binary ───────────────────────────────────────────────────
        if (exe_deleted) {
            result.findings.push_back({
                Severity::HIGH,
                "Processes",
                "Process from deleted binary: " + name + " (PID " + std::to_string(pid) +
                    ", user: " + username + ")",
                "Binary removed from disk while process is running — possible rootkit/malware. "
                "Connections: " + conn_str
            });
            continue;
        }

        // ── Binary in /tmp, /dev/shm, etc. ──────────────────────────────────
        if (!exe.empty() && is_suspicious_path(exe)) {
            result.findings.push_back({
                Severity::CRITICAL,
                "Processes",
                "Process running from suspicious path: " + name + " [" + exe + "]",
                "Executables in /tmp or /dev/shm are a strong indicator of malware. "
                "Connections: " + conn_str
            });
            continue;
        }

        // ── Shell making external network connections ────────────────────────
        if (is_shell(name)) {
            result.findings.push_back({
                Severity::HIGH,
                "Processes",
                "Shell with active network connections: " + name +
                    " (PID " + std::to_string(pid) + ", user: " + username + ")",
                "A shell process should not normally hold network connections. "
                "cmd: " + cmdline + " | connections: " + conn_str
            });
            continue;
        }

        // ── Root process with binary outside standard paths ──────────────────
        if (is_root_proc && !exe.empty() && !is_standard_path(exe)) {
            result.findings.push_back({
                Severity::HIGH,
                "Processes",
                "Root process from non-standard path: " + name + " [" + exe + "]",
                "Connections: " + conn_str
            });
            continue;
        }

        // ── Non-standard binary path (any user) ─────────────────────────────
        if (!exe.empty() && !is_standard_path(exe)) {
            result.findings.push_back({
                Severity::MEDIUM,
                "Processes",
                "Process from unusual path: " + name + " [" + exe + "] (user: " + username + ")",
                "Connections: " + conn_str
            });
            continue;
        }

        // Everything else: standard path — collect for summary, don't spam findings
        normal_procs.push_back(name + "[" + username + "]");
    }

    if (!normal_procs.empty()) {
        std::string list;
        for (size_t i = 0; i < normal_procs.size(); ++i) {
            if (i) list += ", ";
            list += normal_procs[i];
        }
        result.findings.push_back({
            Severity::INFO,
            "Processes",
            std::to_string(normal_procs.size()) +
                " process(es) with external connections — all from standard paths",
            list
        });
    }

    return result;
}
