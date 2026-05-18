#include "types.hpp"
#include "util.hpp"
#include <filesystem>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <set>
#include <fstream>

namespace fs = std::filesystem;

// Known-good SUID/SGID binaries on a typical Linux desktop
// Canonical paths for known-good SUID/SGID binaries.
// On systems where /bin → /usr/bin, canonical() resolves to /usr/bin/*.
static const std::set<std::string> EXPECTED_SUID = {
    // Core auth / privilege
    "/usr/bin/su", "/usr/bin/sudo", "/usr/bin/sudoedit",
    "/usr/bin/newgrp", "/usr/bin/sg",
    "/usr/bin/passwd", "/usr/bin/gpasswd", "/usr/bin/chage",
    "/usr/bin/chsh", "/usr/bin/chfn",
    "/usr/bin/expiry", "/usr/bin/unix_chkpwd",
    "/usr/bin/newuidmap", "/usr/bin/newgidmap",
    // Mounting
    "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/fusermount", "/usr/bin/fusermount3",
    "/usr/bin/mount.cifs", "/usr/bin/mount.smb3",
    // Network / ping
    "/usr/bin/ping", "/usr/bin/ping6",
    // Scheduling
    "/usr/bin/at", "/usr/bin/crontab",
    // Messaging
    "/usr/bin/write", "/usr/bin/wall",
    // PolicyKit
    "/usr/bin/pkexec",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    // D-Bus
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/dbus-daemon-launch-helper",
    // SSH
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/ssh/ssh-keysign",
    // Xorg
    "/usr/bin/Xorg", "/usr/bin/X",
    "/usr/lib/Xorg.wrap",
    // Kerberos
    "/usr/bin/ksu",
    // System helpers
    "/usr/sbin/pam_timestamp_check", "/usr/sbin/suexec",
    "/usr/sbin/unix_chkpwd",
    // Group management
    "/usr/bin/groupmems",
    // utempter (SGID tty)
    "/usr/lib/utempter/utempter",
    // Electron sandboxes (chrome-sandbox is SUID on many systems)
    // — flagged individually since version dirs change
    // libgtop helper
    "/usr/lib/libgtop/libgtop_server2",
};


static bool is_known_good_suid(const std::string& path, const std::string& canon_path) {
    if (EXPECTED_SUID.count(path) || EXPECTED_SUID.count(canon_path)) return true;
    // Version-agnostic patterns
    auto basename = [](const std::string& p) {
        size_t pos = p.rfind('/');
        return pos == std::string::npos ? p : p.substr(pos + 1);
    };
    std::string name = basename(path);
    // chrome-sandbox is SUID for Electron/Chromium namespace isolation
    if (name == "chrome-sandbox") return true;
    // Debug build-id files are hardlinks to real binaries — skip entirely
    if (path.find("/debug/.build-id/") != std::string::npos) return true;
    if (path.find("/debug/usr/") != std::string::npos) return true;
    return false;
}

static void scan_suid(const std::string& dir, std::vector<Finding>& findings,
                      std::set<ino_t>& seen_inodes) {
    // Skip symlink dirs to avoid scanning /bin → /usr/bin twice
    if (fs::is_symlink(dir)) return;

    try {
        for (const auto& entry : fs::recursive_directory_iterator(
                dir, fs::directory_options::skip_permission_denied)) {
            if (!entry.is_regular_file()) continue;
            auto perms = entry.status().permissions();
            bool suid = (perms & fs::perms::set_uid) != fs::perms::none;
            bool sgid = (perms & fs::perms::set_gid) != fs::perms::none;
            if (!suid && !sgid) continue;

            std::string path = entry.path().string();
            std::error_code ec;
            auto canon = fs::canonical(entry.path(), ec);
            std::string canon_path = ec ? path : canon.string();

            // Check known-good BEFORE inode dedup so we don't shadow the real path
            if (is_known_good_suid(path, canon_path)) {
                struct stat st{};
                if (stat(entry.path().c_str(), &st) == 0)
                    seen_inodes.insert(st.st_ino);
                continue;
            }

            struct stat st{};
            if (stat(entry.path().c_str(), &st) != 0) continue;
            if (!seen_inodes.insert(st.st_ino).second) continue;

            Severity sev = Severity::LOW;
            if (suid && st.st_uid == 0) sev = Severity::HIGH;
            else if (suid)              sev = Severity::MEDIUM;

            findings.push_back({
                sev,
                "Filesystem",
                std::string(suid ? "SUID" : "SGID") + " binary: " + path,
                "Not in known-good list — verify this needs elevated privileges: stat " + path
            });
        }
    } catch (...) {}
}

static void check_world_writable(std::vector<Finding>& findings) {
    // Scan common directories for world-writable dirs without sticky bit
    static const std::vector<std::string> SCAN_DIRS = {
        "/tmp", "/var/tmp", "/usr", "/etc", "/bin", "/sbin"
    };
    for (const auto& base : SCAN_DIRS) {
        if (!fs::exists(base)) continue;
        try {
            for (const auto& entry : fs::recursive_directory_iterator(
                    base, fs::directory_options::skip_permission_denied)) {
                if (!entry.is_directory()) continue;
                auto perms = entry.status().permissions();
                bool world_write = (perms & fs::perms::others_write) != fs::perms::none;
                bool sticky      = (perms & fs::perms::sticky_bit)   != fs::perms::none;
                if (world_write && !sticky) {
                    findings.push_back({
                        Severity::HIGH,
                        "Filesystem",
                        "World-writable directory without sticky bit: " + entry.path().string(),
                        "Any user can delete/rename files here. Fix: chmod +t " + entry.path().string()
                    });
                }
            }
        } catch (...) {}
    }
}

static std::string get_mount_opts(const std::string& mount_point) {
    auto mounts = util::read_file("/proc/mounts");
    if (!mounts) return {};
    for (const auto& line : util::split_lines(*mounts)) {
        auto parts = util::split(line, ' ');
        if (parts.size() >= 4 && parts[1] == mount_point)
            return parts[3];
    }
    return {};
}

static bool opt_present(const std::string& opts, const std::string& opt) {
    for (const auto& o : util::split(opts, ','))
        if (util::trim(o) == opt) return true;
    return false;
}

CheckResult check_filesystem() {
    CheckResult result;
    result.name = "Filesystem Security (SUID, World-Writable, Mount Options)";

    // ── SUID / SGID binaries ─────────────────────────────────────────────────
    // Inode set is local — no stale state if check runs more than once
    std::set<ino_t> seen_inodes;
    for (const auto& dir : {"/usr/bin", "/usr/sbin", "/usr/lib",
                             "/usr/libexec", "/bin", "/sbin"}) {
        scan_suid(dir, result.findings, seen_inodes);
    }

    // ── World-writable directories without sticky bit ────────────────────────
    check_world_writable(result.findings);

    // ── /tmp security ────────────────────────────────────────────────────────
    {
        std::string opts = get_mount_opts("/tmp");
        bool on_separate = !opts.empty();
        if (!on_separate) {
            result.findings.push_back({
                Severity::LOW,
                "Filesystem",
                "/tmp is not on a separate partition",
                "Mounting /tmp separately with noexec,nosuid,nodev prevents many local exploits"
            });
        } else {
            bool noexec = opt_present(opts, "noexec");
            bool nosuid = opt_present(opts, "nosuid");
            bool nodev  = opt_present(opts, "nodev");
            if (!noexec)
                result.findings.push_back({Severity::MEDIUM, "Filesystem",
                    "/tmp mounted without noexec",
                    "Attackers can drop and execute binaries in /tmp. Add noexec to /tmp mount options."});
            if (!nosuid)
                result.findings.push_back({Severity::MEDIUM, "Filesystem",
                    "/tmp mounted without nosuid",
                    "SUID binaries in /tmp can escalate privileges. Add nosuid."});
            if (!nodev)
                result.findings.push_back({Severity::LOW, "Filesystem",
                    "/tmp mounted without nodev", "Add nodev to /tmp mount options."});
            if (noexec && nosuid && nodev)
                result.findings.push_back({Severity::INFO, "Filesystem",
                    "/tmp mounted with noexec,nosuid,nodev", ""});
        }
    }

    // ── /home and /var mount options ─────────────────────────────────────────
    for (const auto& mp : {"/home", "/var"}) {
        std::string opts = get_mount_opts(mp);
        if (opts.empty()) continue; // not a separate partition, skip
        if (!opt_present(opts, "nosuid"))
            result.findings.push_back({Severity::LOW, "Filesystem",
                std::string(mp) + " mounted without nosuid",
                "Prevents SUID abuse from user files."});
    }

    // ── /proc hidepid ────────────────────────────────────────────────────────
    {
        std::string opts = get_mount_opts("/proc");
        if (!opts.empty() && opts.find("hidepid") == std::string::npos) {
            result.findings.push_back({Severity::LOW, "Filesystem",
                "/proc mounted without hidepid",
                "Any user can read /proc/<pid>/ of other users' processes. "
                "Add hidepid=2 to /proc mount options in /etc/fstab."});
        }
    }

    // ── Unowned files in key directories ─────────────────────────────────────
    if (util::is_root()) {
        std::string out = util::exec(
            "find /usr /etc -xdev -nouser -o -nogroup 2>/dev/null | head -20");
        for (const auto& path : util::split_lines(out)) {
            if (!path.empty())
                result.findings.push_back({Severity::MEDIUM, "Filesystem",
                    "File with no valid owner: " + path,
                    "Files without a valid UID/GID owner can indicate tampering or leftover packages"});
        }
    }

    return result;
}
