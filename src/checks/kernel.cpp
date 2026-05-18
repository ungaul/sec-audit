#include "types.hpp"
#include "util.hpp"
#include <fstream>

static std::string sysctl_get(const std::string& key) {
    // Read directly from /proc/sys to avoid needing sysctl binary
    std::string path = "/proc/sys/" + key;
    std::replace(path.begin(), path.end(), '.', '/');
    std::ifstream f(path);
    if (!f) return {};
    std::string val;
    std::getline(f, val);
    return util::trim(val);
}

struct SysctlCheck {
    std::string key;
    std::string expected;   // expected value(s), comma-separated
    Severity sev;
    std::string title;
    std::string detail;
    bool lower_is_better = false; // if true, value <= expected[0] is good
};

CheckResult check_kernel() {
    CheckResult result;
    result.name = "Kernel Security Parameters (sysctl)";

    int checked = 0, issues = 0;
    auto flag = [&](bool bad) { ++checked; if (bad) ++issues; };

    // ── ASLR ──────────────────────────────────────────────────────────────────
    {
        auto v = sysctl_get("kernel.randomize_va_space");
        if (v == "1") {
            flag(true);
            result.findings.push_back({Severity::MEDIUM, "Kernel",
                "ASLR partially enabled (randomize_va_space=1)",
                "Set kernel.randomize_va_space=2 for full stack/heap randomization"});
        } else if (v != "2") {
            flag(true);
            result.findings.push_back({Severity::CRITICAL, "Kernel",
                "ASLR disabled (randomize_va_space=" + (v.empty() ? "?" : v) + ")",
                "Exploit mitigations rely on ASLR. Set kernel.randomize_va_space=2"});
        } else { flag(false); }
    }

    // ── dmesg restriction ─────────────────────────────────────────────────────
    {
        auto v = sysctl_get("kernel.dmesg_restrict");
        flag(v != "1");
        if (v != "1")
            result.findings.push_back({Severity::MEDIUM, "Kernel",
                "kernel.dmesg_restrict=0 — unprivileged users can read kernel ring buffer",
                "dmesg leaks kernel addresses and device info. Set kernel.dmesg_restrict=1"});
    }

    // ── kernel pointer leak ───────────────────────────────────────────────────
    {
        auto v = sysctl_get("kernel.kptr_restrict");
        if (v == "0") {
            flag(true);
            result.findings.push_back({Severity::HIGH, "Kernel",
                "kernel.kptr_restrict=0 — kernel pointers visible in /proc",
                "Kernel addresses in /proc/kallsyms help bypass KASLR. Set kptr_restrict=2"});
        } else if (v == "1") {
            flag(true);
            result.findings.push_back({Severity::LOW, "Kernel",
                "kernel.kptr_restrict=1 — pointers hidden from unprivileged only",
                "Set kptr_restrict=2 to also hide from root"});
        } else { flag(false); }
    }

    // ── SYN cookies ──────────────────────────────────────────────────────────
    {
        auto v = sysctl_get("net.ipv4.tcp_syncookies");
        flag(v != "1");
        if (v != "1")
            result.findings.push_back({Severity::HIGH, "Kernel",
                "tcp_syncookies disabled — SYN flood attacks more effective",
                "Set net.ipv4.tcp_syncookies=1"});
    }

    // ── IP forwarding ─────────────────────────────────────────────────────────
    {
        // ip_forward=1 and rp_filter=0 are expected when a VPN/tunnel is active
        // or when container runtimes (Docker, containerd, Podman) are running.
        std::string links = util::exec("ip link show");
        bool has_tunnel = links.find(": tun") != std::string::npos ||
                          links.find(": wg")  != std::string::npos ||
                          links.find(": tap") != std::string::npos ||
                          links.find(": ppp") != std::string::npos ||
                          links.find(": docker") != std::string::npos ||
                          links.find(": br-") != std::string::npos ||   // Docker bridge networks
                          links.find(": virbr") != std::string::npos;  // libvirt bridges
        // Also check for active container runtimes via systemd
        bool has_containers =
            util::trim(util::exec("systemctl is-active docker 2>/dev/null")) == "active" ||
            util::trim(util::exec("systemctl is-active containerd 2>/dev/null")) == "active" ||
            util::trim(util::exec("systemctl is-active podman 2>/dev/null")) == "active" ||
            !util::exec("pgrep -x dockerd 2>/dev/null").empty() ||
            !util::exec("pgrep -x containerd 2>/dev/null").empty();
        has_tunnel = has_tunnel || has_containers;

        auto v4 = sysctl_get("net.ipv4.ip_forward");
        auto v6 = sysctl_get("net.ipv6.conf.all.forwarding");
        if (v4 == "1" && !has_tunnel) {
            flag(true);
            result.findings.push_back({Severity::MEDIUM, "Kernel",
                "net.ipv4.ip_forward=1 — machine is routing IPv4 packets",
                "No VPN/tunnel/container interface found. Expected on routers, not desktops."});
        } else { flag(false); }
        if (v6 == "1" && !has_tunnel) {
            flag(true);
            result.findings.push_back({Severity::MEDIUM, "Kernel",
                "net.ipv6.conf.all.forwarding=1 — machine is routing IPv6 packets",
                "No VPN/tunnel/container interface found. Expected on routers, not desktops."});
        } else { flag(false); }
    }

    // ── ICMP redirects ────────────────────────────────────────────────────────
    {
        auto send = sysctl_get("net.ipv4.conf.all.send_redirects");
        auto accept = sysctl_get("net.ipv4.conf.all.accept_redirects");
        auto accept6 = sysctl_get("net.ipv6.conf.all.accept_redirects");
        if (send == "1") {
            result.findings.push_back({Severity::MEDIUM, "Kernel",
                "net.ipv4.conf.all.send_redirects=1 — ICMP redirects sent",
                "Only routers should send ICMP redirects. Set to 0 on workstations."});
        }
        if (accept == "1") {
            result.findings.push_back({Severity::MEDIUM, "Kernel",
                "net.ipv4.conf.all.accept_redirects=1 — ICMP redirects accepted",
                "Accepting ICMP redirects can allow routing table manipulation. Set to 0."});
        }
        if (accept6 == "1") {
            result.findings.push_back({Severity::MEDIUM, "Kernel",
                "net.ipv6.conf.all.accept_redirects=1 — ICMPv6 redirects accepted",
                "Set net.ipv6.conf.all.accept_redirects=0"});
        }
    }

    // ── Source routing ────────────────────────────────────────────────────────
    {
        auto v = sysctl_get("net.ipv4.conf.all.accept_source_route");
        if (v == "1") {
            result.findings.push_back({Severity::HIGH, "Kernel",
                "accept_source_route=1 — IP source routing accepted",
                "Source routing lets attackers bypass firewalls. Set to 0."});
        }
    }

    // ── Reverse path filtering ────────────────────────────────────────────────
    {
        std::string links2 = util::exec("ip link show");
        bool has_tunnel =
            links2.find(": tun") != std::string::npos ||
            links2.find(": wg")  != std::string::npos ||
            links2.find(": tap") != std::string::npos ||
            links2.find(": ppp") != std::string::npos ||
            links2.find(": docker") != std::string::npos ||
            links2.find(": br-") != std::string::npos ||
            links2.find(": virbr") != std::string::npos ||
            util::trim(util::exec("systemctl is-active docker 2>/dev/null")) == "active" ||
            util::trim(util::exec("systemctl is-active containerd 2>/dev/null")) == "active" ||
            !util::exec("pgrep -x containerd 2>/dev/null").empty();
        auto v = sysctl_get("net.ipv4.conf.all.rp_filter");
        if (v == "0" && !has_tunnel) {
            flag(true);
            result.findings.push_back({Severity::MEDIUM, "Kernel",
                "rp_filter=0 — reverse path filtering disabled",
                "No VPN/tunnel found. Allows IP spoofing. Set net.ipv4.conf.all.rp_filter=1"});
        } else { flag(false); }
    }

    // ── SUID core dumps ───────────────────────────────────────────────────────
    {
        auto v = sysctl_get("fs.suid_dumpable");
        flag(v != "0");
        if (v != "0")
            result.findings.push_back({Severity::MEDIUM, "Kernel",
                "fs.suid_dumpable=" + v + " — SUID processes may produce core dumps",
                "Core dumps from SUID binaries can leak credentials. Set fs.suid_dumpable=0"});
    }

    // ── Unprivileged BPF ──────────────────────────────────────────────────────
    {
        auto v = sysctl_get("kernel.unprivileged_bpf_disabled");
        if (!v.empty()) {
            flag(v == "0");
            if (v == "0")
                result.findings.push_back({Severity::MEDIUM, "Kernel",
                    "kernel.unprivileged_bpf_disabled=0 — any user can load eBPF programs",
                    "eBPF is a common local privilege escalation vector. Set to 1."});
        }
    }

    // ── Unprivileged user namespaces ──────────────────────────────────────────
    {
        auto v = sysctl_get("kernel.unprivileged_userns_clone");
        if (v == "1") {
            flag(true);
            result.findings.push_back({Severity::LOW, "Kernel",
                "kernel.unprivileged_userns_clone=1 — unprivileged user namespaces enabled",
                "User namespaces expand attack surface. Set to 0 if containers not needed."});
        } else if (!v.empty()) { flag(false); }
    }

    // ── Perf events ──────────────────────────────────────────────────────────
    {
        auto v = sysctl_get("kernel.perf_event_paranoid");
        flag(v == "-1" || v == "0");
        if (v == "-1" || v == "0")
            result.findings.push_back({Severity::MEDIUM, "Kernel",
                "kernel.perf_event_paranoid=" + v + " — perf events accessible to all users",
                "Perf events enable side-channel attacks. Set to 2 or 3."});
    }

    // ── IPv6 Router Advertisements ────────────────────────────────────────────
    {
        auto v = sysctl_get("net.ipv6.conf.all.accept_ra");
        flag(v == "2");
        if (v == "2")
            result.findings.push_back({Severity::LOW, "Kernel",
                "net.ipv6.conf.all.accept_ra=2 — accepts RA even when forwarding is enabled",
                "Rogue RA packets can reconfigure your IPv6 default route"});
    }

    // ── Summary ───────────────────────────────────────────────────────────────
    if (issues == 0)
        result.findings.push_back({Severity::INFO, "Kernel",
            std::to_string(checked) + " kernel parameters checked — all good", ""});

    return result;
}
