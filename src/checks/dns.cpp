#include "types.hpp"
#include "util.hpp"
#include <regex>
#include <set>

// Well-known privacy-respecting resolvers
static const std::set<std::string> TRUSTED_RESOLVERS = {
    "1.1.1.1",              // Cloudflare
    "1.0.0.1",              // Cloudflare
    "2606:4700:4700::1111", // Cloudflare IPv6
    "2606:4700:4700::1001", // Cloudflare IPv6
    "8.8.8.8",              // Google
    "8.8.4.4",              // Google
    "2001:4860:4860::8888", // Google IPv6
    "2001:4860:4860::8844", // Google IPv6
    "9.9.9.9",              // Quad9
    "149.112.112.112",      // Quad9
    "2620:fe::fe",          // Quad9 IPv6
    "208.67.222.222",       // OpenDNS
    "208.67.220.220",       // OpenDNS
    "94.140.14.14",         // AdGuard
    "94.140.15.15",         // AdGuard
    "76.76.2.0",            // Control D
    "127.0.0.1",            // Local resolver
    "127.0.0.53",           // systemd-resolved stub
    "::1",                  // IPv6 loopback
};

static const std::set<std::string> SUSPICIOUS_RESOLVERS = {
    // ISP resolvers that may log/redirect DNS (common examples)
    // These are heuristic — any non-loopback, non-VPN, non-well-known resolver is flagged
};

CheckResult check_dns() {
    CheckResult result;
    result.name = "DNS Configuration & Leak Check";

    std::set<std::string> nameservers;

    // Check /etc/resolv.conf
    auto resolv = util::read_file("/etc/resolv.conf");
    if (resolv) {
        std::regex ns_re(R"(^\s*nameserver\s+([\d.:a-fA-F]+))");
        for (const auto& line : util::split_lines(*resolv)) {
            std::smatch m;
            if (std::regex_search(line, m, ns_re)) {
                nameservers.insert(m[1].str());
            }
        }
    }

    // Check systemd-resolved configuration
    auto resolved_conf = util::read_file("/etc/systemd/resolved.conf");
    if (resolved_conf) {
        std::regex dns_re(R"(^\s*DNS\s*=\s*(.+))");
        std::regex fallback_re(R"(^\s*FallbackDNS\s*=\s*(.+))");
        for (const auto& line : util::split_lines(*resolved_conf)) {
            std::smatch m;
            if (std::regex_search(line, m, dns_re) || std::regex_search(line, m, fallback_re)) {
                for (const auto& ns : util::split(util::trim(m[1].str()), ' ')) {
                    if (!ns.empty()) nameservers.insert(ns);
                }
            }
        }
    }

    // Check /etc/systemd/resolved.conf.d/
    for (const auto& f : util::glob_files("/etc/systemd/resolved.conf.d/*.conf")) {
        auto content = util::read_file(f);
        if (!content) continue;
        std::regex dns_re(R"(^\s*DNS\s*=\s*(.+))");
        for (const auto& line : util::split_lines(*content)) {
            std::smatch m;
            if (std::regex_search(line, m, dns_re)) {
                for (const auto& ns : util::split(util::trim(m[1].str()), ' ')) {
                    if (!ns.empty()) nameservers.insert(ns);
                }
            }
        }
    }

    // Check NetworkManager DNS
    for (const auto& f : util::glob_files("/etc/NetworkManager/system-connections/*.nmconnection")) {
        auto content = util::read_file(f);
        if (!content) continue;
        std::regex dns_re(R"(dns\s*=\s*(.+))");
        for (const auto& line : util::split_lines(*content)) {
            std::smatch m;
            if (std::regex_search(line, m, dns_re)) {
                for (const auto& ns : util::split(util::trim(m[1].str()), ';')) {
                    if (!ns.empty() && ns != ";" ) nameservers.insert(ns);
                }
            }
        }
    }

    if (nameservers.empty()) {
        result.findings.push_back({
            Severity::MEDIUM,
            "DNS",
            "No DNS resolver configuration found",
            "Could not determine configured nameservers from /etc/resolv.conf or systemd-resolved"
        });
        return result;
    }

    for (const auto& ns : nameservers) {
        bool trusted = TRUSTED_RESOLVERS.count(ns) > 0;
        bool is_loopback = (ns.rfind("127.", 0) == 0 || ns == "::1");
        bool is_link_local = (ns.rfind("fe80:", 0) == 0 || ns.rfind("FE80:", 0) == 0);
        bool is_private = (ns.rfind("192.168.", 0) == 0 ||
                           ns.rfind("10.", 0) == 0 ||
                           ns.rfind("172.", 0) == 0);

        if (is_loopback) {
            result.findings.push_back({
                Severity::INFO,
                "DNS",
                "DNS resolver: local stub (" + ns + ")",
                "Using a local DNS resolver (systemd-resolved, dnsmasq, etc.)"
            });
        } else if (trusted) {
            result.findings.push_back({
                Severity::INFO,
                "DNS",
                "DNS resolver: " + ns + " (known public resolver)",
                "Public resolver — DNS queries are not going through a local privacy proxy"
            });
        } else if (is_link_local) {
            result.findings.push_back({
                Severity::LOW,
                "DNS",
                "DNS resolver: " + ns + " (link-local / router-assigned)",
                "Link-local IPv6 address — typically your router. Verify it doesn't forward queries unencrypted."
            });
        } else if (is_private) {
            result.findings.push_back({
                Severity::LOW,
                "DNS",
                "DNS resolver: " + ns + " (private network address)",
                "Likely a router or local DNS server. Verify it doesn't forward queries unencrypted."
            });
        } else {
            result.findings.push_back({
                Severity::MEDIUM,
                "DNS",
                "DNS resolver: " + ns + " (unrecognized)",
                "Unknown DNS resolver — could be ISP-assigned or a non-standard server that logs queries"
            });
        }
    }

    // Check if DNS-over-HTTPS or DNS-over-TLS is configured in systemd-resolved
    bool dot_enabled = false;
    if (resolved_conf) {
        if (resolved_conf->find("DNSOverTLS=yes") != std::string::npos ||
            resolved_conf->find("DNSOverTLS=opportunistic") != std::string::npos) {
            dot_enabled = true;
        }
    }

    if (!dot_enabled) {
        result.findings.push_back({
            Severity::LOW,
            "DNS",
            "DNS-over-TLS not enabled in systemd-resolved",
            "DNS queries may be sent in plaintext. Consider setting DNSOverTLS=yes in /etc/systemd/resolved.conf"
        });
    } else {
        result.findings.push_back({
            Severity::INFO,
            "DNS",
            "DNS-over-TLS is enabled in systemd-resolved",
            ""
        });
    }

    // Check if DNSSEC is enabled
    bool dnssec_enabled = false;
    if (resolved_conf) {
        if (resolved_conf->find("DNSSEC=yes") != std::string::npos ||
            resolved_conf->find("DNSSEC=allow-downgrade") != std::string::npos) {
            dnssec_enabled = true;
        }
    }
    if (!dnssec_enabled) {
        result.findings.push_back({
            Severity::LOW,
            "DNS",
            "DNSSEC not enabled in systemd-resolved",
            "DNS responses are not cryptographically validated. Consider setting DNSSEC=yes"
        });
    }

    // Check for DNS queries going to port 53 (unencrypted) on active connections
    std::string dns_conns = util::exec("ss -unp dport = :53");
    auto dns_lines = util::split_lines(dns_conns);
    std::set<std::string> dns_procs;
    for (const auto& line : dns_lines) {
        if (line.find("users:") != std::string::npos) {
            size_t start = line.find("users:((\"");
            if (start != std::string::npos) {
                start += 9;
                size_t end = line.find('"', start);
                if (end != std::string::npos)
                    dns_procs.insert(line.substr(start, end - start));
            }
        }
    }
    for (const auto& proc : dns_procs) {
        result.findings.push_back({
            Severity::MEDIUM,
            "DNS",
            "Process making unencrypted DNS queries: " + proc,
            "Process is sending DNS queries to port 53 (plaintext UDP)"
        });
    }

    return result;
}
