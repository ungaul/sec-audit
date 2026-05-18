#include "types.hpp"
#include "util.hpp"
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <regex>

// Known telemetry/tracking domains — suffix-matched
static const std::vector<std::string> TELEMETRY_DOMAINS = {
    // Microsoft telemetry
    "telemetry.microsoft.com", "vortex.data.microsoft.com",
    "settings-win.data.microsoft.com", "watson.telemetry.microsoft.com",
    "dc.services.visualstudio.com", "events.data.microsoft.com",
    "msftconnecttest.com",
    // VS Code / Azure
    "az764295.vo.msecnd.net", "update.code.visualstudio.com",
    // Google Analytics / Ads
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "googlesyndication.com", "googleadservices.com", "googletagservices.com",
    "ssl.google-analytics.com",
    // Meta / Facebook
    "graph.facebook.com", "connect.facebook.net", "fbcdn.net",
    // Analytics platforms
    "segment.io", "segment.com", "api.segment.io",
    "mixpanel.com", "api.mixpanel.com",
    "amplitude.com", "api.amplitude.com", "api2.amplitude.com",
    "hotjar.com", "static.hotjar.com",
    "fullstory.com", "rs.fullstory.com",
    "logrocket.com",
    "pendo.io", "app.pendo.io",
    "intercom.io", "api.intercom.io",
    "heap.io", "heapanalytics.com",
    "kissmetrics.com",
    "crazyegg.com",
    // Error tracking
    "sentry.io", "o0.ingest.sentry.io",
    "bugsnag.com", "notify.bugsnag.com",
    "rollbar.com", "api.rollbar.com",
    "newrelic.com", "bam.nr-data.net",
    "datadoghq.com", "browser-intake-datadoghq.com",
    // Ubuntu/Canonical
    "popcon.ubuntu.com", "metrics.ubuntu.com",
    "report.ubuntu.com", "error-tracker.ubuntu.com",
    // Mozilla
    "incoming.telemetry.mozilla.org", "telemetry.mozilla.org",
    "crash-stats.mozilla.com", "sentry.mozilla.org",
    // JetBrains
    "data.services.jetbrains.com", "resources.jetbrains.com",
    // Marketing / CRM
    "hubspot.com", "api.hubspot.com",
    "marketo.com", "mktoresp.com",
    "salesforce.com", "pardot.com",
    "zendesk.com",
    // CDN-based trackers
    "cdn.segment.com", "cdn.mxpnl.com",
};

// Decode a hex IPv4 address from /proc/net/tcp (little-endian)
static std::string decode_ipv4(const std::string& hex) {
    if (hex.size() != 8) return {};
    try {
        unsigned int addr = std::stoul(hex, nullptr, 16);
        return std::to_string(addr & 0xff) + "." +
               std::to_string((addr >> 8) & 0xff) + "." +
               std::to_string((addr >> 16) & 0xff) + "." +
               std::to_string((addr >> 24) & 0xff);
    } catch (...) { return {}; }
}

// Collect all unique remote IPs with ESTABLISHED state from /proc/net/tcp*
static std::set<std::string> get_established_remote_ips() {
    std::set<std::string> ips;
    for (const auto& path : {"/proc/net/tcp", "/proc/net/tcp6"}) {
        auto content = util::read_file(path);
        if (!content) continue;
        for (const auto& line : util::split_lines(*content)) {
            std::istringstream iss(line);
            std::string sl, local, remote, state;
            iss >> sl >> local >> remote >> state;
            if (state != "01") continue; // ESTABLISHED only
            auto parts = util::split(remote, ':');
            if (parts.size() != 2) continue;
            // Skip loopback
            if (parts[0] == "0100007F" || parts[0] == "7F000001") continue;
            std::string ip = decode_ipv4(parts[0]);
            if (!ip.empty() && ip != "0.0.0.0" && ip.rfind("127.", 0) != 0)
                ips.insert(ip);
        }
    }
    return ips;
}

// Resolve an IP to hostname using getaddrinfo reverse lookup
static std::string reverse_resolve(const std::string& ip) {
    // Use 'host' binary if available for speed — avoids blocking getaddrinfo
    std::string out = util::exec("host -W 2 " + ip + " 2>/dev/null");
    if (out.empty()) return {};
    // "1.1.1.1.in-addr.arpa domain name pointer one.one.one.one."
    std::regex re(R"(pointer\s+([a-zA-Z0-9.\-]+)\.?)");
    std::smatch m;
    if (std::regex_search(out, m, re)) {
        std::string hostname = m[1].str();
        // strip trailing dot
        if (!hostname.empty() && hostname.back() == '.')
            hostname.pop_back();
        return hostname;
    }
    return {};
}

// Check if hostname matches any telemetry domain (suffix match)
static std::string matches_telemetry(const std::string& hostname) {
    if (hostname.empty()) return {};
    std::string lower = hostname;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (const auto& domain : TELEMETRY_DOMAINS) {
        // exact match or subdomain match
        if (lower == domain || (lower.size() > domain.size() &&
            lower.substr(lower.size() - domain.size() - 1) == "." + domain))
            return domain;
    }
    return {};
}

CheckResult check_telemetry() {
    CheckResult result;
    result.name = "Outbound Telemetry / Tracking Connections";

    // Check if 'host' is available for reverse DNS
    bool has_host = !util::trim(util::exec("which host 2>/dev/null")).empty();
    if (!has_host) {
        result.findings.push_back({
            Severity::INFO,
            "Telemetry",
            "Skipping active-connection resolution — 'host' binary not found",
            "Install bind-tools (Arch) or dnsutils (Debian) for full telemetry detection"
        });
    }

    auto ips = get_established_remote_ips();

    std::set<std::string> already_found;
    int resolved = 0;

    if (has_host) {
        for (const auto& ip : ips) {
            std::string hostname = reverse_resolve(ip);
            if (hostname.empty()) continue;
            ++resolved;
            std::string matched = matches_telemetry(hostname);
            if (!matched.empty() && !already_found.count(matched)) {
                already_found.insert(matched);
                result.findings.push_back({
                    Severity::HIGH,
                    "Telemetry",
                    "Active connection to telemetry endpoint: " + hostname + " (" + ip + ")",
                    "Matched known telemetry domain: " + matched
                });
            }
        }
    }

    // Passive: check /etc/hosts for blocked telemetry domains (good hygiene indicator)
    auto hosts_file = util::read_file("/etc/hosts");
    if (hosts_file) {
        std::vector<std::string> blocked;
        for (const auto& domain : TELEMETRY_DOMAINS) {
            if (hosts_file->find(domain) != std::string::npos)
                blocked.push_back(domain);
        }
        if (!blocked.empty()) {
            std::string detail;
            for (size_t i = 0; i < std::min(blocked.size(), size_t(6)); ++i) {
                if (i) detail += ", ";
                detail += blocked[i];
            }
            if (blocked.size() > 6)
                detail += " (+" + std::to_string(blocked.size()-6) + " more)";
            result.findings.push_back({
                Severity::INFO,
                "Telemetry",
                std::to_string(blocked.size()) + " telemetry domain(s) blocked via /etc/hosts",
                detail
            });
        }
    }

    // Check /etc/hosts.deny for telemetry blocks
    // Check NetworkManager dns=none or dns=systemd-resolved (which means no split DNS)

    if (result.findings.empty() || (result.findings.size() == 1 &&
        result.findings[0].severity == Severity::INFO)) {
        std::string summary = "No active connections to known telemetry endpoints";
        if (has_host && !ips.empty())
            summary += " (" + std::to_string(ips.size()) + " remote IPs checked, " +
                       std::to_string(resolved) + " resolved)";
        result.findings.push_back({
            Severity::INFO,
            "Telemetry",
            summary,
            ""
        });
    }

    return result;
}
