#include "types.hpp"
#include "util.hpp"
#include <regex>
#include <sstream>
#include <set>
#include <cstdlib>

static bool offline_mode() {
    const char* v = getenv("SEC_AUDIT_OFFLINE");
    return v && v[0] == '1';
}

static bool curl_available() {
    return !util::trim(util::exec("which curl")).empty();
}

// Extract a string field from a simple flat JSON object
static std::string json_str(const std::string& json, const std::string& key) {
    std::regex re("\"" + key + "\"\\s*:\\s*\"([^\"\\\\]*)\"");
    std::smatch m;
    if (std::regex_search(json, m, re)) return m[1].str();
    return {};
}

static bool is_globally_routable_v6(const std::string& addr) {
    if (addr.empty()) return false;
    // Loopback: ::1
    if (addr == "::1") return false;
    // Link-local: fe80::/10
    std::string lo = addr.substr(0, 4);
    std::transform(lo.begin(), lo.end(), lo.begin(), ::tolower);
    if (lo == "fe80") return false;
    // Unique Local: fc00::/7 (fc, fd)
    if (lo.rfind("fc", 0) == 0 || lo.rfind("fd", 0) == 0) return false;
    // Global unicast: 2000::/3 — starts with 2 or 3
    return addr[0] == '2' || addr[0] == '3';
}

// Parse listening ports on :: or 0.0.0.0 (truly internet-facing)
static std::vector<std::string> internet_facing_ports() {
    std::vector<std::string> result;
    std::set<std::string> seen;
    for (const auto& cmd : {"ss -tlnp", "ss -ulnp"}) {
        std::string proto = (std::string(cmd).find("-u") != std::string::npos) ? "UDP" : "TCP";
        for (const auto& line : util::split_lines(util::exec(cmd))) {
            // Must be bound to all interfaces: 0.0.0.0, *, [::]
            bool wildcard = (line.find(" *:") != std::string::npos ||
                             line.find(" 0.0.0.0:") != std::string::npos ||
                             line.find("[::]:") != std::string::npos ||
                             line.find(" :::") != std::string::npos);
            if (!wildcard) continue;
            // Extract port and process
            std::istringstream iss(line);
            std::string a, b, c, local, peer, rest;
            iss >> a >> b >> c >> local >> peer;
            std::getline(iss, rest);
            size_t colon = local.rfind(':');
            if (colon == std::string::npos) continue;
            std::string port = local.substr(colon + 1);
            // Extract process name
            std::string pname;
            size_t ps = rest.find("users:((\"");
            if (ps != std::string::npos) {
                ps += 9;
                size_t pe = rest.find('"', ps);
                if (pe != std::string::npos) pname = rest.substr(ps, pe - ps);
            }
            std::string entry = proto + "/" + port;
            if (!pname.empty()) entry += "[" + pname + "]";
            if (!seen.count(entry)) {
                seen.insert(entry);
                result.push_back(entry);
            }
        }
    }
    return result;
}

CheckResult check_exposure() {
    CheckResult result;
    result.name = "External Exposure, IPv6 Reachability & Geolocation";

    // ── 1. Detect globally routable IPv6 addresses ──────────────────────────
    std::vector<std::string> global_v6;
    {
        std::string out = util::exec("ip -6 addr show scope global");
        std::regex re(R"(inet6\s+([0-9a-fA-F:]+)/\d+)");
        for (const auto& line : util::split_lines(out)) {
            std::smatch m;
            if (std::regex_search(line, m, re)) {
                if (is_globally_routable_v6(m[1].str()))
                    global_v6.push_back(m[1].str());
            }
        }
    }

    // ── 2. Local IPv4 addresses ──────────────────────────────────────────────
    std::string local_v4;
    {
        std::string out = util::exec("ip -4 addr show scope global");
        std::regex re(R"(inet\s+(\d+\.\d+\.\d+\.\d+)/\d+)");
        std::smatch m;
        if (std::regex_search(out, m, re)) local_v4 = m[1].str();
    }

    // ── 3. Internet-facing ports (wildcard listeners) ────────────────────────
    auto open_ports = internet_facing_ports();
    std::string ports_str;
    for (size_t i = 0; i < open_ports.size(); ++i) {
        if (i) ports_str += "  ";
        ports_str += open_ports[i];
    }

    // ── 4. VPN/tunnel detection ──────────────────────────────────────────────
    std::string ifaces = util::exec("ip link show");
    bool has_vpn = ifaces.find(": tun") != std::string::npos ||
                   ifaces.find(": wg")  != std::string::npos ||
                   ifaces.find(": tap") != std::string::npos ||
                   ifaces.find(": proton") != std::string::npos;
    if (has_vpn) {
        result.findings.push_back({
            Severity::INFO,
            "Exposure",
            "VPN/tunnel interface active (tun/wg/tap)",
            "A VPN or WireGuard tunnel is up — verify traffic routes through it"
        });
    }

    // ── 5. IPv6 global exposure ──────────────────────────────────────────────
    if (global_v6.empty()) {
        result.findings.push_back({
            Severity::INFO,
            "Exposure",
            "No globally routable IPv6 addresses — IPv4 NAT likely in effect",
            ""
        });
    } else {
        std::string addr_list;
        for (const auto& a : global_v6) {
            if (!addr_list.empty()) addr_list += ", ";
            addr_list += a;
        }
        std::string detail = "Unlike IPv4 behind a home router/NAT, IPv6 is end-to-end routed — "
                             "there is no NAT between the internet and this machine. "
                             "Address(es): " + addr_list + ".";
        if (!open_ports.empty())
            detail += " Open wildcard ports reachable directly: " + ports_str;
        result.findings.push_back({
            Severity::HIGH,
            "Exposure",
            "Globally routable IPv6 — machine is directly internet-addressable",
            detail
        });
    }

    // ── 6. External IP lookup (requires curl + internet) ────────────────────
    if (offline_mode()) {
        result.findings.push_back({
            Severity::INFO,
            "Exposure",
            "Offline mode — external IP / geolocation lookup skipped",
            ""
        });
        return result;
    }
    if (!curl_available()) {
        result.findings.push_back({
            Severity::INFO,
            "Exposure",
            "curl not available — skipping external IP / geolocation lookup",
            ""
        });
        return result;
    }

    // IPv4 external IP + geo
    std::string info4 = util::exec("curl -4 -s --max-time 6 --fail https://ipinfo.io/json");
    if (!info4.empty() && info4.find('"') != std::string::npos) {
        std::string ext_ip  = json_str(info4, "ip");
        std::string city    = json_str(info4, "city");
        std::string region  = json_str(info4, "region");
        std::string country = json_str(info4, "country");
        std::string org     = json_str(info4, "org");
        std::string loc     = json_str(info4, "loc");
        std::string tz      = json_str(info4, "timezone");
        std::string postal  = json_str(info4, "postal");

        if (!ext_ip.empty()) {
            bool behind_nat = !local_v4.empty() && local_v4 != ext_ip;

            std::string title = "External IPv4: " + ext_ip;
            if (behind_nat) title += "  (NATed, internal: " + local_v4 + ")";

            std::string detail;
            if (!city.empty())   detail += city;
            if (!postal.empty()) detail += " " + postal;
            if (!region.empty()) detail += ", " + region;
            if (!country.empty()) detail += ", " + country;
            if (!tz.empty())     detail += "  |  TZ: " + tz;
            if (!org.empty())    detail += "  |  ISP/Org: " + org;
            if (!loc.empty())    detail += "  |  Coords: " + loc;

            result.findings.push_back({
                Severity::INFO,
                "Exposure",
                title,
                detail
            });
        }
    } else {
        result.findings.push_back({
            Severity::INFO,
            "Exposure",
            "External IPv4 lookup failed (no internet or service unreachable)",
            ""
        });
    }

    // IPv6 external IP — only relevant if we have global v6
    if (!global_v6.empty()) {
        std::string info6 = util::exec("curl -6 -s --max-time 6 --fail https://ipinfo.io/json");
        if (!info6.empty() && info6.find('"') != std::string::npos) {
            std::string ext6    = json_str(info6, "ip");
            std::string city6   = json_str(info6, "city");
            std::string region6 = json_str(info6, "region");
            std::string country6= json_str(info6, "country");
            std::string org6    = json_str(info6, "org");

            if (!ext6.empty()) {
                std::string geo6;
                if (!city6.empty())    geo6 += city6;
                if (!region6.empty())  geo6 += ", " + region6;
                if (!country6.empty()) geo6 += ", " + country6;
                result.findings.push_back({
                    Severity::HIGH,
                    "Exposure",
                    "External IPv6: " + ext6,
                    "ISP/Org: " + org6 + "  |  Location: " + geo6 +
                    "  |  This address is directly internet-routable — no NAT. "
                    "Open ports: " + (ports_str.empty() ? "none detected" : ports_str)
                });
            }
        } else {
            // We have global v6 locally but couldn't reach the internet over v6
            result.findings.push_back({
                Severity::LOW,
                "Exposure",
                "Globally routable IPv6 assigned but external IPv6 lookup failed",
                "Address may not be routed to the internet, or ipinfo.io unreachable over IPv6"
            });
        }
    }

    // ── 7. Location services (GeoClue2 / GPS / WiFi geolocation) ────────────
    // Distinct from IP geolocation — these give precise GPS-level location to apps.

    bool geoclue_running = util::trim(
        util::exec("systemctl is-active geoclue 2>/dev/null")) == "active";

    if (geoclue_running) {
        result.findings.push_back({
            Severity::MEDIUM,
            "Exposure",
            "GeoClue2 location service is running",
            "Applications can request your physical location (GPS/WiFi/cell-tower triangulation) "
            "via D-Bus. Check /etc/geoclue/geoclue.conf to review which apps have access."
        });
        auto geoclue_conf = util::read_file("/etc/geoclue/geoclue.conf");
        if (geoclue_conf) {
            std::vector<std::string> allowed_agents;
            std::string current_section;
            for (const auto& line : util::split_lines(*geoclue_conf)) {
                if (line.size() > 2 && line.front() == '[' && line.back() == ']')
                    current_section = line.substr(1, line.size() - 2);
                if (!current_section.empty() && current_section != "agent" &&
                    line.find("allowed=true") != std::string::npos)
                    allowed_agents.push_back(current_section);
            }
            if (!allowed_agents.empty()) {
                std::string apps;
                for (size_t i = 0; i < allowed_agents.size(); ++i) {
                    if (i) apps += ", ";
                    apps += allowed_agents[i];
                }
                result.findings.push_back({
                    Severity::LOW,
                    "Exposure",
                    "Apps with explicit GeoClue2 location access: " + apps,
                    "Review /etc/geoclue/geoclue.conf — remove entries for apps that don't need location"
                });
            }
        }
    } else {
        result.findings.push_back({
            Severity::INFO,
            "Exposure",
            "GeoClue2 location service not running",
            "No applications can obtain GPS/WiFi-based physical location data"
        });
    }

    // GPS hardware check
    std::vector<std::string> gps_devs;
    for (const auto& pat : {"/dev/ttyUSB*", "/dev/ttyACM*", "/dev/rfcomm*"})
        for (const auto& dev : util::glob_files(pat))
            gps_devs.push_back(dev);

    bool gpsd_running = util::trim(
        util::exec("systemctl is-active gpsd 2>/dev/null")) == "active" ||
        !util::exec("pgrep -x gpsd 2>/dev/null").empty();

    if (gpsd_running) {
        std::string devs;
        for (const auto& d : gps_devs) { if (!devs.empty()) devs += ", "; devs += d; }
        result.findings.push_back({
            Severity::MEDIUM,
            "Exposure",
            "gpsd is running — GPS receiver active",
            "A GPS daemon is running; applications can obtain precise physical coordinates. "
            "Devices: " + (devs.empty() ? "(none found in /dev)" : devs)
        });
    } else if (!gps_devs.empty()) {
        std::string devs;
        for (const auto& d : gps_devs) { if (!devs.empty()) devs += ", "; devs += d; }
        result.findings.push_back({
            Severity::LOW,
            "Exposure",
            "Serial/GPS devices present but gpsd not running: " + devs,
            "GPS hardware detected — verify these are expected"
        });
    }

    return result;
}
