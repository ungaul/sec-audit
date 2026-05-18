#include "types.hpp"
#include "util.hpp"
#include <regex>
#include <set>
#include <map>
#include <sstream>

// Ports that are commonly expected/benign on a desktop Linux system
static const std::map<int, std::string> EXPECTED_PORTS = {
    {22,   "SSH"},
    {53,   "DNS (local resolver)"},
    {68,   "DHCP client"},
    {546,  "DHCPv6 client"},
    {547,  "DHCPv6 server"},
    {631,  "CUPS printing"},
    {5353, "mDNS/Avahi"},
    {6600, "MPD"},
};

// Ports that are suspicious or unexpected on a desktop
static const std::map<int, std::string> SUSPICIOUS_PORTS = {
    {23,    "Telnet — unencrypted remote shell"},
    {25,    "SMTP — mail server (unexpected on desktop)"},
    {135,   "Microsoft RPC"},
    {139,   "NetBIOS Session Service"},
    {445,   "SMB — file sharing (check if intentional)"},
    {512,   "rexec — remote execution (legacy, dangerous)"},
    {513,   "rlogin — legacy unencrypted login"},
    {514,   "rsh / syslog (plaintext)"},
    {1099,  "Java RMI"},
    {2375,  "Docker daemon (unencrypted, unauthenticated)"},
    {2376,  "Docker daemon TLS"},
    {3306,  "MySQL — database exposed"},
    {3389,  "RDP — Windows remote desktop"},
    {4444,  "Metasploit default listener"},
    {4848,  "GlassFish admin"},
    {5432,  "PostgreSQL — database exposed"},
    {5900,  "VNC — remote desktop"},
    {6379,  "Redis — often unauthenticated"},
    {8080,  "HTTP proxy / dev server"},
    {8443,  "HTTPS alternate"},
    {9200,  "Elasticsearch — often unauthenticated"},
    {27017, "MongoDB — often unauthenticated"},
};

struct ListeningPort {
    std::string proto;
    std::string local_addr;
    int port;
    std::string process;
};

static std::vector<ListeningPort> parse_listening() {
    std::vector<ListeningPort> ports;
    // ss -tlnp: TCP listening, ss -ulnp: UDP listening
    for (const auto& cmd : {
        "ss -tlnp", "ss -ulnp"
    }) {
        std::string proto = (std::string(cmd).find("-u") != std::string::npos) ? "UDP" : "TCP";
        auto lines = util::split_lines(util::exec(cmd));
        for (const auto& line : lines) {
            if (line.find("State") != std::string::npos) continue;
            std::istringstream iss(line);
            std::string state, recvq, sendq, local, peer, proc;
            iss >> state >> recvq >> sendq >> local >> peer;
            std::getline(iss, proc);
            proc = util::trim(proc);

            // Extract port from local address (last :port)
            size_t colon = local.rfind(':');
            if (colon == std::string::npos) continue;
            std::string port_str = local.substr(colon + 1);
            int port = 0;
            try { port = std::stoi(port_str); } catch (...) { continue; }
            if (port <= 0) continue;

            // Extract process name
            std::string procname;
            size_t pstart = proc.find("users:((\"");
            if (pstart != std::string::npos) {
                pstart += 9;
                size_t pend = proc.find('"', pstart);
                if (pend != std::string::npos)
                    procname = proc.substr(pstart, pend - pstart);
            }

            ports.push_back({proto, local.substr(0, colon), port, procname});
        }
    }
    return ports;
}

CheckResult check_ports() {
    CheckResult result;
    result.name = "Listening Ports & Exposed Services";

    auto ports = parse_listening();

    if (ports.empty()) {
        result.findings.push_back({
            Severity::INFO,
            "Ports",
            "No listening ports detected (or insufficient permissions)",
            "Run as root for complete visibility via ss"
        });
        return result;
    }

    std::set<int> seen_ports;
    for (const auto& p : ports) {
        if (seen_ports.count(p.port)) continue;

        auto susp_it = SUSPICIOUS_PORTS.find(p.port);
        auto exp_it  = EXPECTED_PORTS.find(p.port);

        bool is_loopback = (p.local_addr == "127.0.0.1" ||
                            p.local_addr == "::1" ||
                            p.local_addr == "lo" ||
                            p.local_addr.find("127.") == 0);

        std::string proc_str = p.process.empty() ? "(unknown)" : p.process;
        std::string label = p.proto + "/" + std::to_string(p.port);
        std::string addr_desc = is_loopback ? "loopback only" : "all interfaces (0.0.0.0 / ::)";

        if (susp_it != SUSPICIOUS_PORTS.end()) {
            Severity sev = is_loopback ? Severity::MEDIUM : Severity::HIGH;
            result.findings.push_back({
                sev,
                "Ports",
                "Suspicious port listening: " + label + " [" + proc_str + "]",
                susp_it->second + " — bound to " + addr_desc
            });
        } else if (!is_loopback && exp_it == EXPECTED_PORTS.end()) {
            // Unknown port exposed on all interfaces
            result.findings.push_back({
                Severity::MEDIUM,
                "Ports",
                "Unexpected port exposed: " + label + " [" + proc_str + "]",
                "Port " + std::to_string(p.port) + " is listening on " + addr_desc + " with no known service mapping"
            });
        } else if (exp_it != EXPECTED_PORTS.end() && !is_loopback) {
            result.findings.push_back({
                Severity::LOW,
                "Ports",
                "Expected service exposed: " + label + " [" + proc_str + "] (" + exp_it->second + ")",
                "Verify this is intentional — service is reachable from the network"
            });
        } else {
            result.findings.push_back({
                Severity::INFO,
                "Ports",
                "Listening: " + label + " [" + proc_str + "] (" +
                    (exp_it != EXPECTED_PORTS.end() ? exp_it->second : "unknown service") + ")",
                "Bound to " + addr_desc
            });
        }
        seen_ports.insert(p.port);
    }

    return result;
}
