#include "types.hpp"
#include "util.hpp"
#include <regex>
#include <sstream>

// Count actual rules in iptables output (non-chain, non-header lines)
static int count_iptables_rules(const std::string& output) {
    int count = 0;
    for (const auto& line : util::split_lines(output)) {
        if (line.empty()) continue;
        if (line.rfind("Chain ", 0) == 0) continue;
        if (line.rfind("target", 0) == 0) continue;
        if (line.rfind("num", 0) == 0) continue;
        count++;
    }
    return count;
}

// Extract default policy from iptables output, e.g. "Chain INPUT (policy ACCEPT)"
static std::string extract_policy(const std::string& output, const std::string& chain) {
    std::regex re("Chain " + chain + " \\(policy (\\w+)\\)");
    std::smatch m;
    if (std::regex_search(output, m, re)) return m[1].str();
    return {};
}

struct FirewallStatus {
    bool iptables_active   = false;
    bool ip6tables_active  = false;
    bool nftables_active   = false;
    bool ufw_active        = false;
    bool firewalld_active  = false;
    std::string v4_input_policy;
    std::string v6_input_policy;
    int v4_rules = 0;
    int v6_rules = 0;
};

static FirewallStatus probe_firewall() {
    FirewallStatus st;

    // iptables (IPv4)
    std::string ipt = util::exec("iptables -L -n 2>/dev/null || iptables -L 2>/dev/null");
    if (!ipt.empty()) {
        st.iptables_active  = true;
        st.v4_rules         = count_iptables_rules(ipt);
        st.v4_input_policy  = extract_policy(ipt, "INPUT");
    }

    // ip6tables (IPv6)
    std::string ip6t = util::exec("ip6tables -L -n 2>/dev/null || ip6tables -L 2>/dev/null");
    if (!ip6t.empty()) {
        st.ip6tables_active = true;
        st.v6_rules         = count_iptables_rules(ip6t);
        st.v6_input_policy  = extract_policy(ip6t, "INPUT");
    }

    // nftables
    std::string nft = util::exec("nft list ruleset 2>/dev/null");
    if (!nft.empty() && nft.find("table") != std::string::npos) {
        st.nftables_active = true;
    }

    // ufw
    std::string ufw = util::exec("ufw status 2>/dev/null");
    if (ufw.find("Status: active") != std::string::npos) {
        st.ufw_active = true;
    }

    // firewalld
    std::string fwd = util::exec("firewall-cmd --state 2>/dev/null");
    if (util::trim(fwd) == "running") {
        st.firewalld_active = true;
    }

    return st;
}

static bool has_global_v6() {
    std::string out = util::exec("ip -6 addr show scope global");
    std::regex re(R"(inet6\s+[23][0-9a-fA-F:]+/\d+)");
    std::smatch m;
    return std::regex_search(out, m, re);
}

CheckResult check_firewall() {
    CheckResult result;
    result.name = "Firewall Configuration";

    if (!util::is_root()) {
        result.findings.push_back({
            Severity::INFO,
            "Firewall",
            "Requires root to inspect firewall rules",
            "iptables/ip6tables/nftables all need root. Re-run with sudo for a real firewall audit."
        });
        return result;
    }

    auto st = probe_firewall();
    bool any_firewall = st.iptables_active || st.ip6tables_active ||
                        st.nftables_active || st.ufw_active || st.firewalld_active;

    if (!any_firewall) {
        result.findings.push_back({
            Severity::CRITICAL,
            "Firewall",
            "No firewall detected (iptables, ip6tables, nftables, ufw, firewalld)",
            "All incoming connections are accepted by default. Any listening service is fully exposed."
        });
        return result;
    }

    // Report what's active
    std::vector<std::string> active_fw;
    if (st.ufw_active)       active_fw.push_back("ufw");
    if (st.firewalld_active) active_fw.push_back("firewalld");
    if (st.nftables_active)  active_fw.push_back("nftables");
    if (st.iptables_active)  active_fw.push_back("iptables");
    if (st.ip6tables_active) active_fw.push_back("ip6tables");

    std::string fw_list;
    for (size_t i = 0; i < active_fw.size(); ++i) {
        if (i) fw_list += ", ";
        fw_list += active_fw[i];
    }

    // IPv4 analysis
    if (st.iptables_active || st.ufw_active || st.nftables_active || st.firewalld_active) {
        if (st.v4_rules == 0 && st.v4_input_policy == "ACCEPT" && !st.nftables_active && !st.ufw_active) {
            result.findings.push_back({
                Severity::HIGH,
                "Firewall",
                "iptables present but INPUT chain has no rules and policy is ACCEPT",
                "iptables is loaded but not configured — all IPv4 inbound traffic is accepted"
            });
        } else {
            // INPUT ACCEPT with rules: rules may allow everything through anyway
            bool permissive = st.v4_input_policy == "ACCEPT" &&
                              !st.nftables_active && !st.ufw_active && !st.firewalld_active;
            Severity sev = permissive ? Severity::LOW : Severity::INFO;
            std::string note = permissive
                ? "INPUT default policy is ACCEPT — traffic not matched by rules is allowed through. "
                  "Prefer a default DROP/REJECT policy."
                : "";
            result.findings.push_back({
                sev,
                "Firewall",
                "IPv4 firewall active (" + fw_list + ")",
                "iptables rules: " + std::to_string(st.v4_rules) +
                (st.v4_input_policy.empty() ? "" : "  |  INPUT default policy: " + st.v4_input_policy) +
                (note.empty() ? "" : "  |  " + note)
            });
        }
    }

    // IPv6 analysis — critical if global v6 and no ip6 rules
    bool v6_exposed = has_global_v6();
    if (v6_exposed) {
        bool v6_covered = st.ip6tables_active || st.nftables_active ||
                          st.ufw_active || st.firewalld_active;

        if (!v6_covered) {
            result.findings.push_back({
                Severity::CRITICAL,
                "Firewall",
                "IPv6 firewall absent — machine is directly reachable on public IPv6",
                "You have a globally routable IPv6 address but no ip6tables/nftables/ufw rules. "
                "Every port bound to :: is reachable from the internet without restriction."
            });
        } else if (st.ip6tables_active && st.v6_rules == 0 && st.v6_input_policy == "ACCEPT"
                   && !st.nftables_active && !st.ufw_active) {
            result.findings.push_back({
                Severity::HIGH,
                "Firewall",
                "ip6tables present but empty — public IPv6 address is unfiltered",
                "ip6tables INPUT has no rules and policy ACCEPT. All ports accessible over IPv6."
            });
        } else {
            result.findings.push_back({
                Severity::INFO,
                "Firewall",
                "IPv6 firewall active",
                "ip6tables rules: " + std::to_string(st.v6_rules) +
                (st.v6_input_policy.empty() ? "" : "  |  INPUT default policy: " + st.v6_input_policy)
            });
        }
    } else {
        result.findings.push_back({
            Severity::INFO,
            "Firewall",
            "No globally routable IPv6 — IPv6 firewall not critical",
            ""
        });
    }

    // Warn if iptables is UFW/firewalld abstracted and ip6tables may not be covered
    if ((st.ufw_active || st.firewalld_active) && !st.ip6tables_active && !st.nftables_active) {
        result.findings.push_back({
            Severity::LOW,
            "Firewall",
            "Verify that UFW/firewalld covers IPv6 (ufw default deny incoming + IPv6=yes in /etc/default/ufw)",
            "Some UFW configurations don't apply rules to IPv6 by default"
        });
    }

    return result;
}
