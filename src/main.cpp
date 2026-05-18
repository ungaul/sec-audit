#include "report.hpp"
#include "types.hpp"
#include "util.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

// Forward declarations
CheckResult check_exposure();
CheckResult check_telemetry();
CheckResult check_dns();
CheckResult check_ports();
CheckResult check_firewall();
CheckResult check_ssh();
CheckResult check_systemd();
CheckResult check_kernel();
CheckResult check_filesystem();
CheckResult check_users();
CheckResult check_software();
CheckResult check_usb();
CheckResult check_cron();
CheckResult check_credentials();
CheckResult check_processes();

static void usage(const char* prog) {
    fprintf(stderr, "Usage: %s [--check <name>] [--offline] [--help]\n\n", prog);
    fprintf(stderr, "Checks:\n");
    fprintf(stderr, "  exposure     External IP, geolocation, IPv6 direct reachability\n");
    fprintf(stderr, "  telemetry    Outbound connections to tracking endpoints\n");
    fprintf(stderr, "  dns          DNS configuration and leak check\n");
    fprintf(stderr, "  ports        Listening ports and exposed services\n");
    fprintf(stderr, "  firewall     iptables / nftables / ufw posture\n");
    fprintf(stderr, "  ssh          SSH server hardening\n");
    fprintf(stderr, "  systemd      Suspicious systemd services and timers\n");
    fprintf(stderr, "  kernel       Kernel sysctl security parameters\n");
    fprintf(stderr, "  filesystem   SUID binaries, world-writable dirs, mount options\n");
    fprintf(stderr, "  users        User accounts, sudoers, shadow, password policy\n");
    fprintf(stderr, "  software     Pending updates, AppArmor/SELinux, security tools\n");
    fprintf(stderr, "  usb          USB attack surface (USBGuard, Thunderbolt)\n");
    fprintf(stderr, "  cron         Scheduled tasks and cron job permissions\n");
    fprintf(stderr, "  credentials  Secrets in shell history and config files\n");
    fprintf(stderr, "  processes    Processes making unexpected network calls\n");
    fprintf(stderr, "\nFlags:\n");
    fprintf(stderr, "  --offline    Skip checks that make outbound network requests\n");
    fprintf(stderr, "               (external IP lookup in 'exposure' check)\n");
    fprintf(stderr, "\nRun without arguments to run all checks.\n");
}

// Passed via environment so check functions can read it without threading
static bool g_offline = false;

int main(int argc, char* argv[]) {
    std::vector<std::string> run_checks;
    bool help = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            help = true;
        } else if (arg == "--check" && i + 1 < argc) {
            run_checks.push_back(argv[++i]);
        } else if (arg == "--offline") {
            g_offline = true;
            setenv("SEC_AUDIT_OFFLINE", "1", 1);
        } else if (arg == "--no-color") {
            // color is driven by isatty(); redirect stdout to disable
        } else {
            fprintf(stderr, "Unknown argument: %s\n", arg.c_str());
            usage(argv[0]);
            return 1;
        }
    }

    if (help) {
        usage(argv[0]);
        return 0;
    }

    struct CheckEntry {
        std::string name;
        Check fn;
    };

    std::vector<CheckEntry> all_checks = {
        {"exposure",    check_exposure},
        {"telemetry",   check_telemetry},
        {"dns",         check_dns},
        {"ports",       check_ports},
        {"firewall",    check_firewall},
        {"ssh",         check_ssh},
        {"systemd",     check_systemd},
        {"kernel",      check_kernel},
        {"filesystem",  check_filesystem},
        {"users",       check_users},
        {"software",    check_software},
        {"usb",         check_usb},
        {"cron",        check_cron},
        {"credentials", check_credentials},
        {"processes",   check_processes},
    };

    std::vector<CheckEntry> to_run;
    if (run_checks.empty()) {
        to_run = all_checks;
    } else {
        for (const auto& name : run_checks) {
            bool found = false;
            for (const auto& ce : all_checks) {
                if (ce.name == name) {
                    to_run.push_back(ce);
                    found = true;
                    break;
                }
            }
            if (!found) {
                fprintf(stderr, "Unknown check: %s\n", name.c_str());
                usage(argv[0]);
                return 1;
            }
        }
    }

    print_header();

    if (!util::is_root()) {
        fprintf(stderr, "\033[33m[!] Running without root — some checks have limited visibility (firewall rules, all processes).\033[0m\n\n");
    }
    if (g_offline) {
        fprintf(stderr, "\033[36m[i] Offline mode — external IP / geolocation lookup skipped.\033[0m\n\n");
    }

    std::vector<CheckResult> results;
    for (const auto& ce : to_run) {
        CheckResult r;
        try {
            r = ce.fn();
        } catch (const std::exception& ex) {
            r.name = ce.name;
            r.ran  = false;
            r.error = ex.what();
        } catch (...) {
            r.name  = ce.name;
            r.ran   = false;
            r.error = "unknown exception";
        }
        results.push_back(r);
        print_check_result(r);
    }

    print_summary(results);
    return 0;
}
