#include "report.hpp"
#include <cstdio>
#include <unistd.h>
#include <map>
#include <algorithm>

static bool color_enabled() {
    return isatty(STDOUT_FILENO);
}

static const char* sev_color(Severity s) {
    if (!color_enabled()) return "";
    switch (s) {
        case Severity::INFO:     return "\033[36m";
        case Severity::LOW:      return "\033[32m";
        case Severity::MEDIUM:   return "\033[33m";
        case Severity::HIGH:     return "\033[31m";
        case Severity::CRITICAL: return "\033[1;31m";
    }
    return "";
}

static const char* reset() {
    return color_enabled() ? "\033[0m" : "";
}

static const char* bold() {
    return color_enabled() ? "\033[1m" : "";
}

static const char* dim() {
    return color_enabled() ? "\033[2m" : "";
}

static const char* sev_label(Severity s) {
    switch (s) {
        case Severity::INFO:     return "INFO    ";
        case Severity::LOW:      return "LOW     ";
        case Severity::MEDIUM:   return "MEDIUM  ";
        case Severity::HIGH:     return "HIGH    ";
        case Severity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN ";
}


void print_header() {
    printf("\n%s╔══════════════════════════════════════════════════════╗%s\n", bold(), reset());
    printf("%s║           sec-audit — Linux Security Auditor         ║%s\n", bold(), reset());
    printf("%s╚══════════════════════════════════════════════════════╝%s\n\n", bold(), reset());
}

void print_check_result(const CheckResult& r) {
    printf("%s▶ %s%s\n", bold(), r.name.c_str(), reset());

    if (!r.ran) {
        printf("  %s[SKIP] %s%s\n\n", dim(), r.error.c_str(), reset());
        return;
    }

    if (r.findings.empty()) {
        printf("  %s[✓] No issues found%s\n\n", "\033[32m", reset());
        return;
    }

    for (const auto& f : r.findings) {
        printf("  %s[%s]%s %s%s%s\n",
               sev_color(f.severity), sev_label(f.severity), reset(),
               bold(), f.title.c_str(), reset());
        if (!f.detail.empty()) {
            // Wrap detail at 76 chars, indented 12 spaces
            std::string det = f.detail;
            size_t pos = 0;
            while (pos < det.size()) {
                size_t end = std::min(pos + 76, det.size());
                // try to break at space
                if (end < det.size()) {
                    size_t sp = det.rfind(' ', end);
                    if (sp != std::string::npos && sp > pos) end = sp;
                }
                printf("            %s%s%s\n", dim(), det.substr(pos, end - pos).c_str(), reset());
                pos = (end < det.size() && det[end] == ' ') ? end + 1 : end;
            }
        }
    }
    printf("\n");
}

void print_summary(const std::vector<CheckResult>& results) {
    std::map<Severity, int> counts;
    int total = 0;

    for (const auto& r : results) {
        for (const auto& f : r.findings) {
            counts[f.severity]++;
            total++;
        }
    }

    printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", bold(), reset());
    printf("%sSUMMARY%s  ", bold(), reset());

    if (total == 0) {
        printf("%s No findings — system looks clean.%s\n", "\033[32m", reset());
    } else {
        printf("%d finding(s)  ", total);
        for (auto sev : {Severity::CRITICAL, Severity::HIGH, Severity::MEDIUM,
                         Severity::LOW, Severity::INFO}) {
            auto it = counts.find(sev);
            if (it != counts.end() && it->second > 0) {
                printf("%s%s:%d%s  ",
                       sev_color(sev), sev_label(sev), it->second, reset());
            }
        }
        printf("\n");
    }
    printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n", bold(), reset());
}
