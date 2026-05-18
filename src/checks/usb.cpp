#include "types.hpp"
#include "util.hpp"
#include <filesystem>
#include <regex>

namespace fs = std::filesystem;

CheckResult check_usb() {
    CheckResult result;
    result.name = "USB & Physical Attack Surface";

    // ── USBGuard ──────────────────────────────────────────────────────────────
    {
        bool running = util::trim(
            util::exec("systemctl is-active usbguard 2>/dev/null")) == "active";
        bool installed = !util::trim(util::exec("which usbguard 2>/dev/null")).empty();

        if (!installed) {
            result.findings.push_back({Severity::MEDIUM, "USB",
                "USBGuard is not installed",
                "USBGuard enforces a whitelist of authorized USB devices, "
                "preventing BadUSB / Rubber Ducky attacks. "
                "Install: sudo pacman -S usbguard"});
        } else if (!running) {
            result.findings.push_back({Severity::MEDIUM, "USB",
                "USBGuard is installed but not running",
                "USB device authorization is not enforced. "
                "Enable: sudo systemctl enable --now usbguard"});
        } else {
            // USBGuard is active — check default policy
            std::string policy = util::trim(util::exec(
                "usbguard get-parameter InsertedDevicePolicy 2>/dev/null"));
            if (policy == "apply-policy") {
                result.findings.push_back({Severity::INFO, "USB",
                    "USBGuard active — USB device whitelist enforced", ""});
            } else if (policy == "allow") {
                result.findings.push_back({Severity::HIGH, "USB",
                    "USBGuard running but InsertedDevicePolicy=allow",
                    "All newly inserted USB devices are allowed. "
                    "Change to: usbguard set-parameter InsertedDevicePolicy apply-policy"});
            } else {
                result.findings.push_back({Severity::INFO, "USB",
                    "USBGuard active (policy: " + (policy.empty() ? "unknown" : policy) + ")",
                    ""});
            }
        }
    }

    // ── usb_storage kernel module ─────────────────────────────────────────────
    {
        std::string lsmod = util::exec("lsmod 2>/dev/null");
        bool loaded = lsmod.find("usb_storage") != std::string::npos;

        if (loaded) {
            result.findings.push_back({Severity::LOW, "USB",
                "usb_storage kernel module is loaded",
                "USB mass storage devices (thumb drives, external disks) can be mounted. "
                "If not needed: sudo modprobe -r usb_storage && "
                "echo 'blacklist usb_storage' | sudo tee /etc/modprobe.d/no-usb-storage.conf"});
        } else {
            // Check if it's blacklisted
            bool blacklisted = false;
            for (const auto& f : util::glob_files("/etc/modprobe.d/*.conf")) {
                auto c = util::read_file(f);
                if (c && c->find("usb_storage") != std::string::npos &&
                    c->find("blacklist") != std::string::npos) {
                    blacklisted = true;
                    break;
                }
            }
            if (blacklisted) {
                result.findings.push_back({Severity::INFO, "USB",
                    "usb_storage is blacklisted — USB mass storage disabled", ""});
            } else {
                result.findings.push_back({Severity::INFO, "USB",
                    "usb_storage module not currently loaded",
                    "USB mass storage is not active (but could be loaded on demand)"});
            }
        }
    }

    // ── Thunderbolt security ───────────────────────────────────────────────────
    {
        bool has_tb = false;
        for (const auto& dev : util::glob_files("/sys/bus/thunderbolt/devices/*")) {
            std::string sec_path = dev + "/security";
            auto sec = util::read_file(sec_path);
            if (!sec) continue;
            has_tb = true;
            std::string level = util::trim(*sec);
            if (level == "none") {
                result.findings.push_back({Severity::CRITICAL, "USB",
                    "Thunderbolt security level: none (" + dev + ")",
                    "All Thunderbolt devices are authorized automatically — DMA attacks possible. "
                    "Set security level to 'user' or 'secure' in BIOS/UEFI."});
            } else if (level == "user") {
                result.findings.push_back({Severity::INFO, "USB",
                    "Thunderbolt security: user authorization required (" + dev + ")", ""});
            } else if (level == "secure") {
                result.findings.push_back({Severity::INFO, "USB",
                    "Thunderbolt security: secure mode (" + dev + ")", ""});
            } else if (level == "dponly") {
                result.findings.push_back({Severity::INFO, "USB",
                    "Thunderbolt security: DisplayPort only (" + dev + ")", ""});
            } else {
                result.findings.push_back({Severity::LOW, "USB",
                    "Thunderbolt security level unknown: " + level + " (" + dev + ")", ""});
            }
        }
        if (!has_tb) {
            result.findings.push_back({Severity::INFO, "USB",
                "No Thunderbolt controllers detected", ""});
        }
    }

    // ── Connected USB devices (informational) ─────────────────────────────────
    {
        std::string lsusb = util::exec("lsusb 2>/dev/null");
        if (!lsusb.empty()) {
            auto lines = util::split_lines(lsusb);
            // Filter out hubs and root hubs — flag any non-HID, non-hub device
            std::vector<std::string> notable;
            for (const auto& line : lines) {
                std::string lower = line;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                // Skip any hub variant (root hub, rate matching hub, transaction translator hub…)
                if (lower.find("hub") != std::string::npos) continue;
                // Skip keyboards and mice
                if (lower.find("keyboard") != std::string::npos ||
                    lower.find("mouse")    != std::string::npos ||
                    lower.find("optical")  != std::string::npos) continue;
                notable.push_back(line);
            }
            if (!notable.empty()) {
                std::string detail;
                for (size_t i = 0; i < std::min(notable.size(), size_t(5)); ++i) {
                    if (i) detail += "  |  ";
                    detail += util::trim(notable[i]);
                }
                if (notable.size() > 5)
                    detail += "  (+  " + std::to_string(notable.size()-5) + " more)";
                result.findings.push_back({Severity::INFO, "USB",
                    std::to_string(notable.size()) + " non-hub USB device(s) connected",
                    detail});
            }
        }
    }

    // ── Automatic mounting of removable media ─────────────────────────────────
    {
        // Check for udisks2 automount (common on desktops)
        bool udisks = !util::exec("pgrep -x udisksd 2>/dev/null").empty() ||
                      !util::exec("pgrep udisks2 2>/dev/null").empty();
        if (udisks) {
            result.findings.push_back({Severity::LOW, "USB",
                "udisks2 is running — removable media auto-mounted",
                "USB drives are automatically mounted when plugged in. "
                "Consider disabling automount if physical security is a concern."});
        }
    }

    return result;
}
