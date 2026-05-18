cmake_minimum_required(VERSION 3.20)
project(sec-audit LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Hardened build flags
add_compile_options(
    -O2
    -Wall
    -Wextra
    -Wpedantic
    -Wformat=2
    -Wno-unused-parameter
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIE
)

add_link_options(
    -pie
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

include_directories(include)

set(SOURCES
    src/main.cpp
    src/util.cpp
    src/report.cpp
    src/checks/exposure.cpp
    src/checks/telemetry.cpp
    src/checks/dns.cpp
    src/checks/ports.cpp
    src/checks/firewall.cpp
    src/checks/ssh.cpp
    src/checks/systemd.cpp
    src/checks/kernel.cpp
    src/checks/filesystem.cpp
    src/checks/users.cpp
    src/checks/software.cpp
    src/checks/usb.cpp
    src/checks/cron.cpp
    src/checks/credentials.cpp
    src/checks/processes.cpp
)

add_executable(sec-audit ${SOURCES})

# Link only what's needed (stdc++fs for std::filesystem on older GCC)
target_link_libraries(sec-audit PRIVATE stdc++ m)

install(TARGETS sec-audit DESTINATION bin)

# ── Optional runtime tools ────────────────────────────────────────────────────
# These are system binaries used at runtime, not build-time libraries.
# The tool degrades gracefully when they are absent, but noting them here
# mirrors what a PKGBUILD optdepends block would say.
message(STATUS "Checking optional runtime tools:")
foreach(tool
    "host"          # bind-tools  — telemetry DNS resolution
    "lsusb"         # usbutils    — USB device enumeration
    "lsmod"         # kmod        — kernel module inspection
    "usbguard"      # usbguard    — USB device authorization
    "ss"            # iproute2    — socket/port inspection
    "ip"            # iproute2    — network interface info
    "systemctl"     # systemd     — service and timer inspection
    "curl"          # curl        — external IP / geolocation lookup
)
    find_program(TOOL_${tool} ${tool})
    if(TOOL_${tool})
        message(STATUS "  [found] ${tool}")
    else()
        message(STATUS "  [missing] ${tool}")
    endif()
endforeach()
