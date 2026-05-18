#include "util.hpp"
#include <array>
#include <cstdio>
#include <stdexcept>
#include <sstream>
#include <fstream>
#include <glob.h>
#include <unistd.h>

namespace util {

std::string exec(const std::string& cmd) {
    std::string safe = cmd + " 2>/dev/null";
    std::array<char, 4096> buf{};
    std::string result;
    FILE* pipe = popen(safe.c_str(), "r");
    if (!pipe) return {};
    while (fgets(buf.data(), buf.size(), pipe)) result += buf.data();
    pclose(pipe);
    return result;
}

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> lines;
    std::istringstream ss(s);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty()) lines.push_back(line);
    }
    return lines;
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::istringstream ss(s);
    std::string part;
    while (std::getline(ss, part, delim)) parts.push_back(part);
    return parts;
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool file_readable(const std::string& path) {
    return access(path.c_str(), R_OK) == 0;
}

std::optional<std::string> read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::vector<std::string> glob_files(const std::string& pattern) {
    std::vector<std::string> result;
    glob_t g{};
    if (glob(pattern.c_str(), GLOB_TILDE | GLOB_NOSORT, nullptr, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc; ++i)
            result.emplace_back(g.gl_pathv[i]);
    }
    globfree(&g);
    return result;
}

bool is_root() {
    return geteuid() == 0;
}

} // namespace util
