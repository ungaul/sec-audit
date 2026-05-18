#pragma once
#include <string>
#include <vector>
#include <optional>
#include <filesystem>

namespace util {

std::string exec(const std::string& cmd);
std::vector<std::string> split_lines(const std::string& s);
std::vector<std::string> split(const std::string& s, char delim);
std::string trim(const std::string& s);
bool file_readable(const std::string& path);
std::optional<std::string> read_file(const std::string& path);
std::vector<std::string> glob_files(const std::string& pattern);
bool is_root();

}
