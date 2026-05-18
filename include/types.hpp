#pragma once
#include <string>
#include <vector>
#include <functional>

enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL };

struct Finding {
    Severity severity;
    std::string category;
    std::string title;
    std::string detail;
};

struct CheckResult {
    std::string name;
    std::vector<Finding> findings;
    bool ran = true;
    std::string error;
};

using Check = std::function<CheckResult()>;
