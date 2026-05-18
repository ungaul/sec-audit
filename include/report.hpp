#pragma once
#include "types.hpp"
#include <vector>

void print_header();
void print_check_result(const CheckResult& r);
void print_summary(const std::vector<CheckResult>& results);
