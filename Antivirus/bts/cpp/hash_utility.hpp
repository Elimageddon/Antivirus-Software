#ifndef HASH_UTILITY_HPP
#define HASH_UTILITY_HPP

#include <string>
#include <vector>
#include <filesystem>
#include <unordered_map>
#include <unordered_set>

std::unordered_map<std::string, std::unordered_set<std::string>> load_multi_hash_db(const std::string &path);

#endif