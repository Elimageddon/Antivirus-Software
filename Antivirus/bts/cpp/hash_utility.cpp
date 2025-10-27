#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>


// HEX-TO-BYTES CONVERSION (Utility Function)

uint8_t hex_char_to_value(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    throw std::invalid_argument("Invalid hex character");
}

// HEX STRING NORMALIZATION (Utility Function)
static std::string normalize_hex_string(const std::string &line) {
    std::string normalized;
    normalized.reserve(line.size());

    for (size_t i = 0; i < line.size();) {
        char c = line[i];

        // Skip whitespace
        if (std::isspace(static_cast<unsigned char>(c)))
            continue;

        // Skip '0x' or '0X' prefixes
        if (c == '0' && (i + 1 < line.size()) && (line[i + 1] == 'x' || line[i + 1] == 'X')) {
            ++i; // Skip the 'x'
            continue;
        }

        // Validate hex characters (0-9, a-f, A-F)
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            throw std::invalid_argument("Invalid hex character in input");
        }
            
        // Lowercase
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        ++i;

    }

    if (normalized.size() % 2 != 0) {
        throw std::invalid_argument("Odd-length hex string after normalization");

    }

    return normalized;
}

// Functions

// HEX STRING TO BYTE ARRAY CONVERSION
std::vector<uint8_t> hex_to_bytes(const std::string &hex) {
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("Hex string must have an even length");

    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t high = hex_char_to_value(hex[i]);
        uint8_t low = hex_char_to_value(hex[i + 1]);
        out.push_back((high << 4) | low);
    }

    return out;
}

// COMPUTE SHA-256 HASH
std::vector<uint8_t> sha256_bytes(const std::vector<uint8_t>& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    auto ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
        EVP_MD_CTX_new(), &EVP_MD_CTX_free
    );

    // Error-handling (Creation Failure)
    if (!ctx) throw std::runtime_error("Failed to create EVP_MD_CTX");

    // Run the SHA-256 hash computation (fail-fast)
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), hash, &hash_len) != 1) {
        throw std::runtime_error("SHA-256 computation failed");
    }

    // Return the hash as a vector of bytes
    return std::vector<uint8_t>(hash, hash + hash_len);
}

// SHA-256 HASH BYTES TO HEX STRING CONVERSION
std::string sha256_hex(const std::vector<uint8_t>& data) {
    auto bytes = sha256_bytes(data); // hash to bytes

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (uint8_t byte : bytes)
        oss << std::setw(2) << static_cast<int>(byte);

    return oss.str();
}

// LOAD HASH DATABASE
std::unordered_map<std::string, std::unordered_set<std::string>> load_multi_hash_db(const std::string &path) {
    std::unordered_map<std::string, std::unordered_set<std::string>> db;
    std::ifstream ifs(path);
    if(!ifs.is_open())
        throw std::runtime_error("Could not open hash database: " + path);
    
    std::string line;
    size_t lineno = 0;

    while (std::getline(ifs, line)) {
        ++lineno;
        if (line.empty() || line[0] == '#')
            continue;

        std::istringstream iss(line);
        std::string alg, hash;

        if (!std::getline(iss, alg, ':') || !std::getline(iss, hash)) {
            throw std::runtime_error("Invalid format in hash database at line " + std::to_string(lineno));
        }

        try {
            std::string hash_value = normalize_hex_string(hash);
            db[alg].insert(hash_value);
        } catch (const std::invalid_argument &e) {
            std::cerr << "[Error] Line " << lineno << ": " << e.what() << " (in " << path << ")\n";
    }

    }
    
    return db;
}

// LOAD HEX SIGNATURES
std::vector<std::vector<uint8_t>> load_signatures(const std::string &path) {
    std::vector<std::vector<uint8_t>> sigs;
    std::ifstream ifs(path);
    std::string line;
    size_t lineno = 0;

    if (!ifs.is_open())
        throw std::runtime_error("Could not open signature database: " + path);

    while (std::getline(ifs, line)) {
        ++lineno;
        if (line.empty() || line[0] == '#')
        continue;
        try {
            line = normalize_hex_string(line);
            auto b = hex_to_bytes(line);
            if (!b.empty()) sigs.push_back(std::move(b));
        } catch (const std::invalid_argument &e) {
            std::cerr << "[Error] Line " << ": " << e.what() << path <<"\n";
        }

    }
    return sigs;
}