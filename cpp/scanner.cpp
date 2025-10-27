#include <filesystem>

#include "BS_thread_pool.hpp"
// For I/O-heavy tasks like reading files and hashing, you may want:
// size_t num_threads = std::thread::hardware_concurrency() * 2;
#include "hash_utility.hpp"

namespace fs = std::filesystem;

// READS ENTIRE FILE INTO VECTOR (DEMO)
bool read_file_binary(const fs::path &p, std::vector<uint8_t> &out) {
    std::ifstream ifs(p, std::binary);
    if (!ifs) return false;
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    out.resize(size);
    ifs.read(reinterpret_cast<char*>(out.data()), size);
    return true;
}

int main() {

    std::string hash_db_path = argv[1];

    auto hash_db = load_multi_hash_db(hash_db_path);

    fs:recursive_directory_iterator end;
    const int MAX_DEPTH = 100;

    try {

        for (fs::recursive_directory_iterator entry(scan_path, fs::directory_options::skip_permission_denied); entry != end; ++entry)
        {
            if (entry.depth() > MAX_DEPTH) {
                entry.disable_recursion_pending(); // end recursion at 100 levels
                continue;
            }
            if (!entry->is_regular_file()) continue; // files only
            if (entry->is_symlink()) continue; // skip symlinks

            fs::path p = entry->path();
            std::vector<uint8_t> data;

            if (!read_file_binary(p, data)) { // error handling
                std::cerr << "Could not read: " << p << "\n";
                continue;
            }

            std::string h = sha256_hex(data);

            if (bad_hashes.find(h) != bad_hashes.end()) {
                std::cout << "INFECTED - HASH"
            }

        }

    }
}
