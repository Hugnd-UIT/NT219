#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <string>
#include <cstdio>
#include <iomanip>
#include <set>
#include <openssl/evp.h>
#include <openssl/provider.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #include <sys/resource.h>
    #include <sys/time.h>
#endif

//////////////////////////////////////////////////////////////
// OpenSSL
//////////////////////////////////////////////////////////////

static int g_initialized = 0;

void init_openssl() {
    if (!g_initialized) {
        OSSL_PROVIDER_load(NULL, "default");
        g_initialized = 1;
    }
}

//////////////////////////////////////////////////////////////
// Utility
//////////////////////////////////////////////////////////////

void print_hex(const std::vector<unsigned char>& data) {
    for (unsigned char c : data) {
        std::printf("%02x", c);
    }
    std::printf("\n");
}

std::string to_hex_string(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    for (unsigned char c : data) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return ss.str();
}

//////////////////////////////////////////////////////////////
// Validation
//////////////////////////////////////////////////////////////

bool validate_fix_algo(const std::string& algo) {
    static const std::set<std::string> valid_algos = {
        "sha224", "sha256", "sha384", "sha512",
        "sha3-224", "sha3-256", "sha3-384", "sha3-512",
        "shake128", "shake256"
    };
    return valid_algos.count(algo) > 0;
}

bool validate_xof_algo(const std::string& algo) {
    return (algo == "shake128" || algo == "shake256");
}

//////////////////////////////////////////////////////////////
// Hash Class
//////////////////////////////////////////////////////////////

class Hasher {
private:
    const EVP_MD* md;
    std::string algorithm_name;
    bool is_xof;

public:
    explicit Hasher(const std::string& algo) {
        if (!validate_fix_algo(algo)) {
            throw std::invalid_argument("[ERROR] Unsupported or disabled hash algorithm: " + algo);
        }

        init_openssl();
        algorithm_name = algo;
        is_xof = validate_xof_algo(algo);

        md = EVP_get_digestbyname(algo.c_str());
        if (!md) {
            throw std::runtime_error("[ERROR] OpenSSL cannot initialize algorithm: " + algo);
        }
    }

    std::vector<unsigned char> hash_data(const unsigned char* data, size_t len, int xof_outlen = -1) {
        if (!data && len > 0) throw std::runtime_error("[ERROR] Input data is null.");

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("[ERROR] EVP_MD_CTX_new failed.");

        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("[ERROR] DigestInit failed.");
        }

        if (len > 0 && EVP_DigestUpdate(ctx, data, len) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("[ERROR] DigestUpdate failed.");
        }

        std::vector<unsigned char> digest;
        if (is_xof) {
            if (xof_outlen <= 0) {
                EVP_MD_CTX_free(ctx);
                throw std::invalid_argument("[ERROR] SHAKE XOF requires --outlen > 0.");
            }
            digest.resize(xof_outlen);
            if (EVP_DigestFinalXOF(ctx, digest.data(), xof_outlen) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("[ERROR] DigestFinalXOF failed.");
            }
        } else {
            unsigned int digest_len = 0;
            digest.resize(EVP_MAX_MD_SIZE);
            if (EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("[ERROR] DigestFinal failed.");
            }
            digest.resize(digest_len);
        }

        EVP_MD_CTX_free(ctx);
        return digest;
    }

    std::vector<unsigned char> hash_file_stream(const std::string& filename, int xof_outlen = -1) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) throw std::runtime_error("[ERROR] Cannot open input file: " + filename);

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("[ERROR] DigestInit failed.");
        }

        const size_t buffer_size = 8192;
        char buffer[buffer_size];

        while (file.good()) {
            file.read(buffer, buffer_size);
            std::streamsize bytes = file.gcount();
            if (bytes > 0) {
                if (EVP_DigestUpdate(ctx, reinterpret_cast<const unsigned char*>(buffer), static_cast<size_t>(bytes)) != 1) {
                    EVP_MD_CTX_free(ctx);
                    throw std::runtime_error("[ERROR] DigestUpdate failed.");
                }
            }
        }

        std::vector<unsigned char> digest;
        if (is_xof) {
            if (xof_outlen <= 0) {
                EVP_MD_CTX_free(ctx);
                throw std::invalid_argument("[ERROR] SHAKE XOF requires --outlen > 0.");
            }
            digest.resize(xof_outlen);
            if (EVP_DigestFinalXOF(ctx, digest.data(), xof_outlen) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("[ERROR] DigestFinalXOF failed.");
            }
        } else {
            unsigned int digest_len = 0;
            digest.resize(EVP_MAX_MD_SIZE);
            if (EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("[ERROR] DigestFinal failed.");
            }
            digest.resize(digest_len);
        }

        EVP_MD_CTX_free(ctx);
        return digest;
    }

    std::vector<unsigned char> hash_file_mmap(const std::string& filename, int xof_outlen = -1) {
#ifdef _WIN32
        HANDLE hFile = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) throw std::runtime_error("[ERROR] Cannot open file for mmap (Win32).");

        LARGE_INTEGER size;
        GetFileSizeEx(hFile, &size);
        if (size.QuadPart == 0) {
            CloseHandle(hFile);
            std::cout << "[WARNING] Input file is empty. Hashing empty input." << std::endl;
            return hash_data(nullptr, 0, xof_outlen);
        }

        HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!hMap) { CloseHandle(hFile); throw std::runtime_error("[ERROR] CreateFileMapping failed."); }

        const unsigned char* data = static_cast<const unsigned char*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
        if (!data) { CloseHandle(hMap); CloseHandle(hFile); throw std::runtime_error("[ERROR] MapViewOfFile failed."); }

        std::vector<unsigned char> digest = hash_data(data, size.QuadPart, xof_outlen);

        UnmapViewOfFile(data);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return digest;
#else
        int fd = open(filename.c_str(), O_RDONLY);
        if (fd < 0) throw std::runtime_error("[ERROR] Cannot open file for mmap (UNIX).");

        struct stat sb;
        if (fstat(fd, &sb) < 0) { close(fd); throw std::runtime_error("[ERROR] fstat failed."); }
        if (sb.st_size == 0) {
            close(fd);
            std::cout << "[WARNING] Input file is empty. Hashing empty input." << std::endl;
            return hash_data(nullptr, 0, xof_outlen);
        }

        const unsigned char* data = static_cast<const unsigned char*>(mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
        if (data == MAP_FAILED) { close(fd); throw std::runtime_error("[ERROR] mmap failed."); }

        std::vector<unsigned char> digest = hash_data(data, sb.st_size, xof_outlen);

        munmap(const_cast<unsigned char*>(data), sb.st_size);
        close(fd);
        return digest;
#endif
    }
};

//////////////////////////////////////////////////////////////
// CLI
//////////////////////////////////////////////////////////////

void print_banner() {

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8); 
#endif

    std::cout <<
        "\n"
        "  ██╗  ██╗ █████╗ ███████╗██╗  ██╗\n"
        "  ██║  ██║██╔══██╗██╔════╝██║  ██║\n"
        "  ███████║███████║███████╗███████║\n"
        "  ██╔══██║██╔══██║╚════██║██╔══██║\n"
        "  ██║  ██║██║  ██║███████║██║  ██║\n"
        "  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n"
        "\n"
    << std::endl;
}

void print_usage() {
    std::cout
        << "Usage:\n"
        << "  ./hashtool [options]\n"
        << "\n"

        << "Required:\n"
        << "  --algo <algorithm>\n"
        << "  --in <input>\n"
        << "\n"

        << "Options:\n"
        << "  --out <output>\n"
        << "  --outlen <bytes>\n"
        << "  --stream\n"
        << "  --mmap\n"
        << "\n"

        << "Algorithms:\n"
        << "  sha224 sha256 sha384 sha512\n"
        << "  sha3-224 sha3-256 sha3-384 sha3-512\n"
        << "  shake128 shake256\n"
    << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_banner();
        print_usage();
        return 1;
    }

    std::string algo, infile, outfile;
    int outlen = -1;
    bool use_stream = false;
    bool use_mmap = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--algo" && i + 1 < argc) {
            algo = argv[++i];
        } else if (arg == "--in" && i + 1 < argc) {
            infile = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            outfile = argv[++i];
        } else if (arg == "--outlen" && i + 1 < argc) {
            try {
                outlen = std::stoi(argv[++i]);
            } catch (...) {
                std::cerr << "[ERROR] --outlen must be a valid integer." << std::endl;
                return 1;
            }
        } else if (arg == "--stream") {
            use_stream = true;
        } else if (arg == "--mmap") {
            use_mmap = true;
        } else {
            std::cerr << "[ERROR] Unknown argument '" << arg << "'." << std::endl;
            print_usage();
            return 1;
        }
    }

    try {
        if (algo.empty() || infile.empty()) {
            std::cerr << "[ERROR] Missing required parameters: --algo and --in." << std::endl;
            print_usage();
            return 1;
        }

        if (!validate_fix_algo(algo)) {
            std::cerr << "[ERROR] Unsupported algorithm '" << algo << "'." << std::endl;
            return 1;
        }

        if (validate_xof_algo(algo) && outlen <= 0) {
            std::cerr << "[ERROR] Algorithm '" << algo << "' is an XOF and requires --outlen > 0." << std::endl;
            return 1;
        }

        if (use_stream && use_mmap) {
            std::cerr << "[ERROR] Cannot specify both --stream and --mmap." << std::endl;
            return 1;
        }

        if (!use_mmap) {
            use_stream = true;
        }

        std::cout << "[INFO] Algorithm  : " << algo << std::endl;
        std::cout << "[INFO] Input file : " << infile << std::endl;
        std::cout << "[INFO] I/O mode   : " << (use_mmap ? "Memory-mapped" : "Streamed") << std::endl;
        if (validate_xof_algo(algo)) {
            std::cout << "[INFO] Output len : " << outlen << " bytes" << std::endl;
        }

        Hasher hasher(algo);
        std::vector<unsigned char> digest;

        if (use_mmap) {
            digest = hasher.hash_file_mmap(infile, outlen);
        } else {
            digest = hasher.hash_file_stream(infile, outlen);
        }

        std::cout << "[INFO] Digest     : ";
        print_hex(digest);

        if (!outfile.empty()) {
            std::ofstream outbin(outfile, std::ios::binary);
            if (!outbin) {
                throw std::runtime_error("[ERROR] Failed to open output file: " + outfile);
            }
            outbin.write(reinterpret_cast<const char*>(digest.data()), digest.size());
            std::cout << "[INFO] Binary digest saved to: " << outfile << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}