#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <sstream>
#include <vector>
#include <iomanip>
#include <set>
#include <stdexcept>
#include <cstdint>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/provider.h>

using namespace std;
namespace fs = std::filesystem;

// Utilities

string HexEncode(const uint8_t* data, size_t len)
{
    stringstream ss;
    for (size_t i = 0; i < len; ++i)
    {
        ss << hex << setw(2) << setfill('0') << (int)data[i];
    }
    return ss.str();
}

string Base64Encode(const uint8_t* data, size_t len)
{
    if (len == 0)
        return "";

    size_t b64Len = 4 * ((len + 2) / 3);
    string result(b64Len + 1, '\0');
    int ret = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(result.data()), data, static_cast<int>(len));
    if (ret < 0)
        throw runtime_error("[ERROR] Encode failed!");
    result.resize(ret);
    return result;
}

static int g_initialized = 0;

void OpenSSL()
{
    if (!g_initialized)
    {
        OSSL_PROVIDER_load(NULL, "default");
        g_initialized = 1;
    }
}

// Validations

void ValidateAlgo(const string& algo)
{
    static const set<string> validAlgos = {
        "sha224", "sha256", "sha384", "sha512",
        "sha3-224", "sha3-256", "sha3-384", "sha3-512",
        "shake128", "shake256"
    };
    if (validAlgos.count(algo) == 0)
        throw runtime_error("[ERROR] Invalid algorithm!");
}

// Operations

vector<uint8_t> HashData(const string& algo, const uint8_t* data, size_t len, int outLen = -1)
{
    OpenSSL();

    const EVP_MD* md = EVP_get_digestbyname(algo.c_str());
    if (!md)
        throw runtime_error("[ERROR] Invalid algorithm!");

    bool xof = (algo == "shake128" || algo == "shake256");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw runtime_error("[ERROR] OpenSSL failed!");

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("[ERROR] DigestInit failed!");
    }

    if (len > 0 && EVP_DigestUpdate(ctx, data, len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("[ERROR] DigestUpdate failed!");
    }

    vector<uint8_t> digest;
    if (xof)
    {
        digest.resize(outLen);
        if (EVP_DigestFinalXOF(ctx, digest.data(), outLen) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw runtime_error("[ERROR] DigestFinal failed!");
        }
    }
    else
    {
        unsigned int digestLen = 0;
        digest.resize(EVP_MAX_MD_SIZE);
        if (EVP_DigestFinal_ex(ctx, digest.data(), &digestLen) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw runtime_error("[ERROR] DigestFinal failed!");
        }
        digest.resize(digestLen);
    }

    EVP_MD_CTX_free(ctx);
    return digest;
}

vector<uint8_t> HashStream(const string& algo, const string& inFile, int outLen = -1)
{
    OpenSSL();

    const EVP_MD* md = EVP_get_digestbyname(algo.c_str());
    if (!md)
        throw runtime_error("[ERROR] Invalid algorithm!");

    bool xof = (algo == "shake128" || algo == "shake256");

    ifstream file(inFile, ios::binary);
    if (!file)
        throw runtime_error("[ERROR] Invalid input path!");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw runtime_error("[ERROR] OpenSSL failed!");

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("[ERROR] DigestInit failed!");
    }

    const size_t bufSize = 65536;
    vector<char> buffer(bufSize);

    while (file.good())
    {
        file.read(buffer.data(), bufSize);
        streamsize bytes = file.gcount();
        if (bytes > 0)
        {
            if (EVP_DigestUpdate(ctx, reinterpret_cast<const unsigned char*>(buffer.data()), static_cast<size_t>(bytes)) != 1)
            {
                EVP_MD_CTX_free(ctx);
                throw runtime_error("[ERROR] DigestUpdate failed!");
            }
        }
    }

    vector<uint8_t> digest;
    if (xof)
    {
        digest.resize(outLen);
        if (EVP_DigestFinalXOF(ctx, digest.data(), outLen) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw runtime_error("[ERROR] DigestFinal failed!");
        }
    }
    else
    {
        unsigned int digestLen = 0;
        digest.resize(EVP_MAX_MD_SIZE);
        if (EVP_DigestFinal_ex(ctx, digest.data(), &digestLen) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw runtime_error("[ERROR] DigestFinal failed!");
        }
        digest.resize(digestLen);
    }

    EVP_MD_CTX_free(ctx);
    return digest;
}

vector<uint8_t> HashMmap(const string& algo, const string& inFile, int outLen = -1)
{
    uintmax_t fileSize = fs::file_size(inFile);
    if (fileSize == 0)
    {
        cout << "[WARNING] Invalid input file!" << endl;
        return HashData(algo, nullptr, 0, outLen);
    }

#ifdef _WIN32
    HANDLE hFile = CreateFileA(inFile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        throw runtime_error("[ERROR] Invalid input path!");

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap)
    {
        CloseHandle(hFile);
        throw runtime_error("[ERROR] Invalid input path!");
    }

    const unsigned char* data = static_cast<const unsigned char*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!data)
    {
        CloseHandle(hMap);
        CloseHandle(hFile);
        throw runtime_error("[ERROR] Invalid input path!");
    }

    vector<uint8_t> digest = HashData(algo, data, fileSize, outLen);

    UnmapViewOfFile(data);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return digest;
#else
    int fd = open(inFile.c_str(), O_RDONLY);
    if (fd < 0)
        throw runtime_error("[ERROR] Invalid input path!");

    const unsigned char* data = static_cast<const unsigned char*>(mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, fd, 0));
    if (data == MAP_FAILED)
    {
        close(fd);
        throw runtime_error("[ERROR] Invalid input path!");
    }

    vector<uint8_t> digest = HashData(algo, data, fileSize, outLen);

    munmap(const_cast<unsigned char*>(data), fileSize);
    close(fd);
    return digest;
#endif
}

// Dispatchers

vector<uint8_t> HashDispatch(const string& algo, const string& mode, const string& inFile, int outLen = -1)
{
    if (mode == "mmap")
        return HashMmap(algo, inFile, outLen);
    else if (mode == "stream")
        return HashStream(algo, inFile, outLen);
    else
        throw runtime_error("[ERROR] Invalid mode!");
}

// CLI

int main(int argc, char* argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    cout << "\n";
    cout << "  ██╗  ██╗ █████╗ ███████╗██╗  ██╗\n";
    cout << "  ██║  ██║██╔══██╗██╔════╝██║  ██║\n";
    cout << "  ███████║███████║███████╗███████║\n";
    cout << "  ██╔══██║██╔══██║╚════██║██╔══██║\n";
    cout << "  ██║  ██║██║  ██║███████║██║  ██║\n";
    cout << "  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n";
    cout << endl;

    if (argc < 2)
    {
        cout
            << "Usage:\n"
            << "  ./hashtool [options]\n"
            << "\n"

            << "Required:\n"
            << "  --algo <algorithm>\n"
            << "  --in <file> OR --text <text>\n"
            << "\n"

            << "Options:\n"
            << "  --algo <sha224|sha256|sha384|sha512|sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256>\n"
            << "  --in <file>\n"
            << "  --text <text>\n"
            << "  --out <file>\n"
            << "  --outlen <bytes>\n"
            << "  --mode <stream|mmap>\n"
            << "  --stream\n"
            << "  --mmap\n"
            << "  --encode <hex|base64|raw>\n"
            << "  --format <hex|bin>\n"
            << "\n"

            << "Algorithms:\n"
            << "  sha224 sha256 sha384 sha512\n"
            << "  sha3-224 sha3-256 sha3-384 sha3-512\n"
            << "  shake128 shake256\n"
            << "\n";
        return 1;
    }

    string algo      = "";
    string inFile    = "";
    string inText    = "";
    string outFile   = "";
    string mode      = "";
    string encode    = "";
    string fmt       = "";
    int    outLen    = -1;
    bool   useStream = false;
    bool   useMmap   = false;

    for (int i = 1; i < argc; ++i)
    {
        string arg = argv[i];
        if (arg == "--algo" && i + 1 < argc)
            algo = argv[++i];
        else if (arg == "--in" && i + 1 < argc)
            inFile = argv[++i];
        else if (arg == "--text" && i + 1 < argc)
            inText = argv[++i];
        else if (arg == "--out" && i + 1 < argc)
            outFile = argv[++i];
        else if (arg == "--outlen" && i + 1 < argc)
        {
            try
            {
                outLen = stoi(argv[++i]);
            }
            catch (...)
            {
                cerr << "[ERROR] Invalid command!" << endl;
                return 1;
            }
        }
        else if (arg == "--mode" && i + 1 < argc)
            mode = argv[++i];
        else if (arg == "--stream")
            useStream = true;
        else if (arg == "--mmap")
            useMmap = true;
        else if (arg == "--encode" && i + 1 < argc)
            encode = argv[++i];
        else if (arg == "--format" && i + 1 < argc)
            fmt = argv[++i];
        else
        {
            cerr << "[ERROR] Invalid command!" << endl;
            return 1;
        }
    }

    try
    {
        if (algo.empty() || (inFile.empty() && inText.empty()))
        {
            cerr << "[ERROR] Invalid command!" << endl;
            return 1;
        }

        if (useStream && useMmap)
        {
            cerr << "[ERROR] Invalid command!" << endl;
            return 1;
        }

        if (!mode.empty())
        {
            if (mode != "stream" && mode != "mmap")
            {
                cerr << "[ERROR] Invalid mode!" << endl;
                return 1;
            }
            if (useStream || useMmap)
            {
                cerr << "[ERROR] Invalid command!" << endl;
                return 1;
            }
        }
        else
        {
            mode = useMmap ? "mmap" : "stream";
        }

        string temp = "temp";
        bool isTemp = false;

        if (!inText.empty())
        {
            inFile = temp;
            ofstream out(inFile, ios::binary);
            out << inText;
            isTemp = true;
        }
        else if (inFile.empty() || !fs::exists(inFile))
        {
            cerr << "[ERROR] Invalid input path!" << endl;
            return 1;
        }

        ValidateAlgo(algo);

        if ((algo == "shake128" || algo == "shake256") && outLen <= 0)
            throw runtime_error("[ERROR] XOF mode requires --outlen!");

        cout << "[INFO] Algorithm  : " << algo << endl;
        cout << "[INFO] Input file : " << (isTemp ? "[Text input]" : inFile) << endl;
        cout << "[INFO] I/O mode   : " << (mode == "mmap" ? "Memory-mapped" : "Streamed") << endl;
        
        if (algo == "shake128" || algo == "shake256")
        {
            cout << "[INFO] Output len : " << outLen << " bytes" << endl;
        }

        vector<uint8_t> digest = HashDispatch(algo, mode, inFile, outLen);

        cout << "[INFO] Digest     : " << HexEncode(digest.data(), digest.size()) << endl;

        if (encode == "base64")
        {
            cout << "[INFO] Base64     : " << Base64Encode(digest.data(), digest.size()) << endl;
        }

        if (!outFile.empty())
        {
            ofstream out(outFile, ios::binary);
            if (!out)
                throw runtime_error("[ERROR] Invalid output path!");

            if (encode == "hex" || fmt == "hex")
            {
                string hexStr = HexEncode(digest.data(), digest.size());
                out.write(hexStr.data(), hexStr.size());
                cout << "[INFO] Hex digest saved to: " << outFile << endl;
            }
            else if (encode == "base64")
            {
                string b64Str = Base64Encode(digest.data(), digest.size());
                out.write(b64Str.data(), b64Str.size());
                cout << "[INFO] Base64 digest saved to: " << outFile << endl;
            }
            else
            {
                out.write(reinterpret_cast<const char*>(digest.data()), digest.size());
                cout << "[INFO] Binary digest saved to: " << outFile << endl;
            }
        }

        if (isTemp && fs::exists(temp))
        {
            fs::remove(temp);
        }
    }
    catch (const exception& e)
    {
        cerr << e.what() << endl;
        if (!outFile.empty() && fs::exists(outFile))
            fs::remove(outFile);
        if (fs::exists("temp"))
            fs::remove("temp");
        return 1;
    }

    return 0;
}
