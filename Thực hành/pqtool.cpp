#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <sstream>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <cstdint>

#ifdef _WIN32
    #include <windows.h>
#endif

#include <oqs/oqs.h>
#include "json.hpp"

using namespace std;
namespace fs = std::filesystem;
using json = nlohmann::json;

// Utilities

vector<uint8_t> ReadFile(const string& path)
{
    ifstream file(path, ios::binary | ios::ate);
    if (!file.is_open())
        throw runtime_error("[ERROR] Invalid input path!");

    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    vector<uint8_t> buffer(size);
    if (size > 0)
    {
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
            throw runtime_error("[ERROR] Invalid input path!");
    }
    return buffer;
}

void WriteFile(const string& path, const vector<uint8_t>& data)
{
    ofstream file(path, ios::binary);
    if (!file.is_open())
        throw runtime_error("[ERROR] Invalid output path!");

    if (!data.empty())
    {
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
}

static const string B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

string Base64Encode(const uint8_t* data, size_t len)
{
    string ret;
    int i = 0;
    uint8_t a3[3];
    uint8_t a4[4];

    while (len--)
    {
        a3[i++] = *(data++);
        if (i == 3)
        {
            a4[0] = (a3[0] & 0xfc) >> 2;
            a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
            a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
            a4[3] = a3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                ret += B64[a4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (int j = i; j < 3; j++)
            a3[j] = '\0';

        a4[0] = (a3[0] & 0xfc) >> 2;
        a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
        a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);

        for (int j = 0; j < i + 1; j++)
            ret += B64[a4[j]];

        while (i++ < 3)
            ret += '=';
    }
    return ret;
}

vector<uint8_t> Base64Decode(const string& str)
{
    size_t inLen = str.size();
    int i = 0;
    int in = 0;
    uint8_t a4[4];
    uint8_t a3[3];
    vector<uint8_t> ret;

    while (inLen-- && (str[in] != '=') && (isalnum(str[in]) || (str[in] == '+') || (str[in] == '/')))
    {
        a4[i++] = str[in++];
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
                a4[i] = static_cast<uint8_t>(B64.find(a4[i]));

            a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
            a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
            a3[2] = ((a4[2] & 0x3) << 6) + a4[3];

            for (i = 0; i < 3; i++)
                ret.push_back(a3[i]);
            i = 0;
        }
    }

    if (i)
    {
        for (int j = 0; j < i; j++)
            a4[j] = static_cast<uint8_t>(B64.find(a4[j]));

        a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
        a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);

        for (int j = 0; j < i - 1; j++)
            ret.push_back(a3[j]);
    }
    return ret;
}

// Validations

string ResolveOQSAlgo(const string& algo)
{
    if (algo == "mldsa-44")
        return OQS_SIG_alg_ml_dsa_44;
    else if (algo == "mldsa-65")
        return OQS_SIG_alg_ml_dsa_65;
    else if (algo == "mlkem-512")
        return OQS_KEM_alg_ml_kem_512;
    throw runtime_error("[ERROR] Invalid algorithm!");
}

bool IsSigAlgo(const string& algo)
{
    return (algo == "mldsa-44" || algo == "mldsa-65");
}

bool IsKemAlgo(const string& algo)
{
    return (algo == "mlkem-512");
}

// Operations

void GenerateKey(const string& algo, const string& pubPath, const string& privPath)
{
    string oqsAlg = ResolveOQSAlgo(algo);

    if (IsSigAlgo(algo))
    {
        OQS_SIG* sig = OQS_SIG_new(oqsAlg.c_str());
        if (!sig)
            throw runtime_error("[ERROR] Invalid algorithm!");

        vector<uint8_t> pub(sig->length_public_key);
        vector<uint8_t> priv(sig->length_secret_key);

        OQS_STATUS status = OQS_SIG_keypair(sig, pub.data(), priv.data());
        OQS_SIG_free(sig);

        if (status != OQS_SUCCESS)
            throw runtime_error("[ERROR] Key generation failed!");

        WriteFile(pubPath, pub);
        WriteFile(privPath, priv);
        cout << "[INFO] Key pair generated: " << algo << endl;
    }
    else if (IsKemAlgo(algo))
    {
        OQS_KEM* kem = OQS_KEM_new(oqsAlg.c_str());
        if (!kem)
            throw runtime_error("[ERROR] Invalid algorithm!");

        vector<uint8_t> pub(kem->length_public_key);
        vector<uint8_t> priv(kem->length_secret_key);

        OQS_STATUS status = OQS_KEM_keypair(kem, pub.data(), priv.data());
        OQS_KEM_free(kem);

        if (status != OQS_SUCCESS)
            throw runtime_error("[ERROR] Key generation failed!");

        WriteFile(pubPath, pub);
        WriteFile(privPath, priv);
        cout << "[INFO] Key pair generated: " << algo << endl;
    }
    else
    {
        throw runtime_error("[ERROR] Invalid algorithm!");
    }
}

void SignData(const string& algo, const string& inPath, const string& outPath, const string& privPath)
{
    if (!IsSigAlgo(algo))
        throw runtime_error("[ERROR] Invalid algorithm!");

    string oqsAlg = ResolveOQSAlgo(algo);
    OQS_SIG* sig = OQS_SIG_new(oqsAlg.c_str());
    if (!sig)
        throw runtime_error("[ERROR] Invalid algorithm!");

    vector<uint8_t> msg = ReadFile(inPath);
    vector<uint8_t> priv = ReadFile(privPath);

    vector<uint8_t> signature(sig->length_signature);
    size_t sigLen = 0;

    OQS_STATUS status = OQS_SIG_sign(sig, signature.data(), &sigLen, msg.data(), msg.size(), priv.data());
    OQS_SIG_free(sig);

    if (status != OQS_SUCCESS)
        throw runtime_error("[ERROR] Signing failed!");

    signature.resize(sigLen);
    WriteFile(outPath, signature);
    cout << "[INFO] Signed successfully: " << outPath << " (" << sigLen << " bytes)" << endl;
}

void VerifyData(const string& algo, const string& inPath, const string& sigPath, const string& pubPath)
{
    if (!IsSigAlgo(algo))
        throw runtime_error("[ERROR] Invalid algorithm!");

    string oqsAlg = ResolveOQSAlgo(algo);
    OQS_SIG* sig = OQS_SIG_new(oqsAlg.c_str());
    if (!sig)
        throw runtime_error("[ERROR] Invalid algorithm!");

    vector<uint8_t> msg = ReadFile(inPath);
    vector<uint8_t> signature = ReadFile(sigPath);
    vector<uint8_t> pub = ReadFile(pubPath);

    OQS_STATUS status = OQS_SIG_verify(sig, msg.data(), msg.size(), signature.data(), signature.size(), pub.data());
    OQS_SIG_free(sig);

    if (status == OQS_SUCCESS)
    {
        cout << "[INFO] Verification successful!" << endl;
    }
    else
    {
        throw runtime_error("[ERROR] Verification failed!");
    }
}

void EncapsulateKey(const string& algo, const string& pubPath, const string& ctPath, const string& ssPath)
{
    if (!IsKemAlgo(algo))
        throw runtime_error("[ERROR] Invalid algorithm!");

    string oqsAlg = ResolveOQSAlgo(algo);
    OQS_KEM* kem = OQS_KEM_new(oqsAlg.c_str());
    if (!kem)
        throw runtime_error("[ERROR] Invalid algorithm!");

    vector<uint8_t> pub = ReadFile(pubPath);
    vector<uint8_t> ct(kem->length_ciphertext);
    vector<uint8_t> ss(kem->length_shared_secret);

    OQS_STATUS status = OQS_KEM_encaps(kem, ct.data(), ss.data(), pub.data());
    OQS_KEM_free(kem);

    if (status != OQS_SUCCESS)
        throw runtime_error("[ERROR] Encapsulation failed!");

    WriteFile(ctPath, ct);
    WriteFile(ssPath, ss);
    cout << "[INFO] Encapsulation successful: " << ctPath << " & " << ssPath << endl;
}

void DecapsulateKey(const string& algo, const string& privPath, const string& ctPath, const string& ssPath)
{
    if (!IsKemAlgo(algo))
        throw runtime_error("[ERROR] Invalid algorithm!");

    string oqsAlg = ResolveOQSAlgo(algo);
    OQS_KEM* kem = OQS_KEM_new(oqsAlg.c_str());
    if (!kem)
        throw runtime_error("[ERROR] Invalid algorithm!");

    vector<uint8_t> priv = ReadFile(privPath);
    vector<uint8_t> ct = ReadFile(ctPath);
    vector<uint8_t> ss(kem->length_shared_secret);

    OQS_STATUS status = OQS_KEM_decaps(kem, ss.data(), ct.data(), priv.data());
    OQS_KEM_free(kem);

    if (status == OQS_SUCCESS)
    {
        WriteFile(ssPath, ss);
        cout << "[INFO] Decapsulation successful: " << ssPath << endl;
    }
    else
    {
        throw runtime_error("[ERROR] Decapsulation failed!");
    }
}

void IssueCertificate(const string& subject, const string& pubPath, const string& caPrivPath, const string& outJson, const string& algo)
{
    string oqsAlg = (algo == "mldsa-65") ? OQS_SIG_alg_ml_dsa_65 : OQS_SIG_alg_ml_dsa_44;
    OQS_SIG* sig = OQS_SIG_new(oqsAlg.c_str());
    if (!sig)
        throw runtime_error("[ERROR] Invalid algorithm!");

    vector<uint8_t> caPriv = ReadFile(caPrivPath);
    vector<uint8_t> userPub = ReadFile(pubPath);

    string pubB64 = Base64Encode(userPub.data(), userPub.size());
    string issuer = "PQ-CA";
    string dataToSign = subject + pubB64 + issuer;

    vector<uint8_t> signature(sig->length_signature);
    size_t sigLen = 0;

    OQS_STATUS status = OQS_SIG_sign(sig, signature.data(), &sigLen, reinterpret_cast<const uint8_t*>(dataToSign.c_str()), dataToSign.size(), caPriv.data());
    OQS_SIG_free(sig);

    if (status != OQS_SUCCESS)
        throw runtime_error("[ERROR] Signing failed!");

    json cert;
    cert["subject"] = subject;
    cert["public_key"] = pubB64;
    cert["issuer"] = issuer;
    cert["algo"] = (algo == "mldsa-65") ? "mldsa-65" : "mldsa-44";
    cert["signature"] = Base64Encode(signature.data(), sigLen);

    ofstream outFile(outJson);
    if (!outFile.is_open())
        throw runtime_error("[ERROR] Invalid output path!");

    outFile << cert.dump(4) << endl;
    cout << "[INFO] Certificate issued successfully: " << outJson << endl;
}

void VerifyCertificate(const string& inJson, const string& caPubPath)
{
    ifstream inFile(inJson);
    if (!inFile.is_open())
        throw runtime_error("[ERROR] Invalid input path!");

    json cert;
    try
    {
        inFile >> cert;
    }
    catch (...)
    {
        throw runtime_error("[ERROR] Invalid certificate format!");
    }

    string certAlgo = OQS_SIG_alg_ml_dsa_44;
    if (cert.contains("algo"))
    {
        string a = cert["algo"].get<string>();
        if (a == "mldsa-65" || a == OQS_SIG_alg_ml_dsa_65)
            certAlgo = OQS_SIG_alg_ml_dsa_65;
    }

    OQS_SIG* sig = OQS_SIG_new(certAlgo.c_str());
    if (!sig)
        throw runtime_error("[ERROR] Invalid algorithm!");

    vector<uint8_t> caPub = ReadFile(caPubPath);

    if (!cert.contains("subject") || !cert.contains("public_key") || !cert.contains("issuer") || !cert.contains("signature"))
    {
        OQS_SIG_free(sig);
        throw runtime_error("[ERROR] Invalid certificate format!");
    }

    string dataToSign = cert["subject"].get<string>() + cert["public_key"].get<string>() + cert["issuer"].get<string>();
    vector<uint8_t> signature = Base64Decode(cert["signature"].get<string>());

    OQS_STATUS status = OQS_SIG_verify(sig, reinterpret_cast<const uint8_t*>(dataToSign.c_str()), dataToSign.size(), signature.data(), signature.size(), caPub.data());
    OQS_SIG_free(sig);

    if (status == OQS_SUCCESS)
    {
        cout << "[INFO] Certificate verification successful!" << endl;
    }
    else
    {
        throw runtime_error("[ERROR] Verification failed!");
    }
}

void BatchVerify(const string& algo, const string& listPath)
{
    ifstream lf(listPath);
    if (!lf.is_open())
        throw runtime_error("[ERROR] Invalid input path!");

    if (algo.find("mldsa") != string::npos)
    {
        string oqsAlg = (algo == "mldsa-65") ? OQS_SIG_alg_ml_dsa_65 : OQS_SIG_alg_ml_dsa_44;
        OQS_SIG* sig = OQS_SIG_new(oqsAlg.c_str());
        if (!sig)
            throw runtime_error("[ERROR] Invalid algorithm!");

        string msgP, sigP, pubP;
        int passed = 0;
        int total = 0;

        while (lf >> msgP >> sigP >> pubP)
        {
            if (fs::exists(msgP) && fs::exists(sigP) && fs::exists(pubP))
            {
                vector<uint8_t> m = ReadFile(msgP);
                vector<uint8_t> s = ReadFile(sigP);
                vector<uint8_t> p = ReadFile(pubP);

                if (OQS_SIG_verify(sig, m.data(), m.size(), s.data(), s.size(), p.data()) == OQS_SUCCESS)
                {
                    passed++;
                }
                total++;
            }
        }
        OQS_SIG_free(sig);
        cout << "[INFO] Batch verification (" << algo << "): " << passed << "/" << total << " PASSED" << endl;
    }
    else if (algo == "mlkem-512")
    {
        OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
        if (!kem)
            throw runtime_error("[ERROR] Invalid algorithm!");

        string ctP, privP;
        int total = 0;
        int passed = 0;

        while (lf >> ctP >> privP)
        {
            if (fs::exists(ctP) && fs::exists(privP))
            {
                vector<uint8_t> ctData = ReadFile(ctP);
                vector<uint8_t> privData = ReadFile(privP);
                vector<uint8_t> ssRecovered(kem->length_shared_secret);

                if (OQS_KEM_decaps(kem, ssRecovered.data(), ctData.data(), privData.data()) == OQS_SUCCESS)
                {
                    passed++;
                }
                total++;
            }
        }
        OQS_KEM_free(kem);
        cout << "[INFO] Batch decapsulation (" << algo << "): " << passed << "/" << total << " PASSED" << endl;
    }
    else
    {
        throw runtime_error("[ERROR] Invalid algorithm!");
    }
}

// CLI

int main(int argc, char* argv[])
{
    OQS_init();

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    cout << "\n";
    cout << "  ██████╗  ██████╗ ███████╗████████╗\n";
    cout << "  ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝\n";
    cout << "  ██████╔╝██║   ██║███████╗   ██║   \n";
    cout << "  ██╔═══╝ ██║   ██║╚════██║   ██║   \n";
    cout << "  ██║     ╚██████╔╝███████║   ██║   \n";
    cout << "  ╚═╝      ╚═════╝ ╚══════╝   ╚═╝   \n";
    cout << "\n";
    cout << "   ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗████████╗██╗   ██╗███╗   ███╗\n";
    cout << "  ██╔═══██╗██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██║   ██║████╗ ████║\n";
    cout << "  ██║   ██║██║   ██║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║\n";
    cout << "  ██║▄▄ ██║██║   ██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║\n";
    cout << "  ╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║\n";
    cout << "   ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝\n";
    cout << endl;

    if (argc < 2)
    {
        cout
            << "Usage:\n"
            << "  ./pqtool keygen [options]\n"
            << "  ./pqtool sign [options]\n"
            << "  ./pqtool verify [options]\n"
            << "  ./pqtool encaps [options]\n"
            << "  ./pqtool decaps [options]\n"
            << "  ./pqtool cert-gen [options]\n"
            << "  ./pqtool cert-verify [options]\n"
            << "  ./pqtool verify-n [options]\n"
            << "\n"

            << "Required:\n"
            << "  keygen      : --algo --pub --priv\n"
            << "  sign        : --algo --in --out --priv\n"
            << "  verify      : --algo --in --sig --pub\n"
            << "  encaps      : --algo --pub --ct --ss\n"
            << "  decaps      : --algo --priv --ct --ss\n"
            << "  cert-gen    : --pub --priv --out\n"
            << "  cert-verify : --in --pub\n"
            << "  verify-n    : --algo --list\n"
            << "\n"

            << "Options:\n"
            << "  --algo <mldsa-44|mldsa-65|mlkem-512>\n"
            << "  --pub <public.key>\n"
            << "  --priv <private.key>\n"
            << "  --in <file>\n"
            << "  --out <file>\n"
            << "  --sig <signature>\n"
            << "  --ct <ciphertext>\n"
            << "  --ss <shared_secret>\n"
            << "  --list <batch_list.txt>\n"
            << "  --subject <name>\n"
            << "  --cert-algo <mldsa-44|mldsa-65>\n"
            << "\n"

            << "Algorithms:\n"
            << "  ML-DSA : mldsa-44 mldsa-65\n"
            << "  ML-KEM : mlkem-512\n"
            << endl;
        OQS_destroy();
        return 1;
    }

    string cmd      = argv[1];
    string algo     = "";
    string pubPath  = "";
    string privPath = "";
    string inPath   = "";
    string outPath  = "";
    string sigPath  = "";
    string ctPath   = "";
    string ssPath   = "";
    string listPath = "";
    string subject  = "PQ Subject";
    string certAlgo = "mldsa-44";

    for (int i = 2; i < argc; ++i)
    {
        string arg = argv[i];
        if (arg == "--algo" && i + 1 < argc)
            algo = argv[++i];
        else if (arg == "--pub" && i + 1 < argc)
            pubPath = argv[++i];
        else if (arg == "--priv" && i + 1 < argc)
            privPath = argv[++i];
        else if (arg == "--in" && i + 1 < argc)
            inPath = argv[++i];
        else if (arg == "--out" && i + 1 < argc)
            outPath = argv[++i];
        else if (arg == "--sig" && i + 1 < argc)
            sigPath = argv[++i];
        else if (arg == "--ct" && i + 1 < argc)
            ctPath = argv[++i];
        else if (arg == "--ss" && i + 1 < argc)
            ssPath = argv[++i];
        else if (arg == "--list" && i + 1 < argc)
            listPath = argv[++i];
        else if (arg == "--subject" && i + 1 < argc)
            subject = argv[++i];
        else if (arg == "--cert-algo" && i + 1 < argc)
            certAlgo = argv[++i];
        else
        {
            cerr << "[ERROR] Invalid command!" << endl;
            OQS_destroy();
            return 1;
        }
    }

    try
    {
        if (cmd == "keygen")
        {
            if (algo.empty() || pubPath.empty() || privPath.empty())
            {
                cerr << "[ERROR] Invalid arguments!" << endl;
                OQS_destroy();
                return 1;
            }
            GenerateKey(algo, pubPath, privPath);
        }
        else if (cmd == "sign")
        {
            if (algo.empty() || inPath.empty() || outPath.empty() || privPath.empty())
            {
                cerr << "[ERROR] Invalid arguments!" << endl;
                OQS_destroy();
                return 1;
            }
            SignData(algo, inPath, outPath, privPath);
        }
        else if (cmd == "verify")
        {
            if (algo.empty() || inPath.empty() || sigPath.empty() || pubPath.empty())
            {
                cerr << "[ERROR] Invalid arguments!" << endl;
                OQS_destroy();
                return 1;
            }
            VerifyData(algo, inPath, sigPath, pubPath);
        }
        else if (cmd == "encaps")
        {
            if (algo.empty() || pubPath.empty() || ctPath.empty() || ssPath.empty())
            {
                cerr << "[ERROR] Invalid arguments!" << endl;
                OQS_destroy();
                return 1;
            }
            EncapsulateKey(algo, pubPath, ctPath, ssPath);
        }
        else if (cmd == "decaps")
        {
            if (algo.empty() || privPath.empty() || ctPath.empty() || ssPath.empty())
            {
                cerr << "[ERROR] Invalid arguments!" << endl;
                OQS_destroy();
                return 1;
            }
            DecapsulateKey(algo, privPath, ctPath, ssPath);
        }
        else if (cmd == "cert-gen")
        {
            if (pubPath.empty() || privPath.empty() || outPath.empty())
            {
                cerr << "[ERROR] Invalid arguments!" << endl;
                OQS_destroy();
                return 1;
            }
            IssueCertificate(subject, pubPath, privPath, outPath, certAlgo);
        }
        else if (cmd == "cert-verify")
        {
            if (inPath.empty() || pubPath.empty())
            {
                cerr << "[ERROR] Invalid arguments!" << endl;
                OQS_destroy();
                return 1;
            }
            VerifyCertificate(inPath, pubPath);
        }
        else if (cmd == "verify-n")
        {
            if (algo.empty() || listPath.empty())
            {
                cerr << "[ERROR] Invalid arguments!" << endl;
                OQS_destroy();
                return 1;
            }
            BatchVerify(algo, listPath);
        }
        else
        {
            cerr << "[ERROR] Invalid command!" << endl;
            OQS_destroy();
            return 1;
        }
    }
    catch (const exception& e)
    {
        cerr << e.what() << endl;
        if (!outPath.empty() && fs::exists(outPath))
            fs::remove(outPath);
        if (!ctPath.empty() && fs::exists(ctPath))
            fs::remove(ctPath);
        if (!ssPath.empty() && fs::exists(ssPath))
            fs::remove(ssPath);
        OQS_destroy();
        return 1;
    }

    OQS_destroy();
    return 0;
}
