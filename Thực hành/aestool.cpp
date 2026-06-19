#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <sstream> 

#ifdef _WIN32
    #include <windows.h>
#endif

#include <aes.h>
#include <osrng.h>
#include <secblock.h>
#include <hex.h>
#include <base64.h>
#include <files.h>
#include <filters.h>
#include <modes.h>
#include <gcm.h>
#include <ccm.h>
#include <xts.h>

using namespace std;
using namespace CryptoPP;
namespace fs = std::filesystem;

//////////////////////////////////////////////////////////////
// Utilities
//////////////////////////////////////////////////////////////

void PrintHex(const string& label, const CryptoPP::byte* data, size_t len)
{
    string enc;
    StringSource(data, len, true, new HexEncoder(new StringSink(enc), false));
    cout << label << ": " << enc << endl;
}

//////////////////////////////////////////////////////////////
// Security
//////////////////////////////////////////////////////////////

void ValidateIV(const string& mode, size_t len)
{
    if (mode == "cbc" || mode == "cfb" || mode == "ofb" || mode == "ctr" || mode == "xts")
    {
        if (len != 16)
            throw runtime_error("[ERROR] Invalid IV length. Expected 16 bytes.");
    }
    else if (mode == "gcm" || mode == "ccm")
    {
        if (len == 0)
            throw runtime_error("[ERROR] IV/Nonce cannot be empty.");
        if (len != 12)
            cout << "[WARNING] GCM/CCM works best with a 12-byte IV." << endl;
    }
}

void ValidateNonce(const string& mode, const SecByteBlock& key, const SecByteBlock& iv)
{
    if (mode != "ctr" && mode != "gcm" && mode != "ccm")
        return;

    string kHex, iHex;
    StringSource(key, key.size(), true, new HexEncoder(new StringSink(kHex), false));
    StringSource(iv, iv.size(), true, new HexEncoder(new StringSink(iHex), false));
    string rec = mode + ":" + kHex + ":" + iHex;

    ifstream in("history.dat");
    string line;
    if (in.is_open())
    {
        while (getline(in, line))
        {
            if (line == rec)
                throw runtime_error("[ERROR] Nonce reuse detected. Operation rejected.");
        }
        in.close();
    }

    ofstream out("history.dat", ios::app);
    if (out.is_open())
        out << rec << endl;
}

//////////////////////////////////////////////////////////////
// Key Management
//////////////////////////////////////////////////////////////

void GenerateAESKey(SecByteBlock& key, SecByteBlock& iv, size_t len)
{
    AutoSeededRandomPool rng;
    key.CleanNew(len);
    iv.CleanNew(AES::BLOCKSIZE);

    rng.GenerateBlock(key, key.size());
    rng.GenerateBlock(iv, iv.size());
}

void SaveHex(const string& file, const SecByteBlock& key, const SecByteBlock& iv)
{
    string kHex, iHex;
    StringSource(key, key.size(), true, new HexEncoder(new StringSink(kHex), false));
    StringSource(iv, iv.size(), true, new HexEncoder(new StringSink(iHex), false));
    ofstream out(file);
    out << "KEY=" << kHex << endl;
    out << "IV=" << iHex << endl;
}

void LoadHex(const string& file, SecByteBlock& key, SecByteBlock& iv)
{
    ifstream in(file);
    string kLine, iLine;
    getline(in, kLine);
    getline(in, iLine);

    string kHex = (kLine.length() > 4) ? kLine.substr(4) : "";
    string iHex = (iLine.length() > 3) ? iLine.substr(3) : "";

    string kBin, iBin;
    StringSource(kHex, true, new HexDecoder(new StringSink(kBin)));
    key.Assign((const CryptoPP::byte*)kBin.data(), kBin.size());

    if (!iHex.empty())
    {
        StringSource(iHex, true, new HexDecoder(new StringSink(iBin)));
        iv.Assign((const CryptoPP::byte*)iBin.data(), iBin.size());
    }
    else
    {
        iv.resize(0);
    }
}

void SaveBinary(const string& file, const SecByteBlock& key, const SecByteBlock& iv)
{
    FileSink out(file.c_str());
    out.Put(key, key.size());
    out.Put(iv, iv.size());
    out.MessageEnd();
}

void LoadBinary(const string& file, SecByteBlock& key, SecByteBlock& iv)
{
    string raw;
    FileSource src(file.c_str(), true, new StringSink(raw));

    if (raw.size() >= AES::DEFAULT_KEYLENGTH)
    {
        key.Assign((const CryptoPP::byte*)raw.data(), AES::DEFAULT_KEYLENGTH);
        if (raw.size() > AES::DEFAULT_KEYLENGTH)
        {
            iv.Assign((const CryptoPP::byte*)raw.data() + AES::DEFAULT_KEYLENGTH,
                      raw.size() - AES::DEFAULT_KEYLENGTH);
        }
        else
        {
            iv.resize(0);
        }
    }
}

void LoadKey(const string& fmt, const string& file, SecByteBlock& key, SecByteBlock& iv)
{
    if (fmt == "hex")
        LoadHex(file, key, iv);
    else if (fmt == "bin")
        LoadBinary(file, key, iv);
    else
        throw runtime_error("[ERROR] Unknown key format '" + fmt + "'. Use 'hex' or 'bin'.");
}

void SaveKey(const string& fmt, const string& file, const SecByteBlock& key, const SecByteBlock& iv)
{
    if (fmt == "hex")
        SaveHex(file, key, iv);
    else if (fmt == "bin")
        SaveBinary(file, key, iv);
    else
        throw runtime_error("[ERROR] Unknown key format '" + fmt + "'. Use 'hex' or 'bin'.");
}

//////////////////////////////////////////////////////////////
// Core Cryptography
//////////////////////////////////////////////////////////////

void EncryptECB(const string& in, const string& out, const SecByteBlock& key)
{
    ECB_Mode<AES>::Encryption enc;
    enc.SetKey(key, key.size());
    FileSource src(in.c_str(), true, new StreamTransformationFilter(enc, new FileSink(out.c_str())));
}

void DecryptECB(const string& in, const string& out, const SecByteBlock& key)
{
    ECB_Mode<AES>::Decryption dec;
    dec.SetKey(key, key.size());
    FileSource src(in.c_str(), true, new StreamTransformationFilter(dec, new FileSink(out.c_str())));
}

void EncryptCBC(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv)
{
    CBC_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    FileSource src(in.c_str(), true, new StreamTransformationFilter(enc, new FileSink(out.c_str())));
}

void DecryptCBC(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv)
{
    CBC_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    FileSource src(in.c_str(), true, new StreamTransformationFilter(dec, new FileSink(out.c_str())));
}

void EncryptCFB(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv)
{
    CFB_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    FileSource src(in.c_str(), true, new StreamTransformationFilter(enc, new FileSink(out.c_str())));
}

void DecryptCFB(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv)
{
    CFB_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    FileSource src(in.c_str(), true, new StreamTransformationFilter(dec, new FileSink(out.c_str())));
}

void EncryptOFB(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv)
{
    OFB_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    FileSource src(in.c_str(), true, new StreamTransformationFilter(enc, new FileSink(out.c_str())));
}

void DecryptOFB(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv)
{
    OFB_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    FileSource src(in.c_str(), true, new StreamTransformationFilter(dec, new FileSink(out.c_str())));
}

void EncryptCTR(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv)
{
    CTR_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    FileSource src(in.c_str(), true, new StreamTransformationFilter(enc, new FileSink(out.c_str())));
}

void DecryptCTR(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv)
{
    CTR_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    FileSource src(in.c_str(), true, new StreamTransformationFilter(dec, new FileSink(out.c_str())));
}

void EncryptXTS(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv)
{
    XTS_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    FileSource src(in.c_str(), true, new StreamTransformationFilter(enc, new FileSink(out.c_str()),
                  StreamTransformationFilter::NO_PADDING));
}

void DecryptXTS(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv)
{
    XTS_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    FileSource src(in.c_str(), true, new StreamTransformationFilter(dec, new FileSink(out.c_str()),
                  StreamTransformationFilter::NO_PADDING));
}

void EncryptCCM(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv, const string& aad)
{
    CCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());
    enc.SpecifyDataLengths(aad.size(), fs::file_size(in), 0);

    AuthenticatedEncryptionFilter* ef = new AuthenticatedEncryptionFilter(enc, new FileSink(out.c_str()));
    if (!aad.empty())
    {
        ef->ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
        ef->ChannelMessageEnd(AAD_CHANNEL);
    }
    FileSource src(in.c_str(), true, ef);
}

void DecryptCCM(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv, const string& aad)
{
    CCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    uintmax_t fSize = fs::file_size(in);
    uintmax_t mSize = fSize > dec.DigestSize() ? fSize - dec.DigestSize() : 0;
    dec.SpecifyDataLengths(aad.size(), mSize, 0);

    AuthenticatedDecryptionFilter* df = new AuthenticatedDecryptionFilter(dec, new FileSink(out.c_str()),
        AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END);
    if (!aad.empty())
    {
        df->ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
        df->ChannelMessageEnd(AAD_CHANNEL);
    }
    FileSource src(in.c_str(), true, df);
}

void EncryptGCM(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv, const string& aad)
{
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());

    AuthenticatedEncryptionFilter* ef = new AuthenticatedEncryptionFilter(enc, new FileSink(out.c_str()));
    if (!aad.empty())
    {
        ef->ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
        ef->ChannelMessageEnd(AAD_CHANNEL);
    }
    FileSource src(in.c_str(), true, ef);
}

void DecryptGCM(const string& in, const string& out, const SecByteBlock& key, const SecByteBlock& iv, const string& aad)
{
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    AuthenticatedDecryptionFilter* df = new AuthenticatedDecryptionFilter(dec, new FileSink(out.c_str()),
        AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END);
    if (!aad.empty())
    {
        df->ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
        df->ChannelMessageEnd(AAD_CHANNEL);
    }
    FileSource src(in.c_str(), true, df);
}

//////////////////////////////////////////////////////////////
// Dispatchers
//////////////////////////////////////////////////////////////

void EncryptDispatch(const string& mode, const string& in, const string& out,
                     const SecByteBlock& key, const SecByteBlock& iv, const string& aad)
{
    if (!aad.empty() && mode != "gcm" && mode != "ccm")
        throw runtime_error("[ERROR] AAD is only supported in AEAD modes (GCM, CCM).");

    if      (mode == "ecb") EncryptECB(in, out, key);
    else if (mode == "cbc") EncryptCBC(in, out, key, iv);
    else if (mode == "cfb") EncryptCFB(in, out, key, iv);
    else if (mode == "ofb") EncryptOFB(in, out, key, iv);
    else if (mode == "ctr") EncryptCTR(in, out, key, iv);
    else if (mode == "xts") EncryptXTS(in, out, key, iv);
    else if (mode == "ccm") EncryptCCM(in, out, key, iv, aad);
    else if (mode == "gcm") EncryptGCM(in, out, key, iv, aad);
    else throw runtime_error("[ERROR] Unsupported AES mode: " + mode);
}

void DecryptDispatch(const string& mode, const string& in, const string& out,
                     const SecByteBlock& key, const SecByteBlock& iv, const string& aad)
{
    if (!aad.empty() && mode != "gcm" && mode != "ccm")
        throw runtime_error("[ERROR] AAD is only supported in AEAD modes (GCM, CCM).");

    if      (mode == "ecb") DecryptECB(in, out, key);
    else if (mode == "cbc") DecryptCBC(in, out, key, iv);
    else if (mode == "cfb") DecryptCFB(in, out, key, iv);
    else if (mode == "ofb") DecryptOFB(in, out, key, iv);
    else if (mode == "ctr") DecryptCTR(in, out, key, iv);
    else if (mode == "xts") DecryptXTS(in, out, key, iv);
    else if (mode == "ccm") DecryptCCM(in, out, key, iv, aad);
    else if (mode == "gcm") DecryptGCM(in, out, key, iv, aad);
    else throw runtime_error("[ERROR] Unsupported AES mode: " + mode);
}

//////////////////////////////////////////////////////////////
// Main CLI
//////////////////////////////////////////////////////////////

int main(int argc, char* argv[]) {

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    cout << "\n";
    cout << "  █████╗ ███████╗███████╗\n";
    cout << " ██╔══██╗██╔════╝██╔════╝\n";
    cout << " ███████║█████╗  ███████╗\n";
    cout << " ██╔══██║██╔══╝  ╚════██║\n";
    cout << " ██║  ██║███████╗███████║\n";
    cout << " ╚═╝  ╚═╝╚══════╝╚══════╝\n";
    cout << "\n";

    if (argc < 2)
    {
        cout
            << "Usage:\n"
            << "  ./aestool encrypt [options]\n"
            << "  ./aestool decrypt [options]\n"
            << "  ./aestool generate [options]\n"
            << "  ./aestool show [options]\n"
            << "\n"

            << "Required:\n"
            << "  encrypt/decrypt : --mode --key --out\n"
            << "  generate        : --bits --key\n"
            << "  show            : --key\n"
            << "\n"

            << "Options:\n"
            << "  --mode <ecb|cbc|cfb|ofb|ctr|xts|ccm|gcm>\n"
            << "  --bits <128|192|256>\n"
            << "  --key <file>\n"
            << "  --key-hex <hex>\n"
            << "  --in <file>\n"
            << "  --text <text>\n"
            << "  --out <file>\n"
            << "  --iv <hex>\n"
            << "  --nonce <hex>\n"
            << "  --aad <file>\n"
            << "  --aad-text <text>\n"
            << "  --encode <hex|base64|raw>\n"
            << "  --format <hex|bin>\n"
            << "  --allow-ecb\n"
            << "\n";
        return 1;
    }

    string cmd     = argv[1];
    string mode    = "";
    string fmt     = "hex";
    string keyFile = "";
    string inFile  = "";
    string outFile = "";
    string aadText = "";
    string aadFile = "";
    string inText  = "";
    string keyHex  = "";
    string ivHex   = "";
    string encode  = "raw";
    bool   ecb     = false;
    bool   aead    = false;
    int    bits    = 128;

    for (int i = 1; i < argc; ++i)
    {
        string arg = argv[i];
        if (arg == "encrypt" || arg == "decrypt" || arg == "generate" || arg == "show")
            continue;

        if      (arg == "--mode"     && i + 1 < argc) mode    = argv[++i];
        else if (arg == "--key"      && i + 1 < argc) keyFile = argv[++i];
        else if (arg == "--key-hex"  && i + 1 < argc) keyHex  = argv[++i];
        else if (arg == "--in"       && i + 1 < argc) inFile  = argv[++i];
        else if (arg == "--text"     && i + 1 < argc) inText  = argv[++i];
        else if (arg == "--out"      && i + 1 < argc) outFile = argv[++i];
        else if (arg == "--iv"       && i + 1 < argc) ivHex   = argv[++i];
        else if (arg == "--nonce"    && i + 1 < argc) ivHex   = argv[++i];
        else if (arg == "--encode"   && i + 1 < argc) encode  = argv[++i];
        else if (arg == "--format"   && i + 1 < argc) fmt     = argv[++i];
        else if (arg == "--bits"     && i + 1 < argc) bits    = stoi(argv[++i]);
        else if (arg == "--aad"      && i + 1 < argc) aadFile = argv[++i];
        else if (arg == "--aad-text" && i + 1 < argc) aadText = argv[++i];
        else if (arg == "--allow-ecb") ecb = true;
        else if (arg == "--aead")      aead = true;
        else
        {
            cerr << "[ERROR] Unknown or malformed argument '" << arg << "'." << endl;
            return 1;
        }
    }

    try
    {
        string aad = aadText;
        if (!aadFile.empty())
        {
            if (fs::exists(aadFile)) { 
                ifstream f(aadFile); 
                stringstream b; 
                b << f.rdbuf(); 
                aad = b.str(); 
            }
            else 
                cerr << "[WARNING] AAD file not found." << endl;
        }

        if (cmd == "generate")
        {
            if (keyFile.empty())
            {
                cerr << "[ERROR] Missing keyfile path." << endl;
                return 1;
            }

            size_t len = bits / 8;
            if (len != 16 && len != 24 && len != 32)
            {
                cerr << "[ERROR] Invalid key size." << endl;
                return 1;
            }

            SecByteBlock key, iv;
            GenerateAESKey(key, iv, len);
            SaveKey(fmt, keyFile, key, iv);
            cout << "[INFO] Generated " << bits << "-bit key saved to '" << keyFile << "'." << endl;

            return 0;
        }
        else if (cmd == "show")
        {
            if (keyFile.empty() || !fs::exists(keyFile))
            {
                cerr << "[ERROR] Key file missing or does not exist." << endl;
                return 1;
            }
            SecByteBlock key, iv;
            LoadKey(fmt, keyFile, key, iv);
            PrintHex("Key", key, key.size());
            PrintHex("IV",  iv,  iv.size());

            return 0;
        }
        else if (cmd == "encrypt")
        {
            if (mode.empty() || outFile.empty())
            {
                cerr << "[ERROR] Missing arguments for encrypt." << endl;
                return 1;
            }
            if (keyFile.empty() && keyHex.empty())
            {
                cerr << "[ERROR] Missing key." << endl;
                return 1;
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
                cerr << "[ERROR] Input file does not exist." << endl;
                return 1;
            }

            SecByteBlock key, iv;
            if (!keyHex.empty())
            {
                string kBin;
                StringSource(keyHex, true, new HexDecoder(new StringSink(kBin)));
                key.Assign((const CryptoPP::byte*)kBin.data(), kBin.size());
            }
            else
            {
                LoadKey(fmt, keyFile, key, iv);
            }

            if (!ivHex.empty())
            {
                string iBin;
                StringSource(ivHex, true, new HexDecoder(new StringSink(iBin)));
                iv.Assign((const CryptoPP::byte*)iBin.data(), iBin.size());
            }

            // Security 

            if (mode == "ecb")
            {
                cout << "[WARNING] ECB mode is cryptographically insecure." << endl;
                if (fs::file_size(inFile) > 16384 && !ecb)
                {
                    if (isTemp) fs::remove(temp);
                    throw runtime_error("[ERROR] Limit exceeded for ECB. Use --allow-ecb.");
                }
            }

            if (mode != "ecb" && iv.size() == 0)
            {
                AutoSeededRandomPool rng;
                size_t expLen = (mode == "gcm" || mode == "ccm") ? 12 : 16;
                iv.CleanNew(expLen);
                rng.GenerateBlock(iv, iv.size());

                string genIvHex;
                StringSource(iv, iv.size(), true, new HexEncoder(new StringSink(genIvHex), false));
                cout << "[INFO] Auto-generated IV: " << genIvHex << endl;
            }

            if (mode != "ecb") {
                ValidateIV(mode, iv.size());
                ValidateNonce(mode, key, iv);
            }

            if ((mode == "gcm" || mode == "ccm") && !aead)
            {
                if (isTemp) fs::remove(temp);
                throw runtime_error("[ERROR] AEAD modes require --aead.");
            }

            EncryptDispatch(mode, inFile, outFile, key, iv, aad);

            string iOut, aOut, tOut;
            StringSource(iv, iv.size(), true, new HexEncoder(new StringSink(iOut), false));

            if (!aad.empty())
                StringSource((const CryptoPP::byte*)aad.data(), aad.size(), true, new HexEncoder(new StringSink(aOut), false));

            if (mode == "gcm" || mode == "ccm")
            {
                string raw;
                FileSource(outFile.c_str(), true, new StringSink(raw));
                size_t tLen = 16;
                if (raw.size() >= tLen)
                {
                    string tag = raw.substr(raw.size() - tLen);
                    StringSource(tag, true, new HexEncoder(new StringSink(tOut), false));
                }
            }

            // Encode

            bool doEncode = false;
            if (encode == "hex")
            {
                string raw;
                FileSource(outFile.c_str(), true, new StringSink(raw));
                StringSource(raw, true, new HexEncoder(new FileSink(outFile.c_str())));
                doEncode = true;
            }
            else if (encode == "base64")
            {
                string raw;
                FileSource(outFile.c_str(), true, new StringSink(raw));
                StringSource(raw, true, new Base64Encoder(new FileSink(outFile.c_str()), false));
                doEncode = true;
            }

            if (isTemp) fs::remove(temp);

            cout << "[INFO] Encryption complete: " << outFile << endl;

            string rOut;
            FileSource(outFile.c_str(), true, new StringSink(rOut));
            if (rOut.size() <= 2048)
            {
                string hex;
                if (doEncode && encode == "hex") hex = rOut;
                else if (doEncode && encode == "base64")
                {
                    string dec;
                    StringSource(rOut, true, new Base64Decoder(new StringSink(dec)));
                    StringSource(dec, true, new HexEncoder(new StringSink(hex)));
                }
                else StringSource(rOut, true, new HexEncoder(new StringSink(hex)));
                
                cout << "[INFO] Ciphertext (HEX): " << hex << endl;
            }
        }
        else if (cmd == "decrypt")
        {
            if (mode.empty() || outFile.empty())
            {
                cerr << "[ERROR] Missing arguments for decrypt." << endl;
                return 1;
            }
            if (keyFile.empty() && keyHex.empty())
            {
                cerr << "[ERROR] Missing key." << endl;
                return 1;
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
                cerr << "[ERROR] Input file does not exist." << endl;
                return 1;
            }

            SecByteBlock key, iv;
            if (!keyHex.empty())
            {
                string kBin;
                StringSource(keyHex, true, new HexDecoder(new StringSink(kBin)));
                key.Assign((const CryptoPP::byte*)kBin.data(), kBin.size());
            }
            else
            {
                LoadKey(fmt, keyFile, key, iv);
            }

            if (!ivHex.empty())
            {
                string iBin;
                StringSource(ivHex, true, new HexDecoder(new StringSink(iBin)));
                iv.Assign((const CryptoPP::byte*)iBin.data(), iBin.size());
            }

            // Security

            if (mode != "ecb") {
                ValidateIV(mode, iv.size());
            }

            if ((mode == "gcm" || mode == "ccm") && !aead)
            {
                if (isTemp) fs::remove(temp);
                throw runtime_error("[ERROR] AEAD modes require --aead.");
            }

            // Decode

            bool doDecode = false;
            if (encode == "hex")
            {
                string raw;
                FileSource(inFile.c_str(), true, new StringSink(raw));
                StringSource(raw, true, new HexDecoder(new FileSink(temp.c_str())));
                inFile = temp;
                isTemp = true;
                doDecode = true;
            }
            else if (encode == "base64")
            {
                string raw;
                FileSource(inFile.c_str(), true, new StringSink(raw));
                StringSource(raw, true, new Base64Decoder(new FileSink(temp.c_str())));
                inFile = temp;
                isTemp = true;
                doDecode = true;
            }

            DecryptDispatch(mode, inFile, outFile, key, iv, aad);

            if (isTemp) fs::remove(temp);

            cout << "[INFO] Decryption complete: " << outFile << endl;
        }
        else
        {
            cerr << "[ERROR] Unknown command '" << cmd << "'." << endl;
            return 1;
        }
    }
    catch (const Exception& e)
    {
        cerr << "[ERROR] Crypto++: " << e.what() << endl;
        if (!outFile.empty() && fs::exists(outFile))
            fs::remove(outFile);
        if (fs::exists("temp")) 
            fs::remove("temp");
        return 1;
    }
    catch (const exception& e)
    {
        cerr << e.what() << endl;
        return 1;
    }
    return 0;
}