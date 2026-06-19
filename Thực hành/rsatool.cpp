#include <rsa.h>
#include <osrng.h>
#include <queue.h>
#include <files.h>
#include <base64.h>
#include <filters.h>
#include <oaep.h>
#include <sha.h>
#include <aes.h>
#include <gcm.h>
#include <hex.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
    #include <windows.h>
#endif

using namespace CryptoPP;

namespace {

    enum class InputMode {
        TEXT,
        FILE
    };

    enum class OutputFormat {
        BINARY,
        TEXT
    };

    enum class KeyFormat { 
        PEM, 
        DER, 
        BOTH 
    };

    enum class KeyMaterialType {
        UNKNOWN,
        PUBLIC_KEY,
        PRIVATE_KEY
    };

    //////////////////////////////////////////////////////////////
    // Utilities
    //////////////////////////////////////////////////////////////

    void WriteError(char* buffer, uint32_t bufferSize, const std::string& msg) {
        if (!buffer || bufferSize == 0) {
            return;
        }
        const size_t maxCopy = static_cast<size_t>(bufferSize - 1);
        const size_t copyLen = (msg.size() < maxCopy) ? msg.size() : maxCopy;
        std::memcpy(buffer, msg.data(), copyLen);
        buffer[copyLen] = '\0';
    }

    std::string ToLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return s;
    }

    std::string StripExt(const std::string& path) {
        size_t pos = path.find_last_of(".");
        if (pos == std::string::npos) {
            return path;
        }
        return path.substr(0, pos);
    }

    bool ParseOutputFormat(const std::string& s, OutputFormat& fmt) {
        const std::string v = ToLower(s);
        if (v == "binary" || v == "bin" || v == "raw") {
            fmt = OutputFormat::BINARY;
            return true;
        }
        if (v == "text" || v == "base64" || v == "b64") {
            fmt = OutputFormat::TEXT;
            return true;
        }
        return false;
    }

    std::string ExtractJSONValue(const std::string& json, const std::string& key) {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) {
            return "";
        }
        
        pos = json.find(":", pos + key.size() + 2);
        if (pos == std::string::npos) {
            return "";
        }
        
        size_t start = json.find("\"", pos);
        if (start == std::string::npos) {
            size_t numStart = json.find_first_of("0123456789", pos);
            size_t numEnd = json.find_first_not_of("0123456789", numStart);
            return json.substr(numStart, numEnd - numStart);
        }
        
        size_t end = json.find("\"", start + 1);
        if (end == std::string::npos) {
            return "";
        }
        
        return json.substr(start + 1, end - start - 1);
    }

    std::string ReadFileBinary(const std::string& filename) {
        std::ifstream in(filename, std::ios::binary);
        if (!in) {
            throw std::runtime_error("[ERROR] Failed to open file for reading: " + filename);
        }
        return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }

    void WriteFileBinary(const std::string& filename, const std::string& content) {
        std::ofstream out(filename, std::ios::binary);
        if (!out) {
            throw std::runtime_error("[ERROR] Failed to open file for writing: " + filename);
        }
        
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        
        if (!out) {
            throw std::runtime_error("[ERROR] Failed to write file: " + filename);
        }
    }

    std::string Base64Encode(const std::string& binary) {
        std::string encoded;
        StringSource ss(reinterpret_cast<const byte*>(binary.data()), binary.size(), true, new Base64Encoder(new StringSink(encoded), false));
        return encoded;
    }

    std::string Base64Decode(const std::string& text) {
        std::string decoded;
        StringSource ss(text, true, new Base64Decoder(new StringSink(decoded)));
        return decoded;
    }

    bool ContainsPEMMarker(const std::string& content) {
        return content.find("-----BEGIN ") != std::string::npos;
    }

    struct PEMBlock {
        std::string der;
        KeyMaterialType type = KeyMaterialType::UNKNOWN;
    };

    PEMBlock DecodePEM(const std::string& pemContent) {
        PEMBlock out;
        const size_t beginPos = pemContent.find("-----BEGIN ");
        
        if (beginPos == std::string::npos) {
            throw std::runtime_error("[ERROR] PEM begin marker not found");
        }
        
        const size_t beginEnd = pemContent.find("-----", beginPos + 11);
        
        if (beginEnd == std::string::npos) {
            throw std::runtime_error("[ERROR] Malformed PEM header");
        }

        const std::string headerType = pemContent.substr(beginPos + 11, beginEnd - (beginPos + 11));
        const std::string endMarker = "-----END " + headerType + "-----";
        const size_t endPos = pemContent.find(endMarker, beginEnd + 5);
        
        if (endPos == std::string::npos) {
            throw std::runtime_error("[ERROR] Matching PEM end marker not found");
        }

        std::string base64;
        for (size_t i = beginEnd + 5; i < endPos; ++i) {
            const unsigned char ch = static_cast<unsigned char>(pemContent[i]);
            if (!std::isspace(ch)) {
                base64.push_back(static_cast<char>(ch));
            }
        }

        if (base64.empty()) {
            throw std::runtime_error("[ERROR] PEM payload is empty");
        }

        const std::string typeLower = ToLower(headerType);
        if (typeLower == "public key" || typeLower == "rsa public key") {
            out.type = KeyMaterialType::PUBLIC_KEY;
        } else if (typeLower == "private key" || typeLower == "rsa private key") {
            out.type = KeyMaterialType::PRIVATE_KEY;
        } else if (typeLower == "encrypted private key") {
            throw std::runtime_error("[ERROR] Encrypted private key PEM is not supported");
        } else {
            out.type = KeyMaterialType::UNKNOWN;
        }

        out.der = Base64Decode(base64);
        return out;
    }

    void FillQueue(const std::string& bytes, ByteQueue& q) {
        q.Put(reinterpret_cast<const byte*>(bytes.data()), bytes.size());
        q.MessageEnd();
    }

    bool TryLoadPublicKeyDER(const std::string& derBytes, RSA::PublicKey& publicKey) {
        try { 
            ByteQueue q; 
            FillQueue(derBytes, q); 
            publicKey.BERDecode(q); 
            return true; 
        } catch (...) {
        }
        
        try { 
            ByteQueue q; 
            FillQueue(derBytes, q); 
            publicKey.BERDecodePublicKey(q, false, static_cast<CryptoPP::word32>(q.MaxRetrievable())); 
            return true; 
        } catch (...) {
        }
        
        try { 
            ByteQueue q; 
            FillQueue(derBytes, q); 
            publicKey.Load(q); 
            return true; 
        } catch (...) {
        }
        
        return false;
    }

    bool TryLoadPrivateKeyDER(const std::string& derBytes, RSA::PrivateKey& privateKey) {
        try { 
            ByteQueue q; 
            FillQueue(derBytes, q); 
            privateKey.BERDecode(q); 
            return true; 
        } catch (...) {
        }
        
        try { 
            ByteQueue q; 
            FillQueue(derBytes, q); 
            privateKey.BERDecodePrivateKey(q, false, static_cast<CryptoPP::word32>(q.MaxRetrievable())); 
            return true; 
        } catch (...) {
        }
        
        try { 
            ByteQueue q; 
            FillQueue(derBytes, q); 
            privateKey.Load(q); 
            return true; 
        } catch (...) {
        }
        
        return false;
    }

    RSA::PublicKey LoadEncryptionKeyFromFile(const std::string& keyPath) {
        const std::string fileBytes = ReadFileBinary(keyPath);
        std::string derBytes = fileBytes;
        KeyMaterialType hintedType = KeyMaterialType::UNKNOWN;

        if (ContainsPEMMarker(fileBytes)) {
            PEMBlock pem = DecodePEM(fileBytes);
            derBytes = pem.der;
            hintedType = pem.type;
        }

        AutoSeededRandomPool rng;
        if (hintedType == KeyMaterialType::PUBLIC_KEY || hintedType == KeyMaterialType::UNKNOWN) {
            RSA::PublicKey pub;
            if (TryLoadPublicKeyDER(derBytes, pub)) {
                if (pub.Validate(rng, 3)) {
                    return pub;
                }
            }
        }

        if (hintedType == KeyMaterialType::PRIVATE_KEY || hintedType == KeyMaterialType::UNKNOWN) {
            RSA::PrivateKey priv;
            if (TryLoadPrivateKeyDER(derBytes, priv)) {
                if (priv.Validate(rng, 3)) {
                    RSA::PublicKey pub;
                    pub.Initialize(priv.GetModulus(), priv.GetPublicExponent());
                    if (!pub.Validate(rng, 3)) {
                        throw std::runtime_error("[ERROR] Derived public key validation failed");
                    }
                    return pub;
                }
            }
        }
        
        throw std::runtime_error("[ERROR] Failed to load RSA key from file: " + keyPath);
    }

    RSA::PrivateKey LoadDecryptionKeyFromFile(const std::string& keyPath) {
        const std::string fileBytes = ReadFileBinary(keyPath);
        std::string derBytes = fileBytes;
        
        if (ContainsPEMMarker(fileBytes)) {
            PEMBlock pem = DecodePEM(fileBytes);
            derBytes = pem.der;
        }
        
        RSA::PrivateKey priv;
        if (TryLoadPrivateKeyDER(derBytes, priv)) {
            AutoSeededRandomPool rng;
            if (priv.Validate(rng, 3)) {
                return priv;
            }
        }
        
        throw std::runtime_error("[ERROR] Unable to read the Private Key from the file: " + keyPath);
    }

    //////////////////////////////////////////////////////////////
    // Manual OAEP Primitives
    //////////////////////////////////////////////////////////////
    
    void MGF1_SHA256(const byte* seed, size_t seedLen, byte* mask, size_t maskLen) {
        SHA256 sha;
        size_t counter = 0;
        size_t generated = 0;
        
        while (generated < maskLen) {
            byte c[4];
            c[0] = (byte)((counter >> 24) & 0xFF);
            c[1] = (byte)((counter >> 16) & 0xFF);
            c[2] = (byte)((counter >> 8) & 0xFF);
            c[3] = (byte)(counter & 0xFF);
            
            sha.Update(seed, seedLen);
            sha.Update(c, 4);
            byte digest[32];
            sha.Final(digest);
            
            size_t toCopy = std::min((size_t)32, maskLen - generated);
            std::memcpy(mask + generated, digest, toCopy);
            generated += toCopy;
            counter++;
        }
    }

    std::string Manual_OAEP_Encode(const std::string& M, size_t k, const std::string& label = "") {
        size_t hLen = 32; 
        
        if (M.size() > k - 2 * hLen - 2) {
            throw std::invalid_argument("[ERROR] Plaintext too large for RSA key size");
        }
        
        byte lHash[32];
        SHA256().CalculateDigest(lHash, (const byte*)label.data(), label.size());
        
        size_t dbLen = k - hLen - 1;
        std::vector<byte> DB(dbLen, 0);
        std::memcpy(DB.data(), lHash, hLen);
        DB[dbLen - M.size() - 1] = 0x01;
        std::memcpy(DB.data() + dbLen - M.size(), M.data(), M.size());
        
        AutoSeededRandomPool rng;
        byte seed[32];
        rng.GenerateBlock(seed, hLen);
        
        std::vector<byte> dbMask(dbLen);
        MGF1_SHA256(seed, hLen, dbMask.data(), dbLen);
        
        std::vector<byte> maskedDB(dbLen);
        for (size_t i = 0; i < dbLen; i++) {
            maskedDB[i] = DB[i] ^ dbMask[i];
        }
        
        byte seedMask[32];
        MGF1_SHA256(maskedDB.data(), dbLen, seedMask, hLen);
        
        byte maskedSeed[32];
        for (size_t i = 0; i < hLen; i++) {
            maskedSeed[i] = seed[i] ^ seedMask[i];
        }
        
        std::string EM;
        EM.push_back(0x00);
        EM.append((char*)maskedSeed, hLen);
        EM.append((char*)maskedDB.data(), dbLen);
        
        return EM;
    }

    std::string Manual_OAEP_Decode(const std::string& EM, size_t k, const std::string& label = "") {
        size_t hLen = 32;
        bool bad = false; 

        if (EM.size() != k || EM[0] != 0x00) {
            bad = true;
        }
        
        const byte* maskedSeed = (const byte*)EM.data() + 1;
        const byte* maskedDB = (const byte*)EM.data() + 1 + hLen;
        size_t dbLen = k - hLen - 1;
        
        byte seedMask[32];
        MGF1_SHA256(maskedDB, dbLen, seedMask, hLen);
        
        byte seed[32];
        for (size_t i = 0; i < hLen; i++) {
            seed[i] = maskedSeed[i] ^ seedMask[i];
        }
        
        std::vector<byte> dbMask(dbLen);
        MGF1_SHA256(seed, hLen, dbMask.data(), dbLen);
        
        std::vector<byte> DB(dbLen);
        for (size_t i = 0; i < dbLen; i++) {
            DB[i] = maskedDB[i] ^ dbMask[i];
        }
        
        byte lHash[32];
        SHA256().CalculateDigest(lHash, (const byte*)label.data(), label.size());
        
        if (!bad && std::memcmp(DB.data(), lHash, hLen) != 0) {
            bad = true;
        }
        
        size_t onePos = hLen;
        while (onePos < dbLen && DB[onePos] == 0x00) {
            onePos++;
        }
        
        if (onePos >= dbLen || DB[onePos] != 0x01) {
            bad = true;
        }
        
        if (bad) {
            throw std::runtime_error("[ERROR] Decryption failed: Ciphertext rejected.");
        }
        
        size_t mStart = onePos + 1;
        return std::string((char*)DB.data() + mStart, dbLen - mStart);
    }

    class RSAKeyGen {
    public:
        static std::string QueueToString(ByteQueue& queue) {
            std::string out; 
            out.resize(queue.CurrentSize());
            queue.Get(reinterpret_cast<byte*>(&out[0]), out.size()); 
            return out;
        }

        static std::string PrivateKeyToDER(const RSA::PrivateKey& key) { 
            ByteQueue q; 
            key.DEREncodePrivateKey(q); 
            return QueueToString(q); 
        }

        static std::string PublicKeyToDER(const RSA::PublicKey& key) { 
            ByteQueue q; 
            key.DEREncodePublicKey(q); 
            return QueueToString(q); 
        }

        static std::string DERToPEM(const std::string& derBytes, const std::string& header, const std::string& footer) {
            return header + "\n" + Base64Encode(derBytes) + "\n" + footer + "\n"; 
        }

        void Generate(uint32_t bits, const std::string& pubPath, const std::string& privPath) {
            if (bits < 2048) {
                throw std::invalid_argument("[ERROR] Key size must be at least 2048 bits. Lab 3 requires >= 3072.");
            }
            
            AutoSeededRandomPool rng;
            InvertibleRSAFunction params;
            params.Initialize(rng, bits, 65537);

            RSA::PrivateKey privateKey(params);
            RSA::PublicKey publicKey(params);

            std::string pubDer = PublicKeyToDER(publicKey);
            std::string privDer = PrivateKeyToDER(privateKey);
            std::string pubPem = DERToPEM(pubDer, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");
            std::string privPem = DERToPEM(privDer, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");

            WriteFileBinary(pubPath, pubPem);
            WriteFileBinary(privPath, privPem);

            std::string basePub = StripExt(pubPath);
            std::string basePriv = StripExt(privPath);
            WriteFileBinary(basePub + ".der", pubDer);
            WriteFileBinary(basePriv + ".der", privDer);

            std::string meta = "{\n  \"creation_time\": \"" + std::to_string(std::time(nullptr)) + "\",\n  \"modulus_bits\": " + std::to_string(bits) + ",\n  \"hash\": \"SHA-256\"\n}\n";
            WriteFileBinary("metadata.json", meta);
        }
    };

    class RSAEnc {
    public:
        static std::string EncryptBytes(const std::string& keyPath, const std::string& plaintext, OutputFormat outputFormat, const std::string& label = "") {
            if (keyPath.empty()) {
                throw std::invalid_argument("[ERROR] Key path cannot be empty");
            }

            RSA::PublicKey publicKey = LoadEncryptionKeyFromFile(keyPath);
            size_t k = publicKey.GetModulus().ByteCount();
            size_t hLen = 32;
            size_t maxPlaintext = k - 2 * hLen - 2;
            
            if (plaintext.size() > maxPlaintext) {
                AutoSeededRandomPool rng;
                SecByteBlock aesKey(32); 
                rng.GenerateBlock(aesKey, aesKey.size());
                
                SecByteBlock iv(12); 
                rng.GenerateBlock(iv, iv.size());

                std::string aesKeyStr((char*)aesKey.data(), aesKey.size());
                std::string em = Manual_OAEP_Encode(aesKeyStr, k, label);

                Integer m((const byte*)em.data(), em.size());
                Integer c = publicKey.ApplyFunction(m);
                std::string wrappedKey;
                wrappedKey.resize(k);
                c.Encode((byte*)&wrappedKey[0], wrappedKey.size());

                GCM<AES>::Encryption gcm;
                gcm.SetKeyWithIV(aesKey, aesKey.size(), iv, iv.size());

                std::string gcmCipher;
                StringSource(plaintext, true, new AuthenticatedEncryptionFilter(gcm, new StringSink(gcmCipher)));

                std::string ct = gcmCipher.substr(0, gcmCipher.size() - 16);
                std::string tag = gcmCipher.substr(gcmCipher.size() - 16);

                std::string out = "{\n";
                out += "  \"mode\": \"RSA-OAEP-AES-GCM\",\n";
                out += "  \"rsa_modulus\": " + std::to_string(publicKey.GetModulus().BitCount()) + ",\n";
                out += "  \"hash\": \"SHA-256\",\n";
                out += "  \"wrapped_key\": \"" + Base64Encode(wrappedKey) + "\",\n";
                out += "  \"iv\": \"" + Base64Encode(std::string((char*)iv.data(), iv.size())) + "\",\n";
                out += "  \"tag\": \"" + Base64Encode(tag) + "\",\n";
                out += "  \"ciphertext\": \"" + Base64Encode(ct) + "\"\n";
                out += "}";
                
                return out; 
            } else {
                std::string em = Manual_OAEP_Encode(plaintext, k, label);
                Integer m((const byte*)em.data(), em.size());
                Integer c = publicKey.ApplyFunction(m);
                std::string ciphertext;
                ciphertext.resize(k);
                c.Encode((byte*)&ciphertext[0], ciphertext.size());

                if (outputFormat == OutputFormat::TEXT) {
                    return Base64Encode(ciphertext);
                }
                return ciphertext;
            }
        }

        static std::string LoadInput(InputMode inputMode, const std::string& inputValue) {
            if (inputMode == InputMode::FILE) {
                return ReadFileBinary(inputValue);
            }
            return inputValue;
        }

        static void EncryptToFile(const std::string& keyPath, InputMode inputMode, const std::string& inputValue, const std::string& outputPath, OutputFormat outputFormat, const std::string& label = "") {
            if (outputPath.empty()) {
                throw std::invalid_argument("[ERROR] Output path cannot be empty");
            }
            const std::string plaintext = LoadInput(inputMode, inputValue);
            const std::string output = EncryptBytes(keyPath, plaintext, outputFormat, label);
            WriteFileBinary(outputPath, output);
        }
    };

    class RSADec {
    public:
        static std::string DecryptBytes(const std::string& keyPath, const std::string& ciphertext, OutputFormat inputFormat, const std::string& label = "") {
            if (keyPath.empty()) {
                throw std::invalid_argument("[ERROR] Key path cannot be empty");
            }

            std::string rawCipher;
            if (inputFormat == OutputFormat::TEXT) {
                rawCipher = Base64Decode(ciphertext);
            } else {
                rawCipher = ciphertext;
            }

            if (rawCipher.find("\"mode\": \"RSA-OAEP-AES-GCM\"") != std::string::npos || ciphertext.find("\"mode\": \"RSA-OAEP-AES-GCM\"") != std::string::npos) {
                std::string jsonStr;
                if (ciphertext.find("\"mode\"") != std::string::npos) {
                    jsonStr = ciphertext;
                } else {
                    jsonStr = rawCipher;
                }
                
                std::string wrappedKey64 = ExtractJSONValue(jsonStr, "wrapped_key");
                std::string iv64 = ExtractJSONValue(jsonStr, "iv");
                std::string tag64 = ExtractJSONValue(jsonStr, "tag");
                std::string ct64 = ExtractJSONValue(jsonStr, "ciphertext");

                std::string wrappedKey = Base64Decode(wrappedKey64);
                std::string iv = Base64Decode(iv64);
                std::string tag = Base64Decode(tag64);
                std::string ct = Base64Decode(ct64);

                RSA::PrivateKey privateKey = LoadDecryptionKeyFromFile(keyPath);
                size_t k = privateKey.GetModulus().ByteCount();
                AutoSeededRandomPool rng;

                Integer c((const byte*)wrappedKey.data(), wrappedKey.size());
                Integer m = privateKey.CalculateInverse(rng, c);
                std::string em;
                em.resize(k);
                m.Encode((byte*)&em[0], em.size());

                std::string aesKey = Manual_OAEP_Decode(em, k, label);

                GCM<AES>::Decryption gcm;
                gcm.SetKeyWithIV((const byte*)aesKey.data(), aesKey.size(), (const byte*)iv.data(), iv.size());

                std::string payload = ct + tag;
                std::string plaintext;
                AuthenticatedDecryptionFilter* df = new AuthenticatedDecryptionFilter(gcm, new StringSink(plaintext), AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END);
                StringSource(payload, true, df);

                return plaintext;
            } else {
                RSA::PrivateKey privateKey = LoadDecryptionKeyFromFile(keyPath);
                size_t k = privateKey.GetModulus().ByteCount();
                AutoSeededRandomPool rng;

                if (rawCipher.size() != k) {
                    throw std::invalid_argument("[ERROR] Ciphertext length is invalid for this RSA key.");
                }

                Integer c((const byte*)rawCipher.data(), rawCipher.size());
                Integer m = privateKey.CalculateInverse(rng, c);
                std::string em;
                em.resize(k);
                m.Encode((byte*)&em[0], em.size());

                return Manual_OAEP_Decode(em, k, label);
            }
        }

        static void DecryptToFile(const std::string& keyPath, InputMode inputMode, const std::string& inputValue, const std::string& outputPath, OutputFormat inputFormat, const std::string& label = "") {
            if (outputPath.empty()) {
                throw std::invalid_argument("[ERROR] Output path cannot be empty");
            }
            std::string ciphertext = RSAEnc::LoadInput(inputMode, inputValue);
            std::string plaintext = DecryptBytes(keyPath, ciphertext, inputFormat, label);
            WriteFileBinary(outputPath, plaintext);
        }
    };

    void PrintUsage()
    {
        std::cerr
            << "Usage:\n"
            << " ./rsatool keygen [options]\n"
            << " ./rsatool encrypt [options]\n"
            << " ./rsatool decrypt [options]\n"
            << "\n"

            << "Required:\n"
            << "  keygen  : --pub --priv\n"
            << "  encrypt : (--pub | --key) --out (--in | --text)\n"
            << "  decrypt : (--priv | --key) --out (--in | --text)\n"
            << "\n"

            << "Options:\n"
            << "  --bits <3072|4096>\n"
            << "  --pub <public.pem>\n"
            << "  --priv <private.pem>\n"
            << "  --key <key.pem>\n"
            << "  --in <file>\n"
            << "  --text <text>\n"
            << "  --out <file>\n"
            << "  --label <label>\n"
            << "  --encode <binary|text>\n"
            << "\n"
        << std::endl;
    }
} 

int main(int argc, char* argv[]) {

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    std::cout << "\n";
    std::cout << " ██████╗ ███████╗ █████╗ \n";
    std::cout << " ██╔══██╗██╔════╝██╔══██╗\n";
    std::cout << " ██████╔╝███████╗███████║\n";
    std::cout << " ██╔══██╗╚════██║██╔══██║\n";
    std::cout << " ██║  ██║███████║██║  ██║\n";
    std::cout << " ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n";
    std::cout << "\n";

    if (argc < 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
        PrintUsage(); 
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "keygen") {
        uint32_t bits = 3072;
        std::string pubPath, privPath;
        
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--bits" && i + 1 < argc) {
                bits = std::stoul(argv[++i]);
            } else if (arg == "--pub" && i + 1 < argc) {
                pubPath = argv[++i];
            } else if (arg == "--priv" && i + 1 < argc) {
                privPath = argv[++i];
            }
        }
        
        if (bits < 3072) {
            std::cerr << "[ERROR] Security policy violation! Minimum key size is 3072 bits." << std::endl;
            return 1;
        }

        if (pubPath.empty() || privPath.empty()) { 
            std::cerr << "[ERROR] --pub and --priv are required\n"; 
            return 1; 
        }
        
        try { 
            RSAKeyGen().Generate(bits, pubPath, privPath); 
            std::cout << "[INFO] Keygen successful.\n"; 
        } catch (const std::exception& e) { 
            std::cerr << "[ERROR] " << e.what() << "\n"; 
            return 1; 
        }
        return 0;
    }

    if (cmd == "encrypt" || cmd == "decrypt") {
        std::string keyPath, inFile, outFile, textIn, labelStr;
        std::string encodeOut = "binary";
        bool hasText = false, hasFile = false;

        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            
            if (arg == "--key" || arg == "--pub" || arg == "--priv") { 
                if (i + 1 < argc) {
                    keyPath = argv[++i]; 
                }
            } else if (arg == "--in" || arg == "--infile") { 
                if (i + 1 < argc) { 
                    inFile = argv[++i]; 
                    hasFile = true; 
                } 
            } else if (arg == "--text" && i + 1 < argc) { 
                textIn = argv[++i]; 
                hasText = true; 
            } else if (arg == "--out" || arg == "--outfile") { 
                if (i + 1 < argc) {
                    outFile = argv[++i]; 
                }
            } else if (arg == "--label" && i + 1 < argc) {
                labelStr = argv[++i];
            } else if (arg == "--encode" && i + 1 < argc) {
                encodeOut = argv[++i];
            }
        }

        if (keyPath.empty() || outFile.empty()) { 
            std::cerr << "[ERROR] Missing required arguments.\n"; 
            return 1; 
        }
        
        if (hasText == hasFile) { 
            std::cerr << "[ERROR] Specify exactly one of --in or --text.\n"; 
            return 1; 
        }

        try {
            OutputFormat fmt; 
            ParseOutputFormat(encodeOut, fmt);
            InputMode mode = hasText ? InputMode::TEXT : InputMode::FILE;
            std::string val = hasText ? textIn : inFile;

            if (cmd == "encrypt") {
                RSAEnc::EncryptToFile(keyPath, mode, val, outFile, fmt, labelStr);
                std::cout << "[INFO] Encryption successful. File saved: " << outFile << "\n";
            } else {
                RSADec::DecryptToFile(keyPath, mode, val, outFile, fmt, labelStr);
                std::cout << "[INFO] Decryption successful. File saved: " << outFile << "\n";
            }
        } catch (const std::exception& e) { 
            std::string msg = e.what();
            if (msg.find("[ERROR]") == std::string::npos) {
                std::cerr << "[ERROR] " << msg << "\n"; 
            } else {
                std::cerr << msg << "\n";
            }
            return 1; 
        }
        return 0;
    }

    std::cerr << "[ERROR] Invalid command.\n"; 
    PrintUsage(); 
    return 1;
}