#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <oqs/oqs.h>
#include "json.hpp" 

#ifdef _WIN32
    #include <windows.h>
#endif

using json = nlohmann::json;

//////////////////////////////////////////////////////////////
// HELPER FUNCTIONS
//////////////////////////////////////////////////////////////

void write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary); 
    if (!data.empty()) {
        f.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
}

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    
    if (!f.is_open()) {
        return {};
    }
    
    size_t size = f.tellg(); 
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(size); 
    f.read(reinterpret_cast<char*>(buf.data()), size);
    
    return buf;
}

std::string get_arg(int argc, char* argv[], const std::string& flag, const std::string& default_val = "") {
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string(argv[i]) == flag) {
            return argv[i + 1];
        }
    }
    return default_val;
}

static const std::string b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const uint8_t* bytes_to_encode, unsigned int in_len) {
    std::string ret; 
    int i = 0;
    int j = 0; 
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];
    
    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (i = 0; i < 4; i++) {
                ret += b64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        
        for (j = 0; j < i + 1; j++) {
            ret += b64_chars[char_array_4[j]];
        }
        
        while (i++ < 3) {
            ret += '=';
        }
    }
    return ret;
}

std::vector<uint8_t> base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size(); 
    int i = 0;
    int j = 0;
    int in_ = 0;
    uint8_t char_array_4[4];
    uint8_t char_array_3[3]; 
    std::vector<uint8_t> ret;
    
    while (in_len-- && (encoded_string[in_] != '=') && (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
        char_array_4[i++] = encoded_string[in_]; 
        in_++;
        
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                char_array_4[i] = b64_chars.find(char_array_4[i]);
            }
            
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            
            for (i = 0; i < 3; i++) {
                ret.push_back(char_array_3[i]);
            }
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j < 4; j++) {
            char_array_4[j] = 0;
        }
        
        for (j = 0; j < 4; j++) {
            char_array_4[j] = b64_chars.find(char_array_4[j]);
        }
        
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        
        for (j = 0; j < i - 1; j++) {
            ret.push_back(char_array_3[j]);
        }
    }
    return ret;
}

//////////////////////////////////////////////////////////////
// CORE HANDLERS
//////////////////////////////////////////////////////////////

void handle_keygen(std::string algo, std::string pub_path, std::string priv_path) {
    if (algo == OQS_SIG_alg_ml_dsa_44 || algo == OQS_SIG_alg_ml_dsa_65) {
        OQS_SIG *sig = OQS_SIG_new(algo.c_str());
        if (!sig) { 
            std::cerr << "[ERROR] OQS_SIG_new failed for: " << algo << "\n"; 
            return; 
        }
        
        std::vector<uint8_t> pub(sig->length_public_key);
        std::vector<uint8_t> priv(sig->length_secret_key);
        
        OQS_SIG_keypair(sig, pub.data(), priv.data());
        write_file(pub_path, pub); 
        write_file(priv_path, priv);
        
        std::cout << "[INFO] Tao khoa thanh cong: " << algo << "\n";
        OQS_SIG_free(sig);
    } 
    else if (algo == OQS_KEM_alg_ml_kem_512) {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
        if (!kem) { 
            std::cerr << "[ERROR] OQS_KEM_new failed\n"; 
            return; 
        }
        
        std::vector<uint8_t> pub(kem->length_public_key);
        std::vector<uint8_t> priv(kem->length_secret_key);
        
        OQS_KEM_keypair(kem, pub.data(), priv.data());
        write_file(pub_path, pub); 
        write_file(priv_path, priv);
        
        std::cout << "[INFO] Tao khoa thanh cong: " << algo << "\n";
        OQS_KEM_free(kem);
    } 
    else {
        std::cerr << "[ERROR] Thuat toan khong hop le: " << algo << "\n";
    }
}

void handle_sign(std::string algo, std::string in, std::string out, std::string priv_path) {
    OQS_SIG *sig = OQS_SIG_new(algo.c_str()); 
    if (!sig) { 
        std::cerr << "[ERROR] OQS_SIG_new failed for: " << algo << "\n"; 
        return; 
    }
    
    auto msg = read_file(in);
    if (msg.empty()) { 
        std::cerr << "[ERROR] Khong doc duoc file input: " << in << "\n"; 
        OQS_SIG_free(sig); 
        return; 
    }
    
    auto priv = read_file(priv_path);
    if (priv.empty()) { 
        std::cerr << "[ERROR] Khong doc duoc private key: " << priv_path << "\n"; 
        OQS_SIG_free(sig); 
        return; 
    }
    
    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len;
    
    OQS_SIG_sign(sig, signature.data(), &sig_len, msg.data(), msg.size(), priv.data());
    signature.resize(sig_len);
    write_file(out, signature);
    
    std::cout << "[INFO] Da ky file. Dung luong chu ky: " << sig_len << " bytes\n";
    OQS_SIG_free(sig);
}

void handle_verify(std::string algo, std::string in, std::string sig_f, std::string pub_path) {
    OQS_SIG *sig = OQS_SIG_new(algo.c_str()); 
    if (!sig) { 
        std::cerr << "[ERROR] OQS_SIG_new failed for: " << algo << "\n"; 
        return; 
    }
    
    auto msg = read_file(in);
    auto signature = read_file(sig_f);
    auto pub = read_file(pub_path);
    
    if (msg.empty() || signature.empty() || pub.empty()) {
        std::cerr << "[ERROR] Khong doc duoc 1 trong cac file can thiet (msg/sig/pub).\n";
        OQS_SIG_free(sig); 
        return;
    }
    
    if (OQS_SIG_verify(sig, msg.data(), msg.size(), signature.data(), signature.size(), pub.data()) == OQS_SUCCESS) {
        std::cout << "[INFO] VERIFIED SUCCESS: Chu ky hop le!\n";
    } else {
        std::cerr << "[ERROR] VERIFIED FAILED: Chu ky bi sai hoac file bi sua!\n";
    }
    
    OQS_SIG_free(sig);
}

void handle_encaps(std::string algo, std::string pub_path, std::string ct_path, std::string ss_path) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    auto pub = read_file(pub_path);
    std::vector<uint8_t> ct(kem->length_ciphertext);
    std::vector<uint8_t> ss(kem->length_shared_secret);
    
    OQS_KEM_encaps(kem, ct.data(), ss.data(), pub.data());
    write_file(ct_path, ct); 
    write_file(ss_path, ss);
    
    std::cout << "[INFO] Encapsulate thanh cong! Sinh ra Shared Secret.\n";
    OQS_KEM_free(kem);
}

void handle_decaps(std::string algo, std::string priv_path, std::string ct_path, std::string ss_path) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    auto priv = read_file(priv_path); 
    auto ct = read_file(ct_path);
    std::vector<uint8_t> ss(kem->length_shared_secret);
    
    if (OQS_KEM_decaps(kem, ss.data(), ct.data(), priv.data()) == OQS_SUCCESS) {
        write_file(ss_path, ss);
        std::cout << "[INFO] Decapsulate thanh cong! Thu duoc Shared Secret.\n";
    } else {
        std::cerr << "[ERROR] Decapsulate FAILED: Ciphertext bi loi hoac sai khoa!\n";
    }
    
    OQS_KEM_free(kem);
}

void handle_cert_issue(std::string sub, std::string pub_path, std::string ca_priv_path, std::string out_json, std::string algo = "mldsa-44") {
    const char* alg;
    if (algo == "mldsa-65") {
        alg = OQS_SIG_alg_ml_dsa_65;
    } else {
        alg = OQS_SIG_alg_ml_dsa_44;
    }
    
    OQS_SIG *sig = OQS_SIG_new(alg);
    auto ca_priv = read_file(ca_priv_path); 
    auto user_pub = read_file(pub_path);
    
    std::string pub_b64 = base64_encode(user_pub.data(), user_pub.size());
    std::string issuer = "PQ-CA";
    std::string data_to_sign = sub + pub_b64 + issuer;
    
    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len;
    
    OQS_SIG_sign(sig, signature.data(), &sig_len, (const uint8_t*)data_to_sign.c_str(), data_to_sign.size(), ca_priv.data());
    
    json cert; 
    cert["subject"] = sub; 
    cert["public_key"] = pub_b64; 
    cert["issuer"] = issuer;
    cert["algo"] = algo;
    cert["signature"] = base64_encode(signature.data(), sig_len);
    
    std::ofstream o(out_json); 
    o << cert.dump(4);
    
    std::cout << "[INFO] Tao chung chi JSON thanh cong: " << out_json << "\n";
    OQS_SIG_free(sig);
}

void handle_cert_verify(std::string in_json, std::string ca_pub_path) {
    std::ifstream i(in_json);
    if (!i.is_open()) { 
        std::cerr << "[ERROR] Khong mo duoc file cert: " << in_json << "\n"; 
        return; 
    }
    
    json cert; 
    i >> cert;
    
    std::string cert_algo = OQS_SIG_alg_ml_dsa_44;
    if (cert.contains("algo")) {
        std::string a = cert["algo"].get<std::string>();
        if (a == "mldsa-65" || a == OQS_SIG_alg_ml_dsa_65) {
            cert_algo = OQS_SIG_alg_ml_dsa_65;
        }
    }
    
    OQS_SIG *sig = OQS_SIG_new(cert_algo.c_str());
    if (!sig) { 
        std::cerr << "[ERROR] OQS_SIG_new failed\n"; 
        return; 
    }
    
    auto ca_pub = read_file(ca_pub_path);
    if (ca_pub.empty()) { 
        std::cerr << "[ERROR] Khong doc duoc CA public key: " << ca_pub_path << "\n"; 
        OQS_SIG_free(sig); 
        return; 
    }
    
    std::string data_to_sign = cert["subject"].get<std::string>() + cert["public_key"].get<std::string>() + cert["issuer"].get<std::string>();
    auto signature = base64_decode(cert["signature"].get<std::string>());
    
    if (OQS_SIG_verify(sig, (const uint8_t*)data_to_sign.c_str(), data_to_sign.size(), signature.data(), signature.size(), ca_pub.data()) == OQS_SUCCESS) {
        std::cout << "[INFO] Chung chi HOP LE (Valid & Untampered)!\n";
    } else {
        std::cerr << "[ERROR] Xac minh chung chi THAT BAI!\n";
    }
    
    OQS_SIG_free(sig);
}

//////////////////////////////////////////////////////////////
// MAIN CLI
//////////////////////////////////////////////////////////////

int main(int argc, char* argv[]) {
    OQS_init();

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    std::cout << "\n";
    std::cout << "  ██████╗  ██████╗ ███████╗████████╗\n";
    std::cout << "  ██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝\n";
    std::cout << "  ██████╔╝██║   ██║███████╗   ██║   \n";
    std::cout << "  ██╔═══╝ ██║   ██║╚════██║   ██║   \n";
    std::cout << "  ██║     ╚██████╔╝███████║   ██║   \n";
    std::cout << "  ╚═╝      ╚═════╝ ╚══════╝   ╚═╝   \n";
    std::cout << "\n";
    std::cout << "   ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗████████╗██╗   ██╗███╗   ███╗\n";
    std::cout << "  ██╔═══██╗██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██║   ██║████╗ ████║\n";
    std::cout << "  ██║   ██║██║   ██║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║\n";
    std::cout << "  ██║▄▄ ██║██║   ██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║\n";
    std::cout << "  ╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║\n";
    std::cout << "   ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝\n";
    std::cout << "\n";
    std::cout << "   ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗  ██████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗██╗   ██╗\n";
    std::cout << "  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║  ██║╚██╗ ██╔╝\n";
    std::cout << "  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██║  ███╗██████╔╝███████║██████╔╝███████║ ╚████╔╝ \n";
    std::cout << "  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██║   ██║██╔══██╗██╔══██║██╔═══╝ ██╔══██║  ╚██╔╝  \n";
    std::cout << "  ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██║     ██║  ██║   ██║   \n";
    std::cout << "   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝   \n";
    std::cout << "\n";

    if (argc < 2) {
        std::cout
            << "Usage:\n"
            << "  pqtool keygen [options]\n"
            << "  pqtool sign [options]\n"
            << "  pqtool verify [options]\n"
            << "  pqtool encaps [options]\n"
            << "  pqtool decaps [options]\n"
            << "  pqtool cert-gen [options]\n"
            << "  pqtool cert-verify [options]\n"
            << "  pqtool verify-n [options]\n"
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
        << std::endl;
        OQS_destroy(); 
        return 1;
    }

    std::string cmd = argv[1];
    std::string algo_input = get_arg(argc, argv, "--algo");
    std::string oqs_algo_str = "";
    
    if (algo_input == "mldsa-44") {
        oqs_algo_str = OQS_SIG_alg_ml_dsa_44;
    } else if (algo_input == "mldsa-65") {
        oqs_algo_str = OQS_SIG_alg_ml_dsa_65;
    } else if (algo_input == "mlkem-512") {
        oqs_algo_str = OQS_KEM_alg_ml_kem_512;
    }

    if (cmd == "keygen") {
        handle_keygen(oqs_algo_str, get_arg(argc, argv, "--pub"), get_arg(argc, argv, "--priv"));
    } 
    else if (cmd == "sign") {
        handle_sign(oqs_algo_str, get_arg(argc, argv, "--in"), get_arg(argc, argv, "--out"), get_arg(argc, argv, "--priv"));
    } 
    else if (cmd == "verify") {
        handle_verify(oqs_algo_str, get_arg(argc, argv, "--in"), get_arg(argc, argv, "--sig"), get_arg(argc, argv, "--pub"));
    } 
    else if (cmd == "encaps") {
        handle_encaps(oqs_algo_str, get_arg(argc, argv, "--pub"), get_arg(argc, argv, "--ct"), get_arg(argc, argv, "--ss"));
    } 
    else if (cmd == "decaps") {
        handle_decaps(oqs_algo_str, get_arg(argc, argv, "--priv"), get_arg(argc, argv, "--ct"), get_arg(argc, argv, "--ss"));
    }
    else if (cmd == "cert-gen") {
        std::string sub = get_arg(argc, argv, "--subject");
        std::string cert_algo = get_arg(argc, argv, "--cert-algo", "mldsa-44");
        
        if (sub.empty()) {
            sub = "PQ Subject";
        }
        
        handle_cert_issue(sub, get_arg(argc, argv, "--pub"), get_arg(argc, argv, "--priv"), get_arg(argc, argv, "--out"), cert_algo);
    }
    else if (cmd == "cert-verify") {
        handle_cert_verify(get_arg(argc, argv, "--in"), get_arg(argc, argv, "--pub"));
    }
    else if (cmd == "verify-n") {
        std::string algo = get_arg(argc, argv, "--algo");
        std::string list_file = get_arg(argc, argv, "--list");
        
        if (list_file.empty() || algo.empty()) {
            std::cerr << "[ERROR] Thieu flag --list hoac --algo cho verify-n!\n";
            OQS_destroy(); 
            return 1;
        }
        
        std::ifstream lf(list_file);
        if (!lf.is_open()) { 
            std::cerr << "[ERROR] Khong mo duoc file danh sach!\n"; 
            OQS_destroy(); 
            return 1; 
        }

        if (algo.find("mldsa") != std::string::npos) {
            const char* oqs_alg;
            if (algo == "mldsa-65") {
                oqs_alg = OQS_SIG_alg_ml_dsa_65;
            } else {
                oqs_alg = OQS_SIG_alg_ml_dsa_44;
            }
            
            OQS_SIG *sig = OQS_SIG_new(oqs_alg);
            std::string msg_p, sig_p, pub_p;
            int passed = 0;
            int total = 0;
            
            std::cout << "[INFO] Running Batch Verification for " << algo << "...\n";
            
            while (lf >> msg_p >> sig_p >> pub_p) {
                auto m = read_file(msg_p); 
                auto s = read_file(sig_p); 
                auto p = read_file(pub_p);
                
                if (!m.empty() && !s.empty() && !p.empty()) {
                    if (OQS_SIG_verify(sig, m.data(), m.size(), s.data(), s.size(), p.data()) == OQS_SUCCESS) {
                        passed++;
                    }
                    total++;
                }
            }
            
            std::cout << "[INFO] Batch Verify (" << algo << "): " << passed << "/" << total << " PASSED\n";
            OQS_SIG_free(sig);
        }
        else if (algo == "mlkem-512") {
            OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
            std::string ct_p, priv_p; 
            int total = 0;
            int passed = 0;
            
            std::cout << "[INFO] Running Batch Decapsulation for ML-KEM-512...\n";
            
            while (lf >> ct_p >> priv_p) {
                auto ct_data = read_file(ct_p); 
                auto priv_data = read_file(priv_p);
                
                if (!ct_data.empty() && !priv_data.empty()) {
                    std::vector<uint8_t> ss_recovered(kem->length_shared_secret);
                    
                    if (OQS_KEM_decaps(kem, ss_recovered.data(), ct_data.data(), priv_data.data()) == OQS_SUCCESS) {
                        passed++;
                    }
                    total++;
                }
            }
            
            std::cout << "[INFO] Batch Decapsulation Result: " << passed << "/" << total << " SUCCESS\n";
            OQS_KEM_free(kem);
        } else {
            std::cerr << "[ERROR] Thuat toan batch ho tro khong hop le.\n";
        }
    }
    else {
        std::cerr << "[ERROR] Unknown command.\n";
    }

    OQS_destroy();
    return 0;
}