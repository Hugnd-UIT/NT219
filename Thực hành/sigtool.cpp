#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/params.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <string>
#include <cstring>
#include <cstdlib>
#include <exception>
#include <cmath>
#include <algorithm>
#include <sstream>

#ifdef _WIN32
    #include <windows.h>
    #undef X509_NAME
    #undef X509_EXTENSIONS
    #undef X509_CERT_PAIR
#endif

//////////////////////////////////////////////////////////////
// HELPER
//////////////////////////////////////////////////////////////

template<typename T, void(*FreeFunc)(T*)>
using ossl_unique_ptr = std::unique_ptr<T, decltype(FreeFunc)>;

using BIO_ptr          = ossl_unique_ptr<BIO, BIO_free_all>;
using EVP_PKEY_ptr     = ossl_unique_ptr<EVP_PKEY, EVP_PKEY_free>;
using EVP_PKEY_CTX_ptr = ossl_unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using EVP_MD_CTX_ptr   = ossl_unique_ptr<EVP_MD_CTX, EVP_MD_CTX_free>;
using X509_REQ_ptr     = ossl_unique_ptr<X509_REQ, X509_REQ_free>;
using X509_ptr         = ossl_unique_ptr<X509, X509_free>;
using ASN1_INTEGER_ptr = ossl_unique_ptr<ASN1_INTEGER, ASN1_INTEGER_free>;

void handle_openssl_error(const std::string& context) {
    std::cerr << "[ERROR] OpenSSL Error in " << context << ":\n";
    ERR_print_errors_fp(stderr);
}

//////////////////////////////////////////////////////////////
// I/O & BASE64 HELPERS
//////////////////////////////////////////////////////////////

bool read_file_bytes(const std::string& file_path, std::vector<unsigned char>& data) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return false;
    }
    
    std::streamsize size = file.tellg();
    if (size < 0) {
        return false;
    }
    
    if (size == 0) { 
        data.clear(); 
        return true; 
    }
    
    file.seekg(0, std::ios::beg);
    data.resize(static_cast<size_t>(size));
    
    if (file.read(reinterpret_cast<char*>(data.data()), size)) {
        return true;
    } else {
        return false;
    }
}

bool write_file_bytes(const std::string& file_path, const std::vector<unsigned char>& data) {
    std::ofstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    if (!data.empty() && !file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
        return false;
    }
    
    return true;
}

EVP_PKEY_ptr load_private_key(const std::string& key_path) {
    BIO_ptr key_bio(BIO_new_file(key_path.c_str(), "rb"), BIO_free_all);
    if (!key_bio) {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }
    
    EVP_PKEY* raw_key = PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr);
    return EVP_PKEY_ptr(raw_key, EVP_PKEY_free);
}

EVP_PKEY_ptr load_public_key(const std::string& key_path) {
    BIO_ptr key_bio(BIO_new_file(key_path.c_str(), "rb"), BIO_free_all);
    if (!key_bio) {
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }
    
    EVP_PKEY* raw_key = PEM_read_bio_PUBKEY(key_bio.get(), nullptr, nullptr, nullptr);
    return EVP_PKEY_ptr(raw_key, EVP_PKEY_free);
}

std::string base64_encode(const std::vector<unsigned char>& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    
    if (!b64 || !mem) {
        BIO_free_all(b64); 
        BIO_free_all(mem);
        handle_openssl_error("BIO_new");
        return "";
    }
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, mem);
    
    if (BIO_write(b64, input.data(), static_cast<int>(input.size())) <= 0) {
        BIO_free_all(b64);
        handle_openssl_error("BIO_write");
        return "";
    }
    
    if (BIO_flush(b64) != 1) {
        BIO_free_all(b64);
        handle_openssl_error("BIO_flush");
        return "";
    }
    
    BUF_MEM* buffer_ptr = nullptr;
    BIO_get_mem_ptr(b64, &buffer_ptr);
    
    if (!buffer_ptr || !buffer_ptr->data) {
        BIO_free_all(b64);
        handle_openssl_error("BIO_get_mem_ptr");
        return "";
    }
    
    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(b64);
    return result;
}

std::vector<unsigned char> base64_decode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(input.data(), input.size());
    
    if (!b64 || !mem) {
        BIO_free_all(b64); 
        BIO_free_all(mem);
        handle_openssl_error("BIO_new");
        return {};
    }
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, mem);
    std::vector<unsigned char> result(input.size());
    int decoded_size = BIO_read(b64, result.data(), input.size());
    BIO_free_all(b64);
    
    if (decoded_size > 0) {
        result.resize(decoded_size);
    } else {
        result.clear();
    }
    return result;
}

std::string hex_encode(const std::vector<unsigned char>& input) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(input.size() * 2);
    for (unsigned char b : input) {
        result.push_back(hex_chars[b >> 4]);
        result.push_back(hex_chars[b & 0x0f]);
    }
    return result;
}

std::vector<unsigned char> hex_decode(const std::string& input) {
    std::vector<unsigned char> result;
    result.reserve(input.size() / 2);
    
    for (size_t i = 0; i < input.size(); i += 2) {
        if (i + 1 >= input.size()) {
            break;
        }
        std::string byteString = input.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

//////////////////////////////////////////////////////////////
// ECDSA KEY GENERATION
//////////////////////////////////////////////////////////////

bool generate_ecdsa_keypair(const std::string& curve_name, const std::string& private_key_path, const std::string& public_key_path) {
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);

    if (!ctx) {
        handle_openssl_error("EVP_PKEY_CTX_new_id");
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        handle_openssl_error("EVP_PKEY_keygen_init");
        return false;
    }

    int curve_nid = OBJ_txt2nid(curve_name.c_str());

    if (curve_nid == NID_undef) {
        std::cerr << "[ERROR] Invalid curve name: " << curve_name << "\n";
        return false;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), curve_nid) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
        return false;
    }

    EVP_PKEY* raw_key = nullptr;

    if (EVP_PKEY_keygen(ctx.get(), &raw_key) <= 0) {
        handle_openssl_error("EVP_PKEY_keygen");
        return false;
    }

    EVP_PKEY_ptr key(raw_key, EVP_PKEY_free);
    BIO_ptr priv_bio(BIO_new_file(private_key_path.c_str(), "wb"), BIO_free_all);

    if (!priv_bio) {
        handle_openssl_error("BIO_new_file");
        return false;
    }

    if (PEM_write_bio_PrivateKey(priv_bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        handle_openssl_error("PEM_write_bio_PrivateKey");
        return false;
    }

    BIO_ptr pub_bio(BIO_new_file(public_key_path.c_str(), "wb"), BIO_free_all);

    if (!pub_bio) {
        handle_openssl_error("BIO_new_file");
        return false;
    }

    if (PEM_write_bio_PUBKEY(pub_bio.get(), key.get()) != 1) {
        handle_openssl_error("PEM_write_bio_PUBKEY");
        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////
// RSA KEY GENERATION
//////////////////////////////////////////////////////////////

bool generate_rsa_keypair(int bits, const std::string& private_key_path, const std::string& public_key_path) {
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);

    if (!ctx) {
        handle_openssl_error("EVP_PKEY_CTX_new_id");
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        handle_openssl_error("EVP_PKEY_keygen_init");
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_rsa_keygen_bits");
        return false;
    }

    EVP_PKEY* raw_key = nullptr;

    if (EVP_PKEY_keygen(ctx.get(), &raw_key) <= 0) {
        handle_openssl_error("EVP_PKEY_keygen");
        return false;
    }

    EVP_PKEY_ptr key(raw_key, EVP_PKEY_free);
    BIO_ptr priv_bio(BIO_new_file(private_key_path.c_str(), "wb"), BIO_free_all);

    if (!priv_bio) {
        handle_openssl_error("BIO_new_file");
        return false;
    }

    if (PEM_write_bio_PrivateKey(priv_bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        handle_openssl_error("PEM_write_bio_PrivateKey");
        return false;
    }

    BIO_ptr pub_bio(BIO_new_file(public_key_path.c_str(), "wb"), BIO_free_all);

    if (!pub_bio) {
        handle_openssl_error("BIO_new_file");
        return false;
    }

    if (PEM_write_bio_PUBKEY(pub_bio.get(), key.get()) != 1) {
        handle_openssl_error("PEM_write_bio_PUBKEY");
        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////
// CSR GENERATION
//////////////////////////////////////////////////////////////

bool generate_csr(const std::string& private_key_path, const std::string& csr_path, const std::vector<std::string>& subject_info) {
    EVP_PKEY_ptr key = load_private_key(private_key_path);

    if (!key) {
        return false;
    }

    X509_REQ_ptr req(X509_REQ_new(), X509_REQ_free);

    if (!req) {
        handle_openssl_error("X509_REQ_new");
        return false;
    }

    if (X509_REQ_set_version(req.get(), 0L) != 1) {
        handle_openssl_error("X509_REQ_set_version");
        return false;
    }

    X509_NAME* name = const_cast<X509_NAME*>(X509_REQ_get_subject_name(req.get()));

    if (!name) {
        handle_openssl_error("X509_REQ_get_subject_name");
        return false;
    }

    for (const auto& entry : subject_info) {
        size_t pos = entry.find('=');

        if (pos == std::string::npos) {
            std::cerr << "[ERROR] Invalid subject entry: " << entry << "\n";
            return false;
        }

        std::string field = entry.substr(0, pos);
        std::string value = entry.substr(pos + 1);

        if (X509_NAME_add_entry_by_txt(name, field.c_str(), MBSTRING_ASC, reinterpret_cast<const unsigned char*>(value.c_str()), -1, -1, 0) != 1) {
            handle_openssl_error("X509_NAME_add_entry_by_txt");
            return false;
        }
    }

    if (X509_REQ_set_pubkey(req.get(), key.get()) != 1) {
        handle_openssl_error("X509_REQ_set_pubkey");
        return false;
    }

    if (X509_REQ_sign(req.get(), key.get(), EVP_sha256()) <= 0) {
        handle_openssl_error("X509_REQ_sign");
        return false;
    }

    BIO_ptr csr_bio(BIO_new_file(csr_path.c_str(), "wb"), BIO_free_all);

    if (!csr_bio) {
        handle_openssl_error("BIO_new_file");
        return false;
    }

    if (PEM_write_bio_X509_REQ(csr_bio.get(), req.get()) != 1) {
        handle_openssl_error("PEM_write_bio_X509_REQ");
        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////
// LOAD CSR
//////////////////////////////////////////////////////////////

X509_REQ_ptr load_csr(const std::string& csr_path) {
    BIO_ptr csr_bio(BIO_new_file(csr_path.c_str(), "rb"), BIO_free_all);

    if (!csr_bio) {
        handle_openssl_error("BIO_new_file");
        return X509_REQ_ptr(nullptr, X509_REQ_free);
    }

    X509_REQ* raw_req = PEM_read_bio_X509_REQ(csr_bio.get(), nullptr, nullptr, nullptr);

    if (!raw_req) {
        handle_openssl_error("PEM_read_bio_X509_REQ");
        return X509_REQ_ptr(nullptr, X509_REQ_free);
    }

    return X509_REQ_ptr(raw_req, X509_REQ_free);
}

//////////////////////////////////////////////////////////////
// SELF-SIGNED CERTIFICATE
//////////////////////////////////////////////////////////////

bool generate_self_signed_certificate(const std::string& csr_path, const std::string& private_key_path, const std::string& certificate_path, int days) {
    X509_REQ_ptr req = load_csr(csr_path);

    if (!req) {
        return false;
    }

    EVP_PKEY_ptr ca_key = load_private_key(private_key_path);

    if (!ca_key) {
        return false;
    }

    EVP_PKEY* raw_pubkey = X509_REQ_get_pubkey(req.get());

    if (!raw_pubkey) {
        handle_openssl_error("X509_REQ_get_pubkey");
        return false;
    }

    EVP_PKEY_ptr pubkey(raw_pubkey, EVP_PKEY_free);

    if (X509_REQ_verify(req.get(), pubkey.get()) != 1) {
        handle_openssl_error("X509_REQ_verify");
        return false;
    }

    X509_ptr cert(X509_new(), X509_free);

    if (!cert) {
        handle_openssl_error("X509_new");
        return false;
    }

    if (X509_set_version(cert.get(), 2L) != 1) {
        handle_openssl_error("X509_set_version");
        return false;
    }

    ASN1_INTEGER_ptr serial(ASN1_INTEGER_new(), ASN1_INTEGER_free);
    ASN1_INTEGER_set(serial.get(), 1L);
    X509_set_serialNumber(cert.get(), serial.get());

    const X509_NAME* subject = X509_REQ_get_subject_name(req.get());
    X509_set_subject_name(cert.get(), subject);
    X509_set_issuer_name(cert.get(), subject);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60L * 60L * 24L * days);
    X509_set_pubkey(cert.get(), pubkey.get());

    if (X509_sign(cert.get(), ca_key.get(), EVP_sha256()) <= 0) {
        handle_openssl_error("X509_sign");
        return false;
    }

    BIO_ptr cert_bio(BIO_new_file(certificate_path.c_str(), "wb"), BIO_free_all);

    if (!cert_bio) {
        handle_openssl_error("BIO_new_file");
        return false;
    }

    if (PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1) {
        handle_openssl_error("PEM_write_bio_X509");
        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////
// ECDSA SIGNING
//////////////////////////////////////////////////////////////

bool sign_ecdsa(const std::string& private_key_path, const std::string& message_path, const std::string& signature_path, const std::string& hash_name = "sha256") {
    EVP_PKEY_ptr pkey = load_private_key(private_key_path);

    if (!pkey) {
        return false;
    }

    if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_EC) {
        std::cerr << "[ERROR] Provided key is not an EC key.\n";
        return false;
    }

    std::vector<unsigned char> message_data;

    if (!read_file_bytes(message_path, message_data)) {
        return false;
    }

    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!md_ctx) {
        handle_openssl_error("EVP_MD_CTX_new");
        return false;
    }

    const EVP_MD* md = EVP_get_digestbyname(hash_name.c_str());
    EVP_PKEY_CTX* pkey_ctx = nullptr; 

    if (!md_ctx || !md || EVP_DigestSignInit(md_ctx.get(), &pkey_ctx, md, nullptr, pkey.get()) <= 0) {
        return false;
    }
    
    unsigned int nonce_type = 1;
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_uint("nonce-type", &nonce_type);
    params[1] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX_set_params(pkey_ctx, params);

    if (EVP_DigestSignUpdate(md_ctx.get(), message_data.data(), message_data.size()) <= 0) {
        handle_openssl_error("EVP_DigestSignUpdate");
        return false;
    }

    size_t sig_len = 0;

    if (EVP_DigestSignFinal(md_ctx.get(), nullptr, &sig_len) <= 0) {
        handle_openssl_error("EVP_DigestSignFinal(size)");
        return false;
    }

    std::vector<unsigned char> signature(sig_len);

    if (EVP_DigestSignFinal(md_ctx.get(), signature.data(), &sig_len) <= 0) {
        handle_openssl_error("EVP_DigestSignFinal(sign)");
        return false;
    }

    signature.resize(sig_len);

    if (!write_file_bytes(signature_path, signature)) {
        return false;
    }

    std::cout << "[INFO] ECDSA Signature (Base64):\n" << base64_encode(signature) << "\n";

    return true;
}

//////////////////////////////////////////////////////////////
// RSA-PSS SIGNING
//////////////////////////////////////////////////////////////

bool sign_rsapss(const std::string& private_key_path, const std::string& message_path, const std::string& signature_path, const std::string& hash_name = "sha256") {
    EVP_PKEY_ptr pkey = load_private_key(private_key_path);

    if (!pkey) {
        return false;
    }

    if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_RSA) {
        std::cerr << "[ERROR] Provided key is not RSA.\n";
        return false;
    }

    std::vector<unsigned char> message_data;

    if (!read_file_bytes(message_path, message_data)) {
        return false;
    }

    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!md_ctx) {
        handle_openssl_error("EVP_MD_CTX_new");
        return false;
    }

    const EVP_MD* md = EVP_get_digestbyname(hash_name.c_str());
    EVP_PKEY_CTX* pkey_ctx = nullptr;

    if (!md_ctx || !md || EVP_DigestSignInit(md_ctx.get(), &pkey_ctx, md, nullptr, pkey.get()) <= 0) {
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_rsa_padding");
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_rsa_pss_saltlen");
        return false;
    }

    if (EVP_DigestSignUpdate(md_ctx.get(), message_data.data(), message_data.size()) <= 0) {
        handle_openssl_error("EVP_DigestSignUpdate");
        return false;
    }

    size_t sig_len = 0;

    if (EVP_DigestSignFinal(md_ctx.get(), nullptr, &sig_len) <= 0) {
        handle_openssl_error("EVP_DigestSignFinal(size)");
        return false;
    }

    std::vector<unsigned char> signature(sig_len);

    if (EVP_DigestSignFinal(md_ctx.get(), signature.data(), &sig_len) <= 0) {
        handle_openssl_error("EVP_DigestSignFinal(sign)");
        return false;
    }

    signature.resize(sig_len);

    if (!write_file_bytes(signature_path, signature)) {
        return false;
    }

    std::cout << "[INFO] RSA-PSS Signature (Base64):\n" << base64_encode(signature) << "\n";

    return true;
}

//////////////////////////////////////////////////////////////
// VERIFICATION
//////////////////////////////////////////////////////////////

bool verify_ecdsa(const std::string& public_key_path, const std::string& message_path, const std::string& signature_path, const std::string& hash_name = "sha256") {    
    EVP_PKEY_ptr pkey = load_public_key(public_key_path);
    if (!pkey) {
        return false;
    }

    if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_EC) {
        std::cerr << "[ERROR] Provided key is not an EC key for ECDSA verification." << std::endl;
        return false;
    }

    std::vector<unsigned char> message_data;
    if (!read_file_bytes(message_path, message_data)) {
        return false;
    }

    std::vector<unsigned char> signature_data;
    if (!read_file_bytes(signature_path, signature_data)) {
        return false;
    }

    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!md_ctx) {
        handle_openssl_error("EVP_MD_CTX_new for verification");
        return false;
    }

    const EVP_MD* md = EVP_get_digestbyname(hash_name.c_str());

    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, md, nullptr, pkey.get()) <= 0) {
        handle_openssl_error("EVP_DigestVerifyInit");
        return false;
    }

    if (EVP_DigestVerifyUpdate(md_ctx.get(), message_data.data(), message_data.size()) <= 0) {
        handle_openssl_error("EVP_DigestVerifyUpdate");
        return false;
    }

    int verify_result = EVP_DigestVerifyFinal(md_ctx.get(), signature_data.data(), signature_data.size());

    if (verify_result == 1) {
        return true; 
    } else if (verify_result == 0) {
        std::cerr << "[ERROR] Verification failed: Signature is invalid." << std::endl;
        return false; 
    } else {
        handle_openssl_error("EVP_DigestVerifyFinal");
        return false; 
    }
}

bool verify_rsapss(const std::string& public_key_path, const std::string& message_path, const std::string& signature_path, const std::string& hash_name = "sha256") {
    EVP_PKEY_ptr pkey = load_public_key(public_key_path);
    if (!pkey) {
        return false;
    }

    if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_RSA) {
        std::cerr << "[ERROR] Provided key is not an RSA key for RSASSA-PSS verification." << std::endl;
        return false;
    }

    std::vector<unsigned char> message_data;
    if (!read_file_bytes(message_path, message_data)) {
        return false;
    }

    std::vector<unsigned char> signature_data;
    if (!read_file_bytes(signature_path, signature_data)) {
        return false;
    }

    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    unsigned int digest_len = 0;

    const EVP_MD* md = EVP_get_digestbyname(hash_name.c_str());
    
    if (!EVP_Digest(message_data.data(), message_data.size(), digest.data(), &digest_len, md, nullptr)) {
        handle_openssl_error("EVP_Digest (calculate hash for PSS verify)");
        return false;
    }
    digest.resize(digest_len);

    EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new(pkey.get(), nullptr), EVP_PKEY_CTX_free); 
    if (!pctx) {
        handle_openssl_error("EVP_PKEY_CTX_new for PSS verification");
        return false;
    }

    if (EVP_PKEY_verify_init(pctx.get()) <= 0) {
        handle_openssl_error("EVP_PKEY_verify_init");
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx.get(), RSA_PKCS1_PSS_PADDING) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_rsa_padding (PSS)");
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx.get(), -1) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_rsa_pss_saltlen");
        return false;
    }

    if (EVP_PKEY_CTX_set_signature_md(pctx.get(), md) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_signature_md");
        return false;
    }

    int verify_result = EVP_PKEY_verify(pctx.get(), signature_data.data(), signature_data.size(), digest.data(), digest.size());

    if (verify_result == 1) {
        return true; 
    } else if (verify_result == 0) {
        std::cerr << "[ERROR] Verification failed: RSASSA-PSS Signature is invalid." << std::endl;
        return false; 
    } else {
        handle_openssl_error("EVP_PKEY_verify");
        return false; 
    }
}

//////////////////////////////////////////////////////////////
// CLI
//////////////////////////////////////////////////////////////

int main(int argc, char* argv[]) {

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    std::cout << "\n";
    std::cout << "  ██████╗ ██╗ ██████╗ ██╗████████╗ █████╗ ██╗     \n";
    std::cout << "  ██╔══██╗██║██╔════╝ ██║╚══██╔══╝██╔══██╗██║     \n";
    std::cout << "  ██║  ██║██║██║  ███╗██║   ██║   ███████║██║     \n";
    std::cout << "  ██║  ██║██║██║   ██║██║   ██║   ██╔══██║██║     \n";
    std::cout << "  ██████╔╝██║╚██████╔╝██║   ██║   ██║  ██║███████╗\n";
    std::cout << "  ╚═════╝ ╚═╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝\n";
    std::cout << "\n";
    std::cout << "  ███████╗██╗ ██████╗ ███╗   ██╗ █████╗ ████████╗██╗   ██╗██████╗ ███████╗\n";
    std::cout << "  ██╔════╝██║██╔════╝ ████╗  ██║██╔══██╗╚══██╔══╝██║   ██║██╔══██╗██╔════╝\n";
    std::cout << "  ███████╗██║██║  ███╗██╔██╗ ██║███████║   ██║   ██║   ██║██████╔╝█████╗  \n";
    std::cout << "  ╚════██║██║██║   ██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██╔══██╗██╔══╝  \n";
    std::cout << "  ███████║██║╚██████╔╝██║ ╚████║██║  ██║   ██║   ╚██████╔╝██║  ██║███████╗\n";
    std::cout << "  ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝\n";
    std::cout << "\n";

    if (argc < 2) {
        std::cout
            << "Usage:\n"
            << "  sigtool keygen [options]\n"
            << "  sigtool sign [options]\n"
            << "  sigtool verify [options]\n"
            << "  sigtool verify-n [options]\n"
            << "\n"

            << "Required:\n"
            << "  keygen   : --algo --priv --pub\n"
            << "  sign     : --algo --in --out --priv --hash\n"
            << "  verify   : --algo --in --sig --pub --hash\n"
            << "  verify-n : --algo --list\n"
            << "\n"

            << "Options:\n"
            << "  --algo <algorithm>\n"
            << "  --priv <private.pem>\n"
            << "  --pub <public.pem>\n"
            << "  --in <file>\n"
            << "  --out <file>\n"
            << "  --sig <signature>\n"
            << "  --list <list.txt>\n"
            << "  --hash <sha256|sha384>\n"
            << "  --encode <raw|hex|base64>\n"
            << "\n"

            << "Algorithms:\n"
            << "  rsa-pss-3072\n"
            << "  ecdsa-p256\n"
            << "  ecdsa-p384\n"
            << std::endl;

        return 1;
    }

    std::string cmd = argv[1];

    std::string algo, priv, pub, in_file, out_file, sig_file;
    std::string hash_algo = "sha256";
    std::string encode_mode = "raw";
    
    for (int i = 2; i < argc; i++) {
        std::string flag = argv[i];
        if (flag == "--algo" && i + 1 < argc) {
            algo = argv[++i];
        } else if (flag == "--priv" && i + 1 < argc) {
            priv = argv[++i];
        } else if (flag == "--pub" && i + 1 < argc) {
            pub = argv[++i];
        } else if (flag == "--in" && i + 1 < argc) {
            in_file = argv[++i];
        } else if (flag == "--out" && i + 1 < argc) {
            out_file = argv[++i];
        } else if (flag == "--sig" && i + 1 < argc) {
            sig_file = argv[++i];
        } else if (flag == "--hash" && i + 1 < argc) {
            hash_algo = argv[++i];
        } else if (flag == "--encode" && i + 1 < argc) {
            encode_mode = argv[++i];
        }
    }

    if (cmd == "keygen") {
        if (algo == "rsa-pss-3072") {
            if (generate_rsa_keypair(3072, priv, pub)) {
                std::cout << "[INFO] Keygen successful for " << algo << "\n";
                return 0;
            } else {
                std::cerr << "[ERROR] Keygen failed for " << algo << "\n";
                return 1;
            }
        }
        if (algo == "ecdsa-p256") {
            if (generate_ecdsa_keypair("prime256v1", priv, pub)) {
                std::cout << "[INFO] Keygen successful for " << algo << "\n";
                return 0;
            } else {
                std::cerr << "[ERROR] Keygen failed for " << algo << "\n";
                return 1;
            }
        }
        if (algo == "ecdsa-p384") {
            if (generate_ecdsa_keypair("secp384r1", priv, pub)) {
                std::cout << "[INFO] Keygen successful for " << algo << "\n";
                return 0;
            } else {
                std::cerr << "[ERROR] Keygen failed for " << algo << "\n";
                return 1;
            }
        }
        std::cerr << "[ERROR] Unknown algorithm: " << algo << "\n";
        return 1;
    } 
    else if (cmd == "sign") {
        std::string temp_sig = out_file + ".tmp";
        bool ok = false;
        
        if (algo == "rsa-pss-3072") {
            ok = sign_rsapss(priv, in_file, temp_sig, hash_algo);
        } else {
            ok = sign_ecdsa(priv, in_file, temp_sig, hash_algo);
        }
        
        if (!ok) {
            return 1;
        }

        std::vector<unsigned char> raw_sig; 
        read_file_bytes(temp_sig, raw_sig);
        std::remove(temp_sig.c_str());
        
        std::string encoded;
        if (encode_mode == "base64") {
            encoded = base64_encode(raw_sig);
        } else if (encode_mode == "hex") {
            encoded = hex_encode(raw_sig);
        } else {
            encoded = std::string(raw_sig.begin(), raw_sig.end());
        }

        std::ofstream out(out_file, std::ios::binary); 
        out.write(encoded.data(), encoded.size());
        
        std::cout << "[INFO] Signature generated successfully. Format: " << encode_mode << "\n";
        return 0;
    } 
    else if (cmd == "verify") {
        std::vector<unsigned char> sig_data; 
        read_file_bytes(sig_file, sig_data);
        std::string content(sig_data.begin(), sig_data.end());
        std::string raw_str;

        if (encode_mode == "base64") { 
            auto d = base64_decode(content); 
            raw_str = std::string(d.begin(), d.end()); 
        } else if (encode_mode == "hex") { 
            auto d = hex_decode(content); 
            raw_str = std::string(d.begin(), d.end()); 
        } else {
            raw_str = content;
        }

        std::string final_sig_path = sig_file;
        if (encode_mode != "raw") {
            final_sig_path = sig_file + ".tmp_dec";
            write_file_bytes(final_sig_path, std::vector<unsigned char>(raw_str.begin(), raw_str.end()));
        }

        bool ok = false;
        if (algo == "rsa-pss-3072") {
            ok = verify_rsapss(pub, in_file, final_sig_path, hash_algo);
        } else {
            ok = verify_ecdsa(pub, in_file, final_sig_path, hash_algo);
        }
        
        if (encode_mode != "raw") { 
            std::remove(final_sig_path.c_str()); 
        }

        if (ok) { 
            std::cout << "[INFO] Verification successful: Signature is valid!\n"; 
            return 0; 
        } else { 
            std::cerr << "[ERROR] Verification failed: File modified or wrong key!\n"; 
            return 1; 
        }
    }
    else if (cmd == "verify-n") {
        std::string list_file;
        for (int i = 2; i < argc; i++) {
            if (std::string(argv[i]) == "--list" && i + 1 < argc) {
                list_file = argv[++i];
            }
        }
        
        if (list_file.empty() || algo.empty()) { 
            std::cerr << "[ERROR] Missing flag --list or --algo!\n"; 
            return 1; 
        }
        
        std::ifstream file(list_file);
        if (!file.is_open()) {
            return 1;
        }

        std::string m_path, s_path, p_path;
        int total = 0;
        int passed = 0;
        
        while (file >> m_path >> s_path >> p_path) {
            total++;
            bool ok = false;
            if (algo == "rsa-pss-3072") {
                ok = verify_rsapss(p_path, m_path, s_path, "sha256");
            } else {
                ok = verify_ecdsa(p_path, m_path, s_path, "sha256");
            }
            if (ok) {
                passed++;
            }
        }
        
        std::cout << "[INFO] Batch Verify: " << passed << "/" << total << " PASSED.\n";
        
        if (total == passed && total > 0) {
            return 0;
        } else {
            return 1;
        }
    }
    
    return 1;
}