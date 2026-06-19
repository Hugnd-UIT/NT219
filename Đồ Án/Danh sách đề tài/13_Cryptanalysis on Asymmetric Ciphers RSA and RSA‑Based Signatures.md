# Capstone Project — Cryptanalysis on Asymmetric Ciphers: RSA & RSA‑Based Signatures

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Cryptanalysis on Asymmetric Ciphers — Phân tích và thực nghiệm RSA và các phiên bản chữ ký số dựa trên RSA (PKCS#1 v1.5, PSS)

---

## 1. Tóm tắt đề tài (Project Synopsis)

Đề tài nghiên cứu các **kỹ thuật tấn công** và **yếu điểm triển khai thực tế** trên RSA và các scheme chữ ký dựa trên RSA (ví dụ PKCS#1 v1.5, RSASSA‑PSS). Sinh viên sẽ khảo sát lý thuyết (factoring attacks, low‑exponent attacks, chosen‑ciphertext attacks, Bleichenbacher padding oracle), thực hiện PoC an toàn cho một số vectơ tấn công trong môi trường kiểm soát (padding oracle, timing, Bleichenbacher, RSA‑CRT fault), đánh giá rủi ro trong các kịch bản triển khai (TLS, code signing, JWT/ID tokens, smartcards/HSMs), và đề xuất biện pháp khắc phục và vận hành (key sizes, padding schemes, side‑channel protections, HSM usage).

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu cơ chế toán học nền tảng của RSA (factorization hardness, modular exponentiation) và các biến thể chữ ký (PKCS#1 v1.5 vs PSS).
2. Khảo sát các class attack: factoring (GNFS), low‑exponent attacks (Håstad), CCA (Bleichenbacher), padding oracle, Wiener’s attack (small private exponent), fault attacks on RSA‑CRT, timing & side‑channel attacks.
3. Triển khai PoC tấn công an toàn (lab): Bleichenbacher oracle on PKCS#1 v1.5 in TLS 1.0/1.1-like server, timing/leakage measurement on RSA implementations, RSA‑CRT fault injection simulation (or hardware if available).
4. Phân tích weaknesses khi RSA được dùng trong hệ thống thực (TLS certs, JWT RS256, code signing, SSH, smartcards) và đề xuất mitigations.
5. Viết báo cáo reproducible: PoC code, experiment logs, mitigation checklist.

---

## 3. Tính cấp thiết & động lực (Relevance)

* RSA vẫn được sử dụng rộng rãi trong nhiều hệ thống (TLS, code signing, JWT, SSH) dù NIST/industry recommend key sizes and alternatives (ECC, PQC). Hiểu vector tấn công thực tế giúp tổ chức đánh giá rủi ro và lập lộ trình migration.
* Một số tấn công thực tế exploit implementation mistakes (padding handling, timing leaks, flawed RNG) hơn là breaking RSA mathematically.

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Trong kịch bản triển khai thực tế (TLS, JWT, code signing, HSMs), đâu là các weakness phổ biến nhất liên quan tới RSA và chúng dẫn tới hậu quả gì (forgery, key recovery, signature replay)?

**RQ2:** Các tấn công Bleichenbacher padding oracle và timing attacks còn khả thi trên các stacks hiện đại (OpenSSL/LibreSSL/BoringSSL) khi gặp cấu hình cũ hoặc lỗi?

**RQ3:** Fault injection on RSA‑CRT or side‑channel leakage from smartcards/HSMs remains a high‑risk vector in physical access scenarios.

**Giả thuyết:** Thực tế compromise thường xảy ra do: unsafe padding (PKCS#1 v1.5) handling, weak RNG producing predictable primes, small exponent misuse, and side‑channel / fault vulnerabilities in hardware implementations. Migrating to RSA‑PSS, enforcing large key sizes (≥3072), using HSMs and constant‑time libraries reduce practical risk substantially.

---

## 5. Background (Tổng quan ngắn)

* **RSA primitives:** keygen (p,q primes), n = p·q, e public exponent, d private exponent. RSA operations: encryption/signature `m^e mod n` and decryption/verification `c^d mod n`.
* **RSA optimizations:** CRT (speed up decryption/signing) introduces fault attack surface.
* **Attacks categories:** factoring (GNFS → requires huge resources for large keys), algorithmic attacks on small exponents, padding oracles (implementation), side‑channel (timing, power), fault attacks, and chosen‑ciphertext attacks.
* **Signature schemes:** PKCS#1 v1.5 historically used in TLS and code signing; RSASSA‑PSS is newer and provides provable security against certain attacks.

---

## 6. Literature review (hướng khảo sát)

* Bleichenbacher (1998) on PKCS#1 v1.5 padding oracle attack.
* Wiener (1990) on small private exponent attack.
* Håstad’s attack on low exponents and common modulus scenarios.
* Timing attacks (Kocher), Fault attacks on RSA‑CRT (Boneh, DeMillo & Lipton), side‑channel literature on smartcards and HSMs.
* Practical incident reports: PKCS#1 v1.5 exploits, vulnerable TLS stacks, RNG failures (Debian OpenSSL 2006), and CVEs on RSA libs.

> Sinh viên cần trích dẫn ít nhất 6 papers / reports và 3 codebases/tools (OpenSSL, RsaCtfTool, spiped/pkcs1\_oracle PoCs).

---

## 7. Phân tích weaknesses trong kịch bản triển khai thực tế (Deep Deployment Weakness Analysis)

### 7.1. TLS / HTTPS

* **Bleichenbacher padding oracle:** Servers that process RSA PKCS#1 v1.5 encrypted PreMasterSecret (TLS ≤1.2) and reveal different errors or timing differences can enable full key recovery of session secrets; modern TLS 1.3 removes RSA key exchange, but legacy servers and clients remain.
* **RSA key exchange deprecation:** RSA key exchange mode (where server private key decrypts PreMasterSecret) is discouraged; ECDHE preferred for forward secrecy.
* **Certificate validation & signature schemes:** Use of PKCS#1 v1.5 signatures for certificates (e.g., old CA-signed certs) may be abused in certain contexts; however main issue historically is PKCS#1 v1.5 encryption padding.

### 7.2. JWT / token signing (RS256)

* **Token forgery / alg confusion:** JWT libraries historically had 'alg: none' parsing bugs; misuse of RSA keys vs HMAC (mistaking alg) can lead to forgery. Ensure strict verification of `alg` and JWK kid selection.
* **Key sizes & rotation:** small RSA keys, absent rotation, or leaked private keys lead to compromise; RS256 uses PKCS#1 v1.5 signature scheme by default — RSA‑PSS preferred for new designs.

### 7.3. Code signing & package ecosystems

* **Weak signing tools / key exposure:** compromised build machines or improper key storage lead to signing key theft; offline HSMs recommended.
* **Legacy signature format:** some ecosystems still accept legacy signature formats that may be susceptible to malleability or replay.

### 7.4. Smartcards / HSMs / TPMs

* **Side‑channel & Fault attacks:** physical attackers with access to smartcards can perform power analysis or induce faults to extract RSA private key, especially when RSA‑CRT is used without countermeasures.
* **API misuse:** exposing raw decryption/signing endpoints from HSM without proper ACL/restrictions can enable abuse (e.g., Bleichenbacher style oracle through HSM interface).

### 7.5. RNG & Key Generation

* **Weak RNG:** insufficient entropy during key generation (e.g., embedded devices) can lead to predictable primes or shared prime reuse across devices — enabling factorization via gcd across moduli.
* **Common modulus / shared primes:** practice errors where different keys share primes or modulus derivatives — catastrophic.

### 7.6. Implementation bugs & side channels

* **Timing leaks in modular exponentiation:** unblinded exponentiation leaks bits via timing; need constant‑time implementations and exponent blinding.
* **CRT recombination faults:** fault during CRT computation reveals p or q (Boneh fault attack).
* **Padding oracle in TLS stacks / libraries:** error messages or timing differences provide oracle.

---

## 8. Methodology (Pipeline & Experiments)

### 8.1. Experimental targets (suggested attacks)

* **Attack A — Bleichenbacher padding oracle PoC:** create a TLS‑like server that uses RSA PKCS#1 v1.5 decryption for PreMasterSecret and leaks different behavior; implement oracle and recover session secrets; then patch to PSS or constant error handling and retest.
* **Attack B — Timing attack on RSA implementation:** measure remote/local timing differences to leak bits of d or enable partial key recovery; evaluate countermeasures (exponent blinding, constant‑time libs).
* **Attack C — Wiener's small‑d / low‑exponent misuse:** generate vulnerable keys with small d or test on weakly generated keys (simulate embedded devices), exploit to recover private key.
* **Attack D — Fault attack on RSA‑CRT:** simulate fault injection (software fault model) and apply Boneh‑DeMillo‑Lipton style attack to recover primes; if hardware glitching available, perform on sacrificial smartcard/HSM with permission.
* **Attack E — Key generation weakness:** analyze multiple generated moduli from simulated low‑entropy device population to find gcd collisions / shared primes.

### 8.2. Lab setup & safety

* Isolated lab network, local TLS server (OpenSSL older version if needed for PoC), HSM/smartcard emulation (SoftHSM) or real device in controlled setting, scripts for automation (RsaCtfTool, custom Python PoC).
* Ensure PoC targets only lab instances; follow ethical rules.

### 8.3. Data collection & metrics

* **Success criteria:** private key recovered? session secret recovered? signature forgery accepted?
* **Effort metrics:** number of oracle queries, time to exploit, computational resources (CPU/GPU), need for physical access.
* **Countermeasure effectiveness:** measure whether blinding/padding changes prevent exploitation.

---

## 9. Implementation & Tools

* **Libraries/tools:** OpenSSL (different versions), RsaCtfTool, MPrime/pari/gmp for big integer ops, scripts for Bleichenbacher PoC (e.g., implementation variants), side‑channel tooling (ChipWhisperer for power), timing measurement harness, SoftHSM for HSM emulation.
* **Hardware:** smartcards or HSM (if available, with permission), general servers for TLS testing, ability to run older OpenSSL versions in container for reproduction.

---

## 10. Evaluation Plan & Metrics

* **Exploit metrics:** key recovered / forgery / plaintext recovered boolean; number of queries; runtime; external resources used.
* **Operational risk metrics:** prevalence of vulnerable config in sample codebases (scan), potential impact (scope of keys affected), ease of detection.
* **Mitigation effectiveness:** validate RSA‑PSS, constant error messages, exponent & CRT blinding, RNG improvements, HSM use.

---

## 11. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Literature review, select experiments, set up lab environment (containers for OpenSSL variants, SoftHSM).
* **Tuần 3–4:** Implement Attack A (Bleichenbacher PoC) in lab environment and collect metrics.
* **Tuần 5–6:** Implement Attack B (timing attacks) and evaluate with/without blinding.
* **Tuần 7–8:** Implement Attack C (Wiener/low‑d) and keygen weakness experiments.
* **Tuần 9–10:** Implement Attack D (RSA‑CRT fault) simulation; if hardware allowed, perform controlled physical test.
* **Tuần 11:** Aggregate results, run mitigation tests and ablation studies.
* **Tuần 12:** Finalize report, reproducible repo, demo video, presentation.

---

## 12. Deliverables

1. **Mid‑term report/presentation:** chosen attacks, lab setup, early results.
2. **Final report:** full experimental methodology, results, weaknesses found, mitigation checklist.
3. **Code repo & PoC:** carefully documented PoC code, Docker containers, logs, and instructions to reproduce in lab.
4. **Responsible disclosure plan:** outline how to report any vulnerabilities found in real libraries to maintainers.
5. **Demo video:** show at least one PoC attack (e.g., Bleichenbacher) and the patched mitigation.

---

## 13. Assessment & Rubric (gợi ý)

* Research grounding & relevance: 20%
* PoC correctness & reproducibility (ethical lab): 30%
* Depth of deployment weakness analysis and mitigation recommendations: 25%
* Documentation & code quality: 15%
* Presentation & clarity: 10%

---

## 14. Risks, Limitations & Ethical Considerations

* **Dual‑use warning:** PoC for Bleichenbacher and similar attacks can be abused; only run in isolated lab and do not target third‑party systems.
* **Hardware attacks risks:** physical fault injection can damage devices; ensure supervision and sacrificial hardware.
* **Legal compliance:** follow institutional policies and responsible disclosure pathway for any vendor vulnerabilities discovered.

---

## 15. Mitigations & Best Practices (summary recommendations)

* **Prefer RSA‑PSS for signatures** (provable security) and avoid PKCS#1 v1.5 where possible.
* **Use large key sizes** (≥3072 bits) or migrate to ECC/PQC for long‑term security.
* **Disable RSA key exchange in TLS; prefer ECDHE** for forward secrecy.
* **Implement exponent & CRT blinding, constant‑time modular exponentiation, and secure RNG for keygen.**
* **Store private keys in HSMs/TPM with strict ACLs and avoid raw key material on servers.**
* **Careful error handling:** uniform error messages and constant‑time responses to prevent padding oracles.

---

## 16. Extensions & Future Work

* Survey of library ecosystem to detect prevalence of vulnerable configs (large‑scale scan on open source repos).
* Explore hybrid attacks combining side‑channel leaks with mathematical weaknesses.
* Plan migration strategy to ECC/PQC for long‑term signed artifacts (code signing, certificates, tokens).

---

## 17. Tools & Resources gợi ý

* OpenSSL, RsaCtfTool, MPrime/pari/gmp, SoftHSM, ChipWhisperer (optional), Docker, Python (pycryptodome), timing measurement harnesses, scripts for Bleichenbacher PoC.

---

## 18. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ docker/             # containers for vulnerable OpenSSL versions, SoftHSM, lab server
  ├─ poc/                # PoC scripts for Bleichenbacher, timing, Wiener, fault sim
  ├─ tools/              # wrappers (RsaCtfTool configs), measurement harness
  ├─ docs/               # report, slides, runbook, responsible disclosure template
  └─ logs/               # experiment outputs (kept non-sensitive)
```

---