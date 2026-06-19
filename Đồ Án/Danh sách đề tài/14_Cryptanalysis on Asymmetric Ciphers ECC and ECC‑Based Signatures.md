# Capstone Project — Cryptanalysis on Asymmetric Ciphers: ECC & ECC‑Based Signatures

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Cryptanalysis on Asymmetric Ciphers — Phân tích và thực nghiệm Elliptic Curve Cryptography (ECC) và các phiên bản chữ ký số dựa trên ECC (ECDSA, EdDSA và variants)

---

## 1. Tóm tắt đề tài (Project Synopsis)

Đề tài nghiên cứu các **yếu điểm lý thuyết và triển khai thực tế** của ECC và các chữ ký dựa trên ECC (ECDSA, Ed25519/Ed448, deterministic ECDSA variants). Mục tiêu là khảo sát vectơ tấn công quan trọng (nonce reuse trong ECDSA, invalid‑curve attacks, small‑subgroup, side‑channel/timing, fault attacks, weak curves/backdoors, poor RNG), thực hiện PoC an toàn cho một số vectơ trong môi trường kiểm soát (e.g., nonce reuse recovery, timing leakage, invalid‑curve oracle), đánh giá rủi ro trong kịch bản triển khai (TLS, SSH, JWT, blockchain/smart contracts, IoT), và đề xuất biện pháp giảm thiểu, quy trình vận hành và migration (curve selection, deterministic signatures, libs, HSM/TAP protection).

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Nắm vững toán học nền tảng của ECC: nhóm điểm, scalar multiplication, curve parameters, cofactor, subgroup order.
2. Hiểu đặc điểm các scheme chữ ký (ECDSA, EdDSA), including deterministic ECDSA (RFC 6979), and trade‑offs.
3. Khảo sát tấn công: nonce reuse/partial nonce leakage, invalid‑curve & small‑subgroup attacks, side‑channel (timing, cache, power), fault attacks and curve parameter backdoor concerns.
4. Triển khai PoC trong lab: recover private key from nonce reuse, exploit invalid‑curve oracle in naive ECDH/ECDSA verification, timing attack demos, and evaluate mitigations.
5. Đề xuất best practices for deployment: curve choices (NIST P‑curves vs Curve25519/Ed25519), deterministic signatures, scalar blinding, cofactor checks, use of libs like libsodium, strict validation, HSM usage.

---

## 3. Tính cấp thiết & động lực (Relevance)

* ECC được sử dụng rộng rãi trong TLS (ECDHE/ECDSA), SSH (ecdsa keys), JWT (ES256, EdDSA), blockchain (secp256k1 in Bitcoin/Ethereum), IoT devices. Một số triển khai lỗi dẫn tới mất chìa khóa/forgery rất nhanh.
* Các vụ tấn công thực tế thường không phá toán học ECC mà khai thác **nonce misuse**, **bad validation**, **weak RNG**, hoặc **side‑channel** — do đó nghiên cứu thực nghiệm rất có giá trị cho practitioner.

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Trong các kịch bản thực tế (TLS, SSH, blockchain, JWT), đâu là các điểm yếu triển khai phổ biến nhất liên quan ECC và chúng dẫn tới hậu quả gì (key recovery, transaction forging, session compromise)?

**RQ2:** Các countermeasures (deterministic signatures, nonce blinding, scalar multiplication blinding, strict point validation, use of safe curves like Curve25519/Ed25519) có hiệu quả thực tế và chi phí vận hành ra sao?

**Giả thuyết:** Nhiều compromise thực tế do: nonce reuse/biased nonce in ECDSA, thiếu point validation (invalid‑curve attacks), and side‑channel leaks. Sử dụng deterministic signatures (RFC‑6979) hoặc EdDSA, strict public‑key / point validation, and constant‑time libs dramatically reduce practical risk.

---

## 5. Background (Tổng quan ngắn)

* **ECC basics:** group of points on elliptic curve over finite field (prime or binary), scalar multiplication k·P. Security based on Elliptic Curve Discrete Logarithm Problem (ECDLP).
* **ECDSA:** signature (r,s) where r = (k·G).x mod n, s = k^{-1}(H(m) + d·r) mod n; nonce k must be unique & secret.
* **EdDSA (Ed25519/Ed448):** deterministic signature with different construction (twisted Edwards), avoids nonce randomness issues.
* **Curve choices:** NIST P‑curves (P‑256, P‑384), secp256k1 (Bitcoin), Curve25519/Ed25519 (modern recommended).

---

## 6. Literature review (hướng khảo sát)

* Papers on nonce reuse and lattice attacks (Bleichenbacher, Howgrave‑Graham & Smart?), paper on Collard et al. for partial nonce leakage, Boneh & Venkatesan on side‑channel, Bernstein on cache timing, invalid‑curve attack papers (Antipa et al.), and fault attacks on ECC.
* Practical incident reports: Bitcoin/Ethereum key reuse/private key theft due to RNG bugs, OpenSSL/LibreSSL vulnerabilities, CVEs on ECDSA implementations.

> Yêu cầu: sinh viên trích dẫn ≥6 papers/reports và ≥3 codebases/tools (libsecp256k1, libsodium, OpenSSL ECC modules, python ec libs for PoC).

---

## 7. Phân tích weaknesses trong kịch bản triển khai thực tế (Deep Deployment Weakness Analysis)

### 7.1. ECDSA nonce reuse & biased nonces

* **Nonce reuse:** If k reused for two messages m1,m2 with same private key d, attacker recovers d via simple algebra: s1 = k^{-1}(H1 + d·r) → subtract yields d. This has caused real Bitcoin key compromises when RNG fails.
* **Partial/nonuniform nonce leakage:** leaking some bits of k (side‑channel or bad RNG) can be exploited by lattice methods (Bleichenbacher-like, Howgrave‑Graham & Smart) to recover d.
* **Deterministic ECDSA / EdDSA:** recommended to remove dependency on RNG for k.

### 7.2. Invalid‑curve & small‑subgroup attacks

* **Invalid‑curve attack (Naive ECDH/ECDSA verify):** if implementation does not validate that peer point lies on expected curve and in prime‑order subgroup, attacker can choose point in small subgroup to extract information about private key (leading to discrete log reductions).
* **Cofactor issues:** curves with cofactor >1 (e.g., Curve25519 has cofactor 8) require careful cofactor handling; failing to multiply by cofactor or validate subgroup can create vulnerabilities.

### 7.3. Curve parameter/backdoor concerns

* **Choice of curve and parameters:** NIST curves (P‑curves) have been subject to scrutiny about generation of parameters; some prefer Curve25519/Ed25519 for transparent generation.
* **Weak or intentionally tampered parameters:** theoretical risk if curve generation process not trusted; real-world mitigation is to prefer well‑audited curves with transparent seeds.

### 7.4. Side‑channel (timing, cache, power) & implementation leaks

* **Scalar multiplication leaks:** windowed/variable time scalar mult implementations leak bits via timing/cache (Flush+Reload, Prime+Probe) — applicable in shared hosts/cloud and physical devices.
* **Microcontroller/IoT devices:** lacking constant‑time libs and protections; physical attacks (power/EM) can extract key with few traces.
* **Branching & conditional reductions:** create timing variability.

### 7.5. Fault attacks

* **Single‑bit fault during scalar mult or point addition** can leak private scalar via differential fault analysis (DFA) adapted for ECC or technique like SafeError attacks on signature generation.
* **CRT does not apply for ECC** but implementations may use projective coordinates; faults in coordinate operations can be exploited.

### 7.6. Blockchain & smart contract contexts

* **Nonce reuse in transaction signatures (Bitcoin/Ethereum):** caused major losses when RNG faulty.
* **Signature malleability:** some signature schemes/parameters allow malleability; blockchain protocols must canonicalize signatures.
* **Compactness pressure leads to reuse of nonrandomness:** devices optimizing size may use deterministic or truncated nonces incorrectly.

### 7.7. TLS/SSH/JWT contexts

* **ECDSA certificates & signatures in TLS/SSH:** poor key generation or reuse leads to session compromise.
* **JWT with ES256:** libraries must strictly verify 'alg' and handle key rotation; misuse can lead to token forgery.
* **Curve negotiation issues:** if server accepts multiple curves, clients may be coerced into using weaker curves.

---

## 8. Methodology (Pipeline & Experiments)

### 8.1. Selected experiments (suggested)

* **Experiment A — Nonce reuse PoC (ECDSA):** simulate RNG failure on client (reuse k across transactions), generate multiple signatures, recover private key; measure number of signatures required and demonstrate impact in blockchain context.
* **Experiment B — Partial nonce leakage via timing:** simulate small‑bit leak of nonce (e.g., top bits), apply lattice techniques (Coppersmith/Howgrave‑Graham) to recover d; use existing libraries for lattice solves (fplll, sage if allowed).
* **Experiment C — Invalid‑curve oracle on naive ECDH/ECDSA:** implement naive point acceptance on server, craft malicious points to recover secret via small subgroup attack; then patch point validation and retest.
* **Experiment D — Side‑channel timing/cache PoC:** run vulnerable scalar mult (table lookups) on co‑located process and perform Prime+Probe or timing measurement to recover bits; if hardware not available, simulate variable time leaks and perform statistical attack.
* **Experiment E — Fault simulation on signature generation:** emulate computation faults and perform DFA extraction in software model; if hardware glitcher available, perform on controlled device.

### 8.2. Lab setup & safety

* Use isolated lab and testnets for blockchain experiments; simulate wallets and signing devices. Use containers for vulnerable libs (older OpenSSL) and emulate RNG faults. For physical SCA/DFA, use sacrificial IoT devices and ChipWhisperer if available. Follow ethical rules.

### 8.3. Data collection & metrics

* **Success metrics:** private key recovered? transaction forged? token accepted?
* **Effort metrics:** number of signatures/messages/traces, compute time (CPU/GPU), lattice solve time, number of oracle queries.
* **Mitigation effectiveness:** re-run after applying mitigations (deterministic nonces, strict validation, constant‑time libs) to measure residual risk.

---

## 9. Implementation & Tools

* **Libraries & tools:** OpenSSL, libsodium (Ed25519), libsecp256k1, python-ecdsa, fplll (lattice), SageMath (if available), fpylll, Ristretto tooling, ChipWhisperer for SCA, oscilloscope/probes for power.
* **Blockchain tools:** local Bitcoin/Ethereum testnets, libraries to craft transactions (web3.py, bitcoinlib).
* **Environment:** Docker containers for vulnerable stacks, VMs for co‑location tests, hardware testbed for IoT devices if available.

---

## 10. Evaluation Plan & Metrics

* **Exploit metrics:** key recovered? forged tx accepted? signature verification bypassed?
* **Quantitative effort:** # signatures/traces, time to recover, lattice solve resource usage.
* **Detection & mitigation:** measure how quickly mitigation prevents exploitation (e.g., deterministic nonce prevents recovery).
* **Operational impact:** measure ease of fixing (patch libs, rotate keys), cost of key rotation on systems like blockchain.

---

## 11. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Literature review, choose curves and lib targets, set up lab environment (Docker, testnets).
* **Tuần 3–4:** Implement Experiment A (nonce reuse) and demonstrate private key recovery in testnet scenario.
* **Tuần 5–6:** Implement Experiment B (partial nonce leakage + lattice) and run experiments; document lattice parameters and solver results.
* **Tuần 7–8:** Implement Experiment C (invalid‑curve oracle) and patch with validation; measure difference.
* **Tuần 9–10:** Side‑channel Experiment D (timing/cache) — PoC via simulation or real host; if hardware available use ChipWhisperer.
* **Tuần 11:** Run mitigation tests, aggregate results and ablation studies.
* **Tuần 12:** Final report, reproducible repo (Docker + scripts), demo video & presentation.

---

## 12. Deliverables

1. **Mid‑term report:** problem statement, chosen attacks, lab setup, initial results.
2. **Final report:** full methodology, experimental results, mitigation recommendations.
3. **Code repo & PoC:** scripts for nonce reuse, lattice solves, invalid‑curve PoC, Docker images, testnet transactions (only on local/regtest).
4. **Responsible disclosure plan** for any library vulnerabilities discovered.
5. **Demo video** showing at least one PoC and the patched mitigation.

---

## 13. Assessment & Rubric (gợi ý)

* Research grounding & relevance: 20%
* PoC correctness & reproducibility: 30%
* Deployment weakness analysis & mitigation depth: 25%
* Documentation & code quality: 15%
* Presentation & clarity: 10%

---

## 14. Risks, Limitations & Ethical Considerations

* **Dual‑use:** PoC can be misused; run only in lab and do not deploy against third parties.
* **Hardware limits:** SCA/fault experiments may need equipment — simulate when not available and clearly label simulations.
* **Blockchain implications:** use regtest/local testnets; do not broadcast exploits to public networks.
* **Responsible disclosure:** follow policy if discovering vulnerabilities in widely used libraries.

---

## 15. Mitigations & Best Practices (summary recommendations)

* **Use deterministic signatures** (RFC 6979) or EdDSA (Ed25519) where appropriate to avoid RNG dependence.
* **Strict public key / point validation**: reject points not on curve or not in correct subgroup; multiply by cofactor or check subgroup membership.
* **Use safe curves and libraries:** prefer Curve25519/Ed25519, libsecp256k1 for Bitcoin with audited code.
* **Constant‑time implementations & scalar blinding:** use vetted libs and hardware acceleration (e.g., curve operations that are constant‑time).
* **Protect RNG & key storage:** use hardware RNG, KMS/HSM, and rotate keys when compromise suspected.
* **Canonicalization & signature checks** in blockchain contexts to avoid malleability.

---

## 16. Extensions & Future Work

* Large‑scale scan of open repositories to detect nonce misuse patterns or bad crypto usage.
* Combine SCA with nonce leakage to speed up key recovery.
* Formal verification of ECC libs for constant‑time and correct validation.

---

## 17. Tools & Resources gợi ý

* OpenSSL, libsodium, libsecp256k1, python-ecdsa, fplll/fpylll, SageMath, ChipWhisperer, web3.py/bitcoinlib for testnet.

---

## 18. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ docker/             # containers for vulnerable stacks, testnet nodes
  ├─ poc/                # nonce_reuse, lattice_solve, invalid_curve PoCs
  ├─ tools/              # lattice solver configs, helper scripts
  ├─ docs/               # report, slides, runbook, responsible disclosure template
  └─ logs/               # experiment outputs (non-sensitive)
```

---
