# Capstone Project — Cryptanalysis on Lattice‑Based Algorithms (FIPS 203/204/205: Kyber, Dilithium, SPHINCS+)

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Cryptanalysis on Lattice‑Based Algorithms — Tập trung vào các thuật toán đã được chọn (FIPS 203/204/205: ML‑KEM (Kyber), ML‑DSA (Dilithium), SLH‑DSA (SPHINCS+)) và phân tích điểm yếu triển khai thực tế

---

## 1. Tóm tắt đề tài (Project Synopsis)

Mục tiêu: nghiên cứu sâu về **các vectơ tấn công thực thi** (implementation attacks) trên các thuật toán lattice‑based vừa được chuẩn hóa (Kyber, Dilithium, SPHINCS+), tập trung vào: side‑channel attacks (power, EM, cache, timing), fault‑injection, decryption‑failure exploitation (DFR), microarchitectural attacks (Rowhammer, speculative/MDS), sampling/entropy issues, và các lỗi giao thức/xử lý lỗi trong FO transforms. Sinh viên sẽ thực hiện PoC trong lab (trong môi trường cô lập), đo lường tác động trong kịch bản triển khai (HSM/TPM, cloud multi‑tenant, IoT), và đề xuất mitigations kỹ thuật và vận hành.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu chi tiết cấu trúc và các bước chính của Kyber (KEM), Dilithium (signature) và SPHINCS+ (hash‑based signature), bao gồm NTT/IDNTT, decoding/recoding, rejection sampling, và FO transforms.
2. Nắm các tấn công hiện đại: single‑trace and profiled SCA, masked implementation breaks, DFR exploitation, fault attacks, rowhammer‑style fault induction, and NN‑assisted template attacks.
3. Triển khai PoC an toàn: side‑channel capture (simulated or hardware), fault injection simulations, decryption‑failure oracle emulation.
4. Đánh giá rủi ro triển khai trong các môi trường thực tế (cloud co‑tenancy, HSM, embedded devices) và đề xuất chính sách/hardening.

---

## 3. Relevance & Motivation

* NIST đã công bố chuẩn FIPS 203/204/205 dựa trên Kyber, Dilithium, và SPHINCS+ — việc hiểu rủi ro triển khai (implementation) là then chốt vì các tấn công thực tế thường khai thác các lỗi hiện thực hơn là lỗ hổng toán học cơ bản.

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Những tấn công implementation nào (SCA, FI, DFR exploitation, microarchitectural) hiệu quả nhất chống lại Kyber/Dilithium/SPHINCS+ trên hardware/software điển hình?

**RQ2:** Ở môi trường cloud đa‑tenant, attacker có thể thực hiện SCA/Rowhammer‑assisted attacks để làm suy yếu KEM/signature trong thời gian hợp lý không?

**RQ3:** Biện pháp phòng thủ (masking, constant‑time, explicit reject FO, attestation/HSM, memory isolation) có thể giảm rủi ro xuống mức chấp nhận được với overhead thế nào?

**Giả thuyết:** Với cài đặt kém bảo hộ hoặc thiếu mitigations, các tấn công SCA và fault có thể thu về bí mật (thông điệp chia sẻ/khóa) trong thực nghiệm; mitigations tiêu chuẩn (masking, blinding, explicit reject, attestation) làm tăng khó khăn nhưng cần đánh đổi về hiệu năng và phức tạp.

---

## 5. Background (Tổng quan ngắn)

* **ML‑KEM (Kyber):** module‑LWE based KEM with NTT speedups and FO transform; decapsulation includes message decoding and error‑correction decoding steps that have been targeted by SCA.
* **ML‑DSA (Dilithium):** module‑lattice signature using rejection sampling; signing uses secret polynomials and rejection loops — sources of side‑channel leakage and rejected‑signature‑based attacks.
* **SLH‑DSA (SPHINCS+):** stateless hash‑based signatures (tree of few‑time signatures + hypertree); robust mathematically but implementation must handle randomness, tree indexing, and fault protections.

---

## 6. Literature review & important references (gợi ý)

* NIST announcement & FIPS pages for the algorithms (FIPS 203/204/205) — background & standard text.
* CHES / CCS / IACR papers on side‑channel and fault attacks against Kyber, Dilithium, SPHINCS+ (several practical SCA and fault POCTs published).
* Research on DFR and decryption‑failure exploitation frameworks.

> Yêu cầu trích dẫn: sinh viên cần thu thập ít nhất 8 nguồn học thuật / kỹ thuật (papers from CHES, CCS, IACR) và 3 repos/implementations (PQClean, liboqs, reference implementations for Kyber/Dilithium/SPHINCS+).

---

## 7. Deep deployment weakness analysis (Practical weaknesses by scenario)

### 7.1. Hardware & Embedded Devices

* **Power/EM SCA:** single‑trace or profiled attacks can target message decoding / NTT stages (Kyber) or secret polynomial unpacking (Dilithium), allowing key or shared secret recovery on unprotected devices.
* **Masked implementations bypassable:** first‑order masking sometimes broken by higher‑order leakage or implementation errors — attacks demonstrated on masked Kyber hardware.

### 7.2. Cloud multi‑tenant & microarchitectural attacks

* **Cache/leakage & co‑resident attacks:** secret‑dependent memory access (e.g., table lookups) can leak via cache attacks (Prime+Probe/Flush+Reload) if implementation not constant‑time.
* **Rowhammer & fault induction:** inducing bit flips in DRAM has been used to force decryption failures or corrupt internal state, amplifying failure‑based attacks.

### 7.3. Decryption Failure (DFR) & FO‑transform handling

* **DFR exploitation:** non‑zero decryption failure rates can be amplified by an attacker submitting many ciphertexts and observing side‑effects/timing/errors; implementations must use explicit‑reject FO variants or constant processing to avoid giving oracles.
* **Error handling leaks:** distinguishable error messages or timing differences during decapsulation enable practical attacks.

### 7.4. Fault Injection & SPHINCS+ concerns

* **Faults on tree traversal or few‑time signature components:** SPHINCS+ has been shown to be vulnerable to fault attacks that can enable forgery under certain fault models, requiring hardware countermeasures.

### 7.5. RNG & sampling issues

* **Bad entropy / sampling biases:** lattice schemes rely on careful discrete sampling; biased or low‑entropy RNGs (especially on IoT) weaken security and can make lattice attacks easier.

---

## 8. Methodology (Suggested experiments & PoC)

### 8.1. Overall experimental plan

1. **Select targets:** Kyber‑512 / Kyber‑768, Dilithium2/3, SPHINCS+ parameter sets commonly used.
2. **Set up lab:** isolated HW testbed (microcontroller / FPGA if available) and virtualized co‑resident VMs for cache/rowhammer tests; use PQClean/liboqs reference code.
3. **Implement PoC vectors:**

   * SCA PoC (power/EM) targeting NTT/message decoding or secret unpacking.
   * DFR oracle emulation (server that leaks timing/errors) to attempt failure‑based exploitation.
   * Rowhammer induced flips during decapsulation to observe failure amplification.
   * Fault injection on SPHINCS+ signing flow (software simulation or hardware glitcher).
4. **Measure:** #traces/queries needed, success probability, time to recover, and required compute.
5. **Mitigate & retest:** apply masking, explicit‑reject FO, constant‑time changes, attestation/HSM, and re‑measure overhead and residual risk.

### 8.2. Example experiments

* **Experiment A — Masked Kyber hardware break:** reproduce published masked Kyber attack (message decoding leakage) in lab (simulated or hardware) to demonstrate shared key recovery.
* **Experiment B — DFR oracle + failure boosting:** deploy decaps server with timing differences and attempt to exploit decryption failures to leak key material or force key recovery.
* **Experiment C — Rowhammer on co‑tenant VM:** run rowhammer on adjacent VM while target performs decapsulation; observe induced failures.
* **Experiment D — Single‑trace Dilithium SCA:** capture power traces during secret polynomial unpacking and evaluate key recovery via profiling/NN‑assisted methods.

---

## 9. Implementation & Tools

* **Reference code:** PQClean, liboqs, reference Kyber/Dilithium/SPHINCS+ implementations.
* **SCA tools:** ChipWhisperer, oscilloscope & probes, EM probes, SCA processing toolchain (numpy/scipy, scikit‑learn, tensorflow for NN profiling).
* **Fault/Rowhammer tools:** research rowhammer tooling, rowhammer‑based PoCs in controlled environment; software fault injection harness.
* **Lattice analysis tools:** fplll/fpylll for lattice work (if needed for DFR exploitation analysis).

---

## 10. Evaluation Plan & Metrics

* **Success criteria:** recovered shared key / private key coefficients / ability to forge signatures / induced forgery in SPHINCS+.
* **Effort metrics:** traces needed (#), queries to oracle, runtime, compute resources.
* **Mitigation metrics:** reduction in success rate and increase in resources required after applying countermeasures (masking order, explicit reject, attestation).
* **Operational cost:** performance overhead (latency, CPU), memory, and deployment complexity.

---

## 11. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Survey literature (CHES/CCS/IACR papers), choose parameter sets, prepare environment and reference builds.
* **Tuần 3–4:** Implement DFR oracle emulation and baseline decapsulation timing/behavior measurements.
* **Tuần 5–6:** Implement SCA capture harness and attempt masked Kyber attack reproduction (simulated or hardware).
* **Tuần 7–8:** Rowhammer co‑tenant experiment and analyze induced failures.
* **Tuần 9–10:** Dilithium side‑channel profiling and SPHINCS+ fault simulation/PoC.
* **Tuần 11:** Implement mitigations (explicit‑reject FO, masking, constant‑time) and re‑test.
* **Tuần 12:** Finalize report, reproducible scripts, plots, and demo video.

---

## 12. Deliverables

1. **Mid‑term report:** literature review, lab plan, initial measurements.
2. **Final report (PDF/MD):** PoC results, analysis, mitigations, and deployment guidance.
3. **Code repo:** PoC scripts, Dockerfiles, SCA processing notebooks, fplll configs, and reproducible harness descriptions.
4. **Artifacts:** captured traces (non‑sensitive/processed), timing logs, rowhammer logs, plots, and demo video.

---

## 13. Assessment & Rubric (gợi ý)

* Research depth & correctness: 25%
* PoC reproducibility & ethics: 30%
* Deployment weakness analysis & mitigation proposals: 25%
* Report & presentation quality: 20%

---

## 14. Risks, Limitations & Ethics

* **Dual‑use concerns:** SCA/fault PoC may be misused; conduct all experiments in isolated lab under supervision.
* **Hardware variability:** Some attacks depend on specific hardware—document hardware and firmware used.
* **Rowhammer & fault tests:** may destabilize host systems—use sacrificial machines.

---

## 15. Mitigations & Best Practices (summary)

* **Use explicit‑reject FO transforms** and constant‑time, constant‑flow decapsulation routines to avoid oracles.
* **High‑quality masking & higher‑order protections** for implementations on hardware; verify masking via leakage assessment (NICV/TVLA).
* **Memory isolation & anti‑rowhammer practices** when deploying in multi‑tenant clouds (pagemap control, pining, firmware patches).
* **RNG & sampling correctness:** audited RNG, hardware entropy sources, and correct sampling algorithms.
* **Attestation & HSMs:** where possible, run decapsulation/signature ops in attested environments or HSMs and validate masked implementations.

---

## 16. Extensions & Future Work

* Build an automated DFR estimator & test harness for new lattice proposals.
* Formal verification of decapsulation code paths to ensure constant‑time and eliminate secret‑dependent branches.
* Comparative study of mitigation overhead across cloud providers and edge devices.

---

## 17. Tools & Resources gợi ý

* PQClean / liboqs, ChipWhisperer, oscilloscope + EM probes, rowhammer research tools, fplll/fpylll, TensorFlow/PyTorch for profiling.

---

## 18. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ docker/             # decapsulation server + attacker containers
  ├─ experiments/
  |   ├─ masked_kyber_sca/
  |   ├─ dfr_oracle/
  |   ├─ rowhammer_frodo_style/
  |   └─ dilithium_sca/
  ├─ tools/              # SCA preprocess, fplll configs
  ├─ docs/               # report, slides, ethics note
  └─ logs/               # processed traces, timing logs (non-sensitive)
```

---
