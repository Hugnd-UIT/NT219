# Capstone Project — Cryptanalysis on Lattice‑Based Algorithms (Focus: Round‑3 Rejected/Non‑Selected Candidates)

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Cryptanalysis on Lattice‑Based Algorithms — Phân tích các thuật toán lattice (đặc biệt các thuật toán không được chọn ở Vòng 3 của PQC) và điểm yếu trong kịch bản triển khai thực tế

---

## 1. Tóm tắt đề tài (Project Synopsis)

Mục tiêu của đề tài là nghiên cứu sâu các **tấn công thực nghiệm** và **yếu điểm triển khai thực tế** trên họ thuật toán dựa trên lattice (LWE/MLWE/NTRU‑like), với trọng tâm vào những thuật toán **đã không được NIST chọn trong vòng 3** (ví dụ: FrodoKEM, NTRU, NTRU‑Prime, Saber — tùy theo bối cảnh) để hiểu lý do vì sao một số thiết kế bị loại, những lỗ hổng thực thi phổ biến (decryption failures, side‑channels, rowhammer/bit‑flip attacks, parameter selection errors), và để tạo bộ khuyến nghị cho triển khai an toàn. Sinh viên sẽ cung cấp PoC an toàn, mô phỏng tấn công thực tế, đo lường mức rủi ro, và đề xuất mitigations.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu sâu các xây dựng lattice phổ biến (LWE, Ring‑LWE, Module‑LWE, NTRU variants) và biến đổi bảo mật (Fujisaki‑Okamoto / FO, KEM transforms).
2. Nắm các tấn công thực tế: decryption‑failure exploitation, side‑channel (power/timing/cache/EM), microarchitectural attacks (Rowhammer, bit‑flips), message‑recovery/lattice attacks, and implementation mistakes.
3. Triển khai PoC tấn công an toàn trong lab: failure‑oracle, DFR amplification, rowhammer on shared hosts, single‑trace SCA on NTRU implementations.
4. Phân tích trade‑offs tham số (DFR vs efficiency), và đề xuất cấu hình/controls để giảm rủi ro (DFR thresholds, constant‑time, masking, memory hard implementations).
5. Soạn tài liệu hướng dẫn deploy & harden (KEM selection, rejection sampling, failure handling, attestation & isolation).

---

## 3. Relevance & Motivation

* Thuật toán lattice là nền tảng cho PQC hiện đại; song nhiều thiết kế trong quá trình tiêu chuẩn hoá cho thấy rủi ro không chỉ do toán học mà do **triển khai và giao thức** (ví dụ cách xử lý lỗi giải mã).
* Hiểu cách tấn công thực tế giúp: (1) chọn tham số an toàn, (2) viết guidance để triển khai thư viện/stack, (3) xác định giới hạn deploy cho môi trường bị chia sẻ (cloud, VM, container).

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Những loại tấn công triển khai (decryption failure exploitation, Rowhammer, SCA) nào là hiệu quả nhất trên các thuật toán lattice đã bị loại ở vòng 3, và ở điều kiện triển khai nào?

**RQ2:** Với mức Decryption Failure Rate (DFR) thực tế, các KEM/LWE‑based schemes có thể bị buộc lỗi (failure‑boosting) để rút thông tin khóa hay không?

**RQ3:** Những biện pháp phòng thủ (noise/DFR hardening, constant‑time implementations, detaching secret‑dependent branches) có thể giảm rủi ro đến mức chấp nhận được cho environments like cloud multi‑tenant không?

**Giả thuyết:** Nhiều tấn công thực tế tận dụng tính không hoàn hảo trong xử lý lỗi (DFR), side‑channel leakage từ cài đặt, hoặc microarchitectural faults — mitigations có thể làm giảm rủi ro nhưng thường đi kèm chi phí hiệu năng/complexity.

---

## 5. Background (Tổng quan ngắn)

* **LWE / Ring‑LWE / Module‑LWE:** bài toán học tập với lỗi (LWE) và các biến thể có cấu trúc để tăng hiệu năng (Ring/Module).
* **NTRU family:** thiết kế dựa trên đa thức vòng và các phép toán vòng, khác về sampling & parameter choices từ LWE‑based schemes.
* **KEM patterns:** encapsulate/decapsulate, thường dùng FO transform (KYBER uses variants) để đạt IND‑CCA với một số xử lý để tránh decryption failures.
* **DFR (Decryption Failure Rate):** xác suất hệ thống trả về lỗi giải mã cho ciphertext hợp lệ — phải được giữ rất thấp; song trong thực thi nó có thể không phải zero, và kẻ tấn công có thể lợi dụng.

---

## 6. Literature review & notable attacks (gợi ý khảo sát)

* Decryption failure attacks (D’Anvers et al., 2019) — framework cho attacks exploiting non‑zero DFR on lattice schemes.
* Rowhammer / bit‑flip attacks leading to key recovery or failure‑amplification in FrodoKEM (Frodoflips paper, CCS 2022).
* Side‑channel analyses on NTRU and other lattice schemes (single‑trace SCA on NTRU implementations; template attacks).
* Papers & reports on failure handling and FO transforms (e.g., Hövelmanns et al., 2022).

---

## 7. Deep deployment weakness analysis (Practical weakness by scenario)

### 7.1. Shared Cloud / Multi‑tenant Hosts

* **Rowhammer & bit‑flip exploitation:** shared hardware can allow an attacker to induce faults in adjacent DRAM rows to flip bits in victim memory (e.g., key material or ephemeral buffers used by KEMs). FrodoKEM PoC exploited such flips to create decryption failures and escalate to key recovery.
* **Microarchitectural side‑channels (Cache, MDS, speculative execution):** implementations using secret‑dependent memory access (e.g., look‑up tables) leak across co‑located tenants; even single‑trace attacks on optimized NTRU implementations have been demonstrated.

### 7.2. Networked Protocols & KEM usage in TLS/API

* **Decryption‑failure oracles:** if a server returns distinguishable errors (or timing differences) on decapsulation failure vs success, attacker can mount chosen‑ciphertext style attacks to learn about secret keys or force failure patterns.
* **Failure boosting:** adversary crafts ciphertexts to increase DFR, amplifying success of key‑recovery attacks; FO transform variants and explicit reject vs implicit reject strategies affect resilience.

### 7.3. IoT / Embedded Devices

* **Single‑trace SCA & power analysis:** constrained devices often lack side‑channel protections; NTRU and other implementations can leak with few traces.
* **Poor entropy for sampling:** lattice schemes rely on discrete Gaussian or bounded distributions; weak RNG leads to biased sampling which can weaken security assumptions and open lattice attacks.

### 7.4. Implementation errors & parameter choices

* **Parameter misestimation:** choosing parameters that give higher-than-expected DFR or lower security margins invites attacks and may have been a factor for some round‑3 eliminations.
* **Insecure sampling / rejection sampling errors:** flawed implementations of discrete Gaussians or centered bins introduce biases exploitable by lattice attacks.

---

## 8. Methodology (Experiments & PoC plan)

### 8.1. Overall plan

1. **Select target algorithms:** pick 2–3 lattice schemes that were not standardized in Round‑3 (e.g., FrodoKEM, NTRU/NTRU‑Prime, Saber) as representative study objects.
2. **Set up lab:** isolated VMs and a vulnerable host (shared memory) to test rowhammer and co‑location SCA; IoT board for embedded experiments.
3. **Implement PoC attacks:** (A) decryption failure oracle and DFR amplification; (B) Rowhammer‑assisted failure induction on FrodoKEM-like implementation; (C) single‑trace SCA on NTRU implementation; (D) RNG bias / sampling abuse experiments.
4. **Measure & analyze:** resources needed, DFR thresholds, success probability, number of queries/traces, false positives.
5. **Mitigations:** implement and re‑test mitigations: explicit‑reject FO variants, constant‑time & masked implementations, hardening vs Rowhammer (memory isolation), and RNG improvements.

### 8.2. Specific experiments

* **Experiment 1 — DFR oracle:** deploy decapsulation server that exposes distinguishable error/timing behavior; run failure‑boosting campaign and attempt key recovery using published frameworks.
* **Experiment 2 — Rowhammer + FrodoProof:** on co‑located VM, perform targeted rowhammer to flip bits in victim memory during decapsulation; measure whether induced failures help in key extraction as in Frodoflips.
* **Experiment 3 — Single‑trace SCA on NTRU:** collect single power/EM trace on embedded board running NTRU decapsulation; attempt profiling/template attack to recover secret.
* **Experiment 4 — Sampling bias:** simulate weak RNG (truncated, low entropy) and demonstrate lattice attack advantage (recover secret with fewer samples or via lattice reductions).

---

## 9. Implementation details & tooling

* **Reference implementations:** use available reference code for FrodoKEM, NTRU/NTRU‑Prime, Saber (PQClean, liboqs where available).
* **Tools:** Rowhammer tooling (research-grade), side‑channel kit (ChipWhisperer) or EM probes for physical traces, lattice tools (fplll / fpylll), implementations of failure‑attack frameworks (from D’Anvers et al. / leaky‑LWE estimator).
* **Environment:** Docker for server/client decapsulation; dedicated hardware for rowhammer & SCA experiments; isolated network.

---

## 10. Evaluation Plan & Metrics

* **Success metrics:** secret key recovered? ciphertext/message recovered? decryption oracle exploited?
* **Effort metrics:** number of queries to oracle, time to recovery, number of traces, compute resources for lattice reductions.
* **Resilience metrics:** DFR threshold below which attacks become impractical; effectiveness of mitigations (reduction in success rate, overhead cost).
* **Operational metrics:** performance overhead of mitigations (latency, CPU), compatibility with TLS stacks.

---

## 11. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Survey, choose target lattice candidates (FrodoKEM, NTRU, Saber), prepare environment and collect reference builds.
* **Tuần 3–4:** Implement DFR oracle PoC and run baseline tests to measure natural DFR; instrument decaps server for timing.
* **Tuần 5–6:** Implement failure‑boosting attacks and attempt key recovery; document thresholds.
* **Tuần 7–8:** Implement Rowhammer experiment against FrodoKEM on co‑located VM; collect data and analyze.
* **Tuần 9–10:** Single‑trace SCA experiments on NTRU implementation (or simulation if hardware not present).
* **Tuần 11:** Apply mitigations (explicit reject, constant‑time, masking, memory isolation) and re‑test.
* **Tuần 12:** Aggregate results, write final report, package reproducible scripts, and record demo video.

---

## 12. Deliverables

1. **Mid‑term presentation/report:** chosen targets, lab setup, initial DFR measurements.
2. **Final report (PDF/MD):** methodology, PoC results, analysis, mitigations, recommendations for deployers.
3. **Code repository:** PoC scripts, instrumentation, Dockerfiles, lattice solver configs, raw logs (non‑sensitive).
4. **Artifacts:** plots (DFR vs success), timing traces, Rowhammer logs, scripts to reproduce experiments in isolated labs.
5. **Demo video:** show one DFR exploitation and subsequent mitigation.

---

## 13. Assessment & Rubric (gợi ý)

* Research depth & technical correctness: 25%
* PoC & reproducibility (ethical lab): 30%
* Deployment weakness analysis & mitigation quality: 25%
* Report & presentation: 20%

---

## 14. Risks, Limitations & Ethics

* **Dual‑use & disclosure:** PoC details are dual‑use; run experiments only on lab setups under supervision. Do not target external systems.
* **Hardware risks:** Rowhammer and fault induction experiments can affect host stability; use isolated test machines.
* **Reproducibility limits:** Some attacks depend on hardware specifics; document hardware & firmware.

---

## 15. Mitigations & Best Practices (summary recommendations)

* **Explicit‑reject Fujisaki‑Okamoto transforms** and careful FO handling to avoid implicit oracle leakage.
* **Keep DFR extremely low** by parameter selection and rigorous testing; avoid patches that accidentally raise DFR.
* **Constant‑time and masked implementations** for lattice operations; avoid secret‑dependent memory access patterns.
* **Memory isolation & anti‑rowhammer measures** on multi‑tenant hosts (page pinning, disabling large pages for sensitive processes, hardware/firmware patches).
* **Strong RNG & verified sampling:** use audited RNGs, hardware entropy sources, and validated sampling algorithms.
* **Attestation & enclave patterns** for highly sensitive key operations when available.

---

## 16. Extensions & Future Work

* Study of hybrid attacks combining decryption failures with SCA/leakage to reduce resource cost.
* Tooling: automated DFR estimation & test harness for new lattice proposals.
* Formal verification of failure‑handling code paths in KEM implementations.

---

## 17. Tools & Resources gợi ý

* PQClean/liboqs implementations for reference, D’Anvers et al. paper on decryption failures, Frodoflips CCS 2022, NIST IR 8413 report for Round‑3 context, fplll/fpylll for lattice solves, ChipWhisperer for SCA.

---

## 18. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ docker/             # decapsulation server + attacker client containers
  ├─ experiments/
  |   ├─ dfr_oracle/
  |   ├─ failure_boosting/
  |   ├─ rowhammer_frodo/
  |   └─ sca_ntru/
  ├─ tools/              # scripts (leaky-LWE-estimator, fplll configs)
  ├─ docs/               # report, slides, runbook, ethics note
  └─ logs/               # raw outputs (timing, traces) - non-sensitive
```

---
