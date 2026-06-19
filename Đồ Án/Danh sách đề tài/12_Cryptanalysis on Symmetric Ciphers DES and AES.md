# Capstone Project — Cryptanalysis on Symmetric Ciphers: DES & AES

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Cryptanalysis on Symmetric Ciphers — Thực nghiệm & Phân tích DES và AES trong kịch bản triển khai thực tế

---

## 1. Tóm tắt đề tài (Project Synopsis)

Đề tài tập trung vào **phân tích mật mã học thực nghiệm** trên các cipher đối xứng điển hình: **DES (và 3DES)** và **AES**. Mục tiêu là kiểm chứng các phương pháp tấn công cổ điển và hiện đại (brute‑force, differential/linear cryptanalysis, meet‑in‑the‑middle, padding oracle, nonce/IV misuse, side‑channel, fault injection, cache timing), đánh giá mức độ rủi ro trong **kịch bản triển khai thực tế** (web/TLS, cloud multi‑tenant, disk encryption, IoT/firmware), và đề xuất biện pháp giảm thiểu. Sinh viên sẽ triển khai PoC an toàn trong môi trường lab, thu thập dữ liệu, đo lường thời gian/nguồn lực cần thiết để thành công, và viết báo cáo khoa học với khuyến nghị vận hành.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu các nguyên lý tấn công tiêu chuẩn trên cipher đối xứng: brute‑force, differential/linear cryptanalysis, MITM, slide attacks.
2. Triển khai và đo lường tấn công thực tế: padding oracle trên AES‑CBC, nonce reuse attack trên AES‑GCM, brute‑force DES/3DES với GPU/cluster, side‑channel trên AES thực thi phần cứng.
3. Phân tích yếu điểm bảo mật khi áp dụng AES/DES trong các kịch bản triển khai (TLS, disk, cloud, IoT) — bao gồm sai cấu hình, quản lý khóa, block‑mode misuse.
4. Đề xuất và thử nghiệm các biện pháp khắc phục: AEAD, unique nonces, constant‑time, HSM/KMS, key rotation.
5. Lập báo cáo có reproducible artifacts: mã nguồn PoC, scripts, datasets mô phỏng, và hướng dẫn lab an toàn.

---

## 3. Tính cấp thiết & động lực (Relevance)

* Mặc dù DES bị xem là lỗi thời, **3DES** và các cấu hình legacy vẫn tồn tại trong môi trường thực (thiết bị cũ, cài đặt legacy ở bên thứ ba). Kiến thức về mức độ rủi ro và kỹ thuật khai thác vẫn cần cho đánh giá an ninh.
* **AES** là tiêu chuẩn hiện đại, nhưng tổ hợp yếu (modes, implementations, key management) vẫn gây lỗ hổng. Nhiều vụ khai thác thực tế không phá cipher trực tiếp mà lợi dụng **misconfiguration** hoặc **side‑channel**.
* Hiểu cả lý thuyết và thực nghiệm giúp đưa ra khuyến nghị tiếp cận thực tế cho vận hành và thiết kế hệ thống.

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Trong các kịch bản thực tế (TLS, disk encryption, cloud multi‑tenant, IoT), những lỗ hổng nào (misuse & implementation) dễ bị khai thác nhất và dẫn đến mất bí mật?

**RQ2:** Các tấn công side‑channel (power/timing/cache) có thể thực hiện từ môi trường cloud/multi‑tenant hay không? Với bao nhiêu trace/nguồn lực?

**RQ3:** Việc chuyển sang AEAD (AES‑GCM, AES‑SIV) và thực hiện đúng nonce management liệu có loại bỏ hầu hết các vectơ tấn công thực tế không?

**Giả thuyết:** Hầu hết các compromise trong thực tế xảy ra do **misuse** (IV/nonce reuse, padding oracle, key reuse), hoặc **implementation leaks** (timing, cache), hơn là do đột phá lý thuyết trên AES. Thực hiện AEAD + KMS + constant‑time implementations + short‑living keys sẽ giảm rủi ro đáng kể.

---

## 5. Background (Tổng quan ngắn)

* **DES:** 56‑bit key (effective), block size 64‑bit — dễ bị brute‑force; differential & linear cryptanalysis (bán thành công trên reduced‑round), 3DES (EDE) tăng key length nhưng vẫn có hạn chế block size 64‑bit (birthday collisions → sweet32).
* **AES:** block size 128‑bit, key sizes 128/192/256; theo lý thuyết cho tới nay chưa có attack thực tế phá AES‑full. Tuy nhiên, reduced‑round attacks, related‑key on toy‑variants, và implementation attacks tồn tại.
* **Modes of operation:** ECB (insecure), CBC (requires IV randomness/unique + padding care), CTR (requires unique nonce), GCM (AEAD but catastrophic if nonce reused), SIV/Deterministic AEAD offer different guarantees.

---

## 6. Literature review (hướng khảo sát)

* Kỹ thuật tấn công kinh điển: differential cryptanalysis (Biham & Shamir), linear cryptanalysis, meet‑in‑the‑middle (Menezes et al.).
* DES history: EFF DES cracker; 3DES & sweet32 attack (birthday collision exploitation on 64‑bit block ciphers).
* AES research: biclique attacks (reduced cost but still astronomically expensive), cache‑timing attacks (Bernstein), side‑channel literature (ChipWhisperer experiments), fault attacks (DFA on AES).
* Practical vulnerabilities: Padding Oracle attacks (Vaudenay), Lucky13 timing attacks on TLS CBC, POODLE (SSLv3), TLS GCM misuse cases.

> Sinh viên cần liệt kê ít nhất 6 paper & 3 mã nguồn / công cụ để tham khảo (e.g., OpenSSL, ChipWhisperer, padbuster-like tools, Hashcat for brute force).

---

## 7. Phân tích weaknesses trong kịch bản triển khai thực tế (Deep Deployment Weakness Analysis)

### 7.1. TLS / HTTPS

* **CBC padding oracle & timing:** mis-implementations hoặc trả lỗi khác biệt có thể làm lộ plaintext (Vaudenay, Lucky13). TLS 1.3 mitigates many CBC issues by removing CBC; TLS 1.2 and older can be vulnerable if server reveals padding vs MAC errors.
* **GCM nonce reuse:** catastrophic — reusing IV/nonce across different messages with same key allows tag forgeries and plaintext recovery (nonce uniqueness critical). Misuse can occur in custom implementations or improper random IV selection.
* **Cipher suite misconfiguration:** allowing weak ciphers (3DES, RC4) or fallback can open attacks (POODLE, sweet32).

### 7.2. Disk encryption & file storage (at rest)

* **Block size collisions (64‑bit):** long lived sessions/files encrypted with 64‑bit block ciphers (3DES) are susceptible to birthday collisions enabling plaintext recovery for large datasets — sweet32 practical with many GBs of data.
* **Key reuse across files/volumes:** reusing IVs or keys for multiple volumes can allow cross‑volume analysis.
* **Metadata leakage through deterministic modes (ECB) or misused IVs.**

### 7.3. Cloud multi‑tenant & virtualization

* **Side‑channel via shared CPU caches:** attacker VM in same host may perform cache attacks (Flush+Reload, Prime+Probe) to recover crypto operations on AES implementations that leak via cache accesses (e.g., T‑table implementations).
* **Timing attacks over network:** remote timing leakage (Lucky13, OpenSSL timing) — slower but possible in some settings.

### 7.4. IoT / embedded devices / firmware

* **Hard‑coded keys & poor RNG:** devices may use fixed keys, predictable PRNG seeds (time based), or low entropy at boot → key recovery or nonce predictability.
* **Side‑channel vulnerabilities:** physical access allows power/EM measurement and key extraction with relatively few traces if device unprotected.
* **Resource constraints → simplified/fast implementations (table lookups) that leak more.**

### 7.5. API and token systems

* **Incorrect use of AES‑CBC for token encryption with predictable IVs or poor error handling → padding oracle.**
* **AES‑CTR or AES‑GCM misuse with nonce reuse across tokens → forgeries.**

### 7.6. Implementation bugs

* **Non constant‑time code for S‑boxes / key schedule:** leads to timing leaks.
* **Optimizations (T‑tables) leak through cache accesses; AES‑NI mitigates this if used properly.**
* **Fault injection on device causing single‑bit faults in intermediate AES rounds can yield key with DFA.**

---

## 8. Methodology (Pipeline & Experiments)

### 8.1. Overall experimental plan

1. **Threat selection:** choose 3–4 attack vectors to implement (e.g., padding oracle on webapp, nonce reuse on GCM, side‑channel on small MCU, brute‑force DES/3DES).
2. **Lab setup:** isolated network + VMs, sample vulnerable services, IoT board bench (e.g., STM32/ESP32), ChipWhisperer for power traces (if available), or simulated leakage for timing attacks.
3. **Implement PoC attacks:** use or adapt public PoC tools (padbuster‑style scripts, Hashcat, cache timing PoC, ChipWhisperer scripts).
4. **Measure & record:** required resources (traces, ciphertexts), time‑to‑success, false positives, and environmental factors (noise, network jitter).
5. **Mitigations & re‑test:** apply fixes (AEAD, unique nonces, constant‑time libs, key rotation, HSM) and measure residual risk.

### 8.2. Specific experiments (examples)

* **Experiment A — Brute‑force DES / 3DES:** build small harness to encrypt known plaintexts and attempt key search with Hashcat or distributed cluster. Measure wall‑time with commodity GPU vs cloud nodes. Demonstrate impracticality of DES in production.
* **Experiment B — Padding Oracle (AES‑CBC):** deploy a deliberately vulnerable API that returns distinct error messages/behaviour when padding invalid. Perform padding oracle attack to recover plaintext; measure number of queries and time. Then patch by constant‑time error handling and re-run.
* **Experiment C — AES‑GCM nonce reuse:** demonstrate forging or plaintext recovery when nonce reused across different messages with same key (simulated); show that AEAD misuse is catastrophic and easier to exploit than brute force.
* **Experiment D — Side‑channel (cache timing / Flush+Reload):** set up target OpenSSL process with a vulnerable (table‑based) AES, and attacker process performing Flush+Reload to recover key bytes. If hardware not available, simulate timing leak via microbenchmarks.
* **Experiment E — Fault Attack (DFA) on AES:** if lab allows, use glitching/fault injection to create faulty ciphertexts and attempt key recovery for reduced rounds; discuss constraints and ethics.

### 8.3. Data collection & reproducibility

* Collect raw logs: ciphertexts, plaintexts, traces, timing logs, script outputs. Provide instructions to reproduce in isolated lab only. Use docker images for server/client, and scripts to run automated experiments. Document all versions and parameters.

---

## 9. Implementation & Tools

* **Software:** OpenSSL (various versions), Python (pycryptodome / cryptography), Hashcat/John the Ripper, pad oracle PoC scripts, cache‑timing PoC, ChipWhisperer tooling.
* **Hardware (recommended):** GPU for brute force (NVIDIA), IoT dev board (ESP32/STM32), ChipWhisperer or oscilloscope + probe for SCA, power measurement rig, glitcher (for DFA) only in lab.
* **Environment:** isolated LAN, VMs for server/client, Kubernetes for deployment examples (optional).

---

## 10. Evaluation Plan & Metrics

* **Success metrics:** key recovered? plaintext recovered? forged ciphertext accepted?
* **Effort:** wall‑clock time, number of queries/messages, number of traces, GPU‑hours, compute cost estimate.
* **Robustness:** attack success under varying noise levels, countermeasures applied.
* **Residual risk after mitigation:** measure improvements (e.g., padding oracle fixed → attack fails; AEAD enforced → nonce reuse prevented).

---

## 11. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Literature survey, choose exact experiments and set up lab environment (docker images, VMs, hardware provisioning).
* **Tuần 3–4:** Implement Experiment A (DES brute force) and baseline AES experiments; collect initial metrics.
* **Tuần 5–6:** Implement Experiment B (padding oracle) and evaluate; patch and retest.
* **Tuần 7–8:** Implement Experiment C (GCM nonce reuse) + demo.
* **Tuần 9–10:** Implement side‑channel Experiment D (cache timing or power traces) and analyze.
* **Tuần 11:** Run mitigation comparison and aggregate results (statistical analysis).
* **Tuần 12:** Finalize report, reproducible repo (docker + scripts), slides & demo video.

---

## 12. Deliverables

1. **Mid‑term presentation/report:** problem statement, chosen attack vectors, lab setup, initial results.
2. **Final report (PDF/MD):** methodology, full experimental results, analysis, recommendations.
3. **Code repo & artifacts:** PoC scripts, Docker images, raw data (non‑sensitive), notebooks for analysis, build/run instructions.
4. **Demo:** recorded video showing at least 4 PoC attacks and their remediation.
5. **Responsible disclosure note:** guidelines and ethics statement showing experiments run only on lab targets.

---

## 13. Assessment & Rubric (gợi ý)

* Research grounding & novelty: 20%
* Correctness & rigor of experiments (reproducible): 30%
* Depth of deployment weakness analysis and mitigation recommendations: 25%
* Code quality & documentation (Docker, scripts): 15%
* Presentation & report clarity: 10%

---

## 14. Risks, Limitations & Ethical Considerations

* **Dual‑use caution:** PoC details can be misused. All experiments must be performed in isolated, permissioned lab environments only. Do not target third‑party live systems.
* **Hardware safety:** fault injection/glitching can damage devices — perform under supervision and using sacrificial hardware.
* **Legal & disclosure:** do not publish exploit code for production targets; follow responsible disclosure if vulnerabilities in open‑source libs are found.

---

## 15. Mitigations & Best Practices (summary recommendations)

* **Use AEAD (AES‑GCM or AES‑SIV / ChaCha20‑Poly1305)** instead of raw CBC/CTR; ensure unique nonces for GCM/CTR.
* **Avoid 3DES / 64‑bit block ciphers** for long‑lived sessions or large volumes of data; migrate to AES.
* **Implement constant‑time cryptography** (use AES‑NI or vetted constant‑time libs) and avoid T‑table implementations.
* **Proper key management:** HSM/KMS, rotate keys, avoid hard‑coded keys, use strong PRNG for IV/nonce.
* **Do not leak detailed error messages:** uniform error responses to avoid padding oracle.
* **Apply side‑channel mitigations:** disable hyper‑threading on sensitive hosts, employ noise, use masking/blinding where appropriate.

---

## 16. Extensions & Future Work

* ML‑based distinguishing attacks on ciphertexts for reduced‑round ciphers.
* Automated scanner to detect AES misuse in codebases (static analysis for nonce/IV usage patterns).
* Study of AES post‑quantum hybrid designs (not to replace AES but to combine symmetric + PQC for keys).

---

## 17. Tools & Resources gợi ý

* OpenSSL (various versions), pycryptodome, Hashcat/oclHashcat, padbuster PoC scripts, ChipWhisperer toolkit, oscilloscope & probes, power measurement tools, glitcher rigs (lab).
* Docker, Vagrant, Mininet (controlled network emulation), Python/Jupyter for analysis.

---

## 18. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ docker/             # docker-compose files for vulnerable services + attacker tools
  ├─ experiments/
  |   ├─ exp_des_bruteforce/
  |   ├─ exp_padding_oracle/
  |   ├─ exp_gcm_nonce_reuse/
  |   └─ exp_sidechannel/
  ├─ docs/               # report, slides, runbook
  ├─ scripts/            # automation scripts to run experiments and collect logs
  └─ data/               # non-sensitive raw outputs (timing logs, trace counts, csvs)
```

---
