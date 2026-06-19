# Capstone Project — Hybrid Classical + PQC TLS Handshake (ECDHE + Kyber)

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Hybrid Classical + PQC Protocols — Thiết kế handshake TLS 1.3 kết hợp ECDHE + Kyber và phân tích hiệu năng

---

## 1. Tóm tắt đề tài (Project Synopsis)

Mục tiêu của đề tài là thiết kế, triển khai và đánh giá một **handshake TLS 1.3 hybrid** kết hợp **ECDHE** (ephemeral Diffie–Hellman trên đường cong elip) và **Kyber** (KEM hậu-lượng-tử) để đạt được cơ chế trao đổi khóa có tính năng phòng thủ đa lớp: vừa giữ forward secrecy truyền thống vừa bổ sung tính an toàn trước máy tính lượng tử. Sinh viên sẽ triển khai các biến thể handshake (ECDHE-only, Kyber-only, hybrid ECDHE+Kyber), tích hợp với OpenSSL (hoặc OpenSSL-OQS), thực hiện benchmark trên môi trường thực (x86\_64 Linux + ARM), và phân tích các hệ quả về hiệu năng, băng thông, memory footprint và tác động tới TLS session resumption.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu chi tiết TLS 1.3 handshake và cách tích hợp cơ chế trao đổi khóa thay thế (KEM/KDF).
2. Thiết kế phép kết hợp khóa an toàn (key composition) giữa ECDHE và Kyber (ví dụ: HKDF-mix), xét đến tính an toàn và forward secrecy.
3. Triển khai thử nghiệm bằng cách sử dụng OpenSSL-OQS/liboqs hoặc patch OpenSSL để hỗ trợ hybrid key-exchange.
4. Đo lường và so sánh hiệu năng (handshake latency, round-trips, throughput), kích thước gói tin, memory và overhead trên x86 và ARM.
5. Trình bày kết quả, phân tích trade-offs và đưa ra khuyến nghị cho thực tế triển khai (server, client, embedded).

---

## 3. Relevance & Motivation

* Khi chuẩn hậu-lượng-tử được áp dụng, nhiều hệ thống cần một lộ trình chuyển đổi (migration path) mà vẫn giữ được khả năng tương tác với hệ thống hiện tại. Hybrid handshake là một cách tiếp cận thực tiễn: đồng thời thực hiện ECDHE và KEM rồi kết hợp các bí mật.
* Việc đo đạc chi tiết overhead (độ trễ, băng thông, code/memory footprint) là cần thiết để quyết định liệu hybrid approach có khả thi cho web servers, mobile clients hoặc các thiết bị tài nguyên hạn chế.

---

## 4. Câu hỏi nghiên cứu & giả thuyết

**RQ1:** Overhead (latency, bytes, cpu) của hybrid ECDHE+Kyber so với ECDHE-only và Kyber-only ở TLS 1.3 là bao nhiêu trên server x86 và ARM (Raspberry Pi)?

**RQ2:** Có thể tối ưu hóa tích hợp Kyber (tùy chọn tham số, lựa chọn implementation PQClean vs optimized asm) để giảm overhead xuống mức chấp nhận được cho server dưới tải cao không?

**RQ3:** Hybrid composition (ví dụ HKDF-Extract trên concat(secrets)) có ảnh hưởng nào to lớn đến tính tương thích hoặc tính bảo mật (ví dụ forward secrecy) không?

**Giả thuyết:** Hybrid handshake sẽ tăng độ trễ và băng thông (krypto bytes) so với ECDHE-only, nhưng với implementation tối ưu và chế độ hybrid nhẹ (chỉ thêm ciphertext nhỏ vào ClientHello/ServerHello), overhead có thể chấp nhận được cho phần lớn use-cases server; trên thiết bị nhúng overhead có thể đáng kể nhưng vẫn có thể tối ưu hóa.

---

## 5. Background (Tổng quan ngắn)

* **TLS 1.3 handshake (tóm tắt):** ClientHello (ClientKeyShare), ServerHello (ServerKeyShare), key derivation, EncryptedExtensions, Certificate, CertificateVerify, Finished. TLS 1.3 hỗ trợ nhiều key-share types.
* **ECDHE:** trao đổi khóa ephemeral dựa trên EC (ví dụ P-256) — cung cấp forward secrecy trong bối cảnh mật mã cổ điển.
* **KEM (Kyber):** Key Encapsulation Mechanism xuất ciphertext chứa shared secret; Kyber là một KEM lattice-based được thiết kế cho PQC.
* **Hybrid approach (cơ bản):** Client & Server thực hiện cả ECDHE và KEM; hai bí mật tổng hợp bằng KDF để tạo Master Secret cuối cùng.

---

## 6. Literature review (những hướng cần khảo sát)

* Tài liệu kỹ thuật về TLS 1.3 và key exchange extensions.
* Bài báo / kỹ thuật tích hợp PQC vào TLS (OpenSSL-OQS, liboqs integration notes).
* Các chiến lược kết hợp bí mật (KDF mixing strategies) và các hệ quả an ninh của chúng.
* Công trình benchmark PQC trong TLS & hybrid handshake (nếu có sẵn).

> Gợi ý: sinh viên phải trích dẫn ít nhất 6 tài liệu kỹ thuật/báo cáo và ít nhất 2 repo mã nguồn (liboqs/OpenSSL-OQS, PQClean).

---

## 7. Methodology (chi tiết đề xuất)

### 7.1. Thiết kế handshake: các biến thể cần triển khai

* **Baseline A — ECDHE-only (TLS 1.3):** Chuẩn hiện tại (ví dụ x25519 hoặc P-256 key share).
* **Baseline B — Kyber-only (KEM-based):** Thực hiện KEM trong key share (client gửi KEM ciphertext as keyshare, server decapsulates). (Lưu ý: pure-KEM TLS KEX cần careful spec)
* **Hybrid C — ECDHE + Kyber (concat+HKDF):** Client và Server thực hiện cả ECDHE và Kyber; derive secret as HKDF-Extract(salt, concat(secret\_ECDHE, secret\_Kyber)) hoặc HKDF-Expand of HKDF-Extract of combined secrets.
* **Hybrid D — KEM-as-fallback / opportunistic:** Primary ECDHE but include Kyber KEM ciphertext in extensions to provide PQ insurance if ECDHE is broken.

### 7.2. Key composition strategies (thiết kế an toàn)

* **Concat + HKDF-Extract:** simplest; MS = HKDF-Extract(salt, secret1 || secret2) → HKDF-Expand(MS, info, L)
* **Sequential HKDF:** MS1 = HKDF-Extract(salt, secret1); MS = HKDF-Extract(MS1, secret2)
* **XOR-based mixing:** MS = HKDF-Extract(salt, secret1 XOR secret2) — less recommended unless sizes match and entropy assumptions verified.

*Cho sinh viên:* thảo luận tính an toàn của từng cách mix, chọn 1–2 cách và đưa luận cứ an ninh ngắn gọn (defense-in-depth, non-degradation property: nếu ít nhất một secret an toàn thì MS an toàn).

### 7.3. Wire format & negotiation

* **ClientHello changes:** include additional KeyShare entry for KEM (or use new extension). Phải đảm bảo kích thước ClientHello không vượt MTU nhiều; nếu cần phân mảnh, thực nghiệm xử lý.
* **ServerHello changes:** trả KEM ciphertext (nếu server encapsulates) hoặc ServerKeyShare for KEM.
* **Compatibility:** server should negotiate hybrid support via extension; fall back to ECDHE if peer does not support.

### 7.4. Implementation path

* **Preferred:** use OpenSSL-OQS (OpenSSL fork or provider supporting OQS) which already implements KEM integration for TLS. Điều chỉnh to implement hybrid mixing strategy if not present by default.
* **Alternative:** patch OpenSSL to add custom KeyShare type for KEM and corresponding derivation; or write wrapper library that performs KEM outside TLS handshake and injects secret into TLS via pre-shared key (PSK) mechanism — *less ideal but practical for prototyping*.

---

## 8. Implementation & Experiment Setup

### 8.1. Hardware & platforms

* **Server (x86\_64):** Linux server or laptop with modern CPU. Fix CPU freq, isolate cores for consistency.
* **Client (x86\_64 & ARM):** Desktop client and ARM (Raspberry Pi 4) to test client performance.
* **Optional mobile:** Android/iOS builds if feasible.

### 8.2. Software stack & tools

* OpenSSL-OQS or OpenSSL patched with liboqs
* liboqs / PQClean / pqm4 (for different implementations)
* Benchmark tools: `s_server`/`s_client` (OpenSSL), `wrk`/`wrk2`, `openssl speed` (modified), custom Python harness using `pyOpenSSL` or `requests` with configured TLS.
* Measurement tools: `time`, `perf`, `strace`, `tcpdump`/`tshark` to measure wire bytes, `valgrind massif`/`smem` for memory.

### 8.3. Experiments to run

1. **Microbenchmarks:** measure time for key exchange operations alone (ECDHE generate/shared secret vs Kyber encaps/decap) in isolated harness.
2. **Handshake latency (single connection):** measure wall-clock time for TLS handshake for each variant: ECDHE-only, Kyber-only, Hybrid. Repeat N times, collect median & CI.
3. **Handshake under load:** server handling concurrent connections (vary concurrency), measure requests/sec, average handshake latency, CPU usage.
4. **Wire-size:** measure ClientHello/ServerHello sizes, total bytes exchanged during handshake.
5. **Session resumption:** measure impact on session tickets / early data flow when hybrid used.
6. **Cross-platform tests:** run client on ARM to evaluate computational overhead on constrained clients.
7. **Optimization experiments:** compare PQClean reference vs optimized asm/NEON builds; test compiler flags (-O2/-O3 -march=native) effects.

### 8.4. Reproducibility

* Provide scripts to build OpenSSL-OQS at specific commit, documented compiler versions, and harness scripts to run experiments. Containerize x86\_64 runs (Docker) and provide cross-compile / aarch64 images or step-by-step instructions for Raspberry Pi.

---

## 9. Evaluation Plan & Metrics

* **Latency:** median handshake time, mean, stddev, 95% CI.
* **Throughput:** handshakes/sec at various concurrencies.
* **Wire overhead:** bytes per handshake, additional round-trips if any.
* **CPU & Memory:** CPU % utilization during handshake, peak RSS.
* **Client energy (optional):** measure power impact on ARM devices.
* **Compatibility & failure modes:** test interoperability with clients/servers not supporting hybrid; fallback behavior.
* **Security considerations:** ensure hybrid preserves forward secrecy and non-degradation property (if at least one primitive secure then combined secret secure).

**Reporting:** present tables/charts: latency vs variant, bytes vs variant, CPU vs variant, per-platform comparison.

---

## 10. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Literature survey, decide mixing strategy, choose target implementations (OpenSSL-OQS commit), procure boards.
* **Tuần 3–4:** Build environment, compile liboqs/OpenSSL-OQS, run basic demos (Kyber KEM, ECDHE) separately.
* **Tuần 5–6:** Implement hybrid handshake prototype (OpenSSL-OQS config or patch), unit test key derivation correctness.
* **Tuần 7–8:** Implement benchmark harness & microbenchmarks, initial runs on x86.
* **Tuần 9:** ARM cross-compile, run client+server experiments on Raspberry Pi.
* **Tuần 10:** Optimization experiments (NEON, flags), retest, gather final data.
* **Tuần 11:** Analyze results, statistical checks, create figures/tables.
* **Tuần 12:** Final report, code repo, Docker images, presentation & demo.

---

## 11. Deliverables

1. **Mid-term presentation/report:** design choices, mixing strategy, initial microbenchmarks.
2. **Final report (PDF/MD):** architecture, implementation details, full benchmarks, interpretation, limitations.
3. **Code repository:** patched OpenSSL-OQS/OpenSSL configurations, harness scripts, exact commit hashes, build instructions.
4. **Artifacts:** raw csv logs of runs, processed plots, binary sizes.
5. **Demo video / live demo:** show handshake traces (tcpdump), handshake times and fallbacks.

---

## 12. Assessment & Rubric (gợi ý)

* Technical correctness & security reasoning: 25%
* Implementation & reproducibility (build scripts, commit hashes): 25%
* Experimental rigor & analysis (statistics, visualizations): 30%
* Report & presentation quality: 20%

---

## 13. Risks, Limitations & Mitigation

* **Complexity of patching TLS stacks:** mitigation: prefer OpenSSL-OQS if it already supports KEM integration; otherwise implement prototype using PSK-injection to simulate mixing.
* **Interoperability with real-world clients:** hybrid may require client+server both updated — simulate using controlled clients/servers.
* **Measurement variance:** mitigate by fixed CPU freq, isolated cores, multiple batches, paired comparisons.
* **Security proofs out of scope:** only provide informal arguments and cite formal literature; do not claim rigorous proofs unless backed by references.

---

## 14. Ethics & Responsible Disclosure

* Không triển khai thử nghiệm trên môi trường production. Nếu phát hiện vấn đề bảo mật trong OpenSSL/liboqs, thông báo tới maintainer qua kênh responsible disclosure.

---

## 15. Extensions & Future Work

* Integrate hybrid approach into HTTP client libraries (curl/libcurl) and measure web-page load impacts.
* Explore hybrid session resumption schemes and early-data security implications.
* Formal analysis of hybrid key derivation composition (theoretical security proofs or reduction to constituent primitives).

---

## 16. Tools & Resources gợi ý

* OpenSSL-OQS, liboqs, PQClean
* Docker (for reproducible x86 experiments), cross-compile toolchains for aarch64
* `wrk`/`wrk2`, `ab`, `openssl s_server`/`s_client` for handshake tests
* `tcpdump`/`tshark` for wire-size analysis, `perf` / `time` for CPU timing
* Raspberry Pi or similar ARM boards for client-side tests

---

## 17. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ openssl-oqs/        # patched OpenSSL or fork reference (submodule) with commit hash
  ├─ liboqs/             # liboqs submodule
  ├─ harness/            # benchmark harness scripts (micro + tls)
  ├─ docker/             # Dockerfiles and buildx configs for multiarch
  ├─ results/            # raw CSVs, processed plots
  ├─ scripts/            # build, deploy, run-experiments scripts
  └─ docs/               # final report, slides, demo video
```

---
