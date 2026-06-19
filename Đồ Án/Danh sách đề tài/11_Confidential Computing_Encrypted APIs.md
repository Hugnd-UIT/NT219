# Capstone Project — Confidential Computing & Encrypted APIs: Tích hợp Enclave (Intel SGX / AMD SEV) với API để xử lý dữ liệu đã mã hóa

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Confidential Computing + Encrypted APIs — Triển khai và đánh giá mẫu tích hợp TEE (Intel SGX, AMD SEV/NV) để xử lý dữ liệu được mã hóa an toàn trong môi trường cloud/API

---

## 1. Tóm tắt đề tài (Project Synopsis)

Đề tài nghiên cứu, thiết kế, triển khai và đánh giá một **API service** kiểu confidential computing: client gửi dữ liệu được mã hóa tới dịch vụ; máy chủ (service) sử dụng **trusted execution environment (TEE)** như Intel SGX hoặc AMD SEV để giải mã, xử lý và trả kết quả đã/được mã hóa trở lại, đồng thời bảo đảm tính **confidentiality** và **integrity** của dữ liệu và keys ngay cả khi hệ điều hành host bị xâm phạm. Sinh viên sẽ:

* So sánh các patterns tích hợp TEE (in‑enclave crypto vs envelope encryption + key provisioning),
* Triển khai prototype cho ít nhất một nền tảng TEE (SGX hoặc SEV) và mô phỏng/đo lường cho nền tảng kia,
* Thực hiện remote attestation để cấp khoá (key provisioning) an toàn,
* Đo lường hiệu năng (latency, throughput), chi phí tài nguyên, và thảo luận các rủi ro bảo mật (side‑channel, implementation bugs).

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu khái niệm Confidential Computing, TEE (Intel SGX, AMD SEV/SEV‑SNP, AWS Nitro Enclaves) và chu trình remote attestation.
2. Thiết kế pipeline mã hoá/giải mã an toàn: client‑side encryption (envelope encryption) kết hợp với attestation‑driven key provisioning.
3. Triển khai prototype sử dụng Open Enclave / Intel SGX SDK / Fortanix SDK / AMD SEV toolchain hoặc AWS Nitro Enclaves để xử lý truy vấn được mã hóa.
4. Đo và phân tích hiệu năng: ECALL/OCall overhead, attestation latency, throughput, memory, và năng lượng (nếu khả dụng).
5. Phân tích các rủi ro an ninh: side‑channels, rollback attacks, Iago attacks, và đề xuất mitigation.

---

## 3. Relevance & Motivation

* Dữ liệu nhạy cảm (y tế, tài chính) thường không thể rời khỏi môi trường bảo mật hoặc phải mã hóa end‑to‑end; confidential computing cho phép xử lý trong đám mây mà vẫn giữ bí mật dữ liệu.
* Cloud providers đã cung cấp dịch vụ confidential VMs / enclaves (Azure Confidential VMs, Google Confidential VM, AWS Nitro Enclaves) — hiểu cách tích hợp với API rất quan trọng để áp dụng vào thực tế.

---

## 4. Câu hỏi nghiên cứu & giả thuyết

**RQ1:** Mẫu tích hợp nào (in‑enclave decryption và processing vs envelope encryption + remote‑attestation based key provisioning) có hiệu năng & an toàn phù hợp cho API latency‑sensitive workloads?

**RQ2:** Liệu overhead của TEE (entry/exit, attestation, memory constraints) có chấp nhận được cho workflows thực tế (ví dụ inference ML nhẹ, queries trên DB) không?

**RQ3:** Những rủi ro side‑channel nào là đáng lưu ý khi xử lý trong enclave, và mitigation nào hiệu quả trong môi trường thực nghiệm?

**Giả thuyết:** Remote‑attestation + envelope encryption (kết hợp KMS) mang lại mức an toàn thực tiễn tốt hơn và giảm surface attack; overhead thêm vào chủ yếu đến từ attestation (một lần) và ECALL/OCALL mỗi request; với batching và caching, throughput chấp nhận được cho nhiều use‑case.

---

## 5. Background (Tổng quan ngắn)

* **Intel SGX:** TEE ở mức enclave trong process, cho phép code & data được bảo vệ khỏi host OS; hỗ trợ sealing, attestation; giới hạn memory (EPC), và entry/exit (ECALL/OCALL) chi phí.
* **AMD SEV / SEV‑SNP:** bảo vệ toàn bộ VM memory; model khác SGX (VM‑level vs process‑level), remote attestation khác (VCEK/DCAP equivalence), phù hợp cho bảo vệ VM workloads.
* **Nitro Enclaves (AWS):** lightweight isolated execution environment với vsock communication; khác về remote attestation (Nitro attestation vs SGX IAS/DCAP).
* **Open Enclave / Fortanix / Graphene:** frameworks giúp viết ứng dụng enclave với APIs trừu tượng hoá.
* **Key provisioning & attestation:** remote attestation flow (enclave → quote → attestation service → attestation verification → KMS grants ephemeral keys).
* **Envelope encryption:** client encrypts payload with symmetric CEK; CEK wrapped under a key only provisioned to attested enclave.

---

## 6. Literature review (các hướng cần khảo sát)

* Intel SGX programming guide, DCAP, Intel Attestation Service (IAS) docs.
* Open Enclave SDK tutorials, Fortanix EDP docs, Graphene.
* AMD SEV / SEV‑SNP docs and attestation flows; AWS Nitro Enclaves docs.
* Papers on TEE side‑channels (cache, speculative execution, SGX attacks) and mitigation techniques.
* Case studies: confidential ML inference, encrypted DB queries in enclave.

> Yêu cầu: sinh viên trích dẫn ít nhất 6 bài báo và 3 repos / vendor docs (Open Enclave, Fortanix, AWS Nitro Enclaves).

---

## 7. Methodology (chi tiết đề xuất)

### 7.1. Kiến trúc đề xuất (2 patterns chính)

**Pattern A — Envelope encryption + remote attestation key provisioning (recommended):**

1. Client tạo CEK (content encryption key) dùng AES‑GCM, mã hoá payload.
2. Client gửi ciphertext + metadata tới API endpoint.
3. Server host (untrusted) forwards ciphertext tới enclave (via ECALL/ vsock) WITHOUT ability to decrypt.
4. Enclave thực hiện remote attestation (trước đó) để chứng minh identity tới attestation service; sau khi xác thực, enclave được cấp ephemeral decryption key (CEK unwrapped) từ KMS or attestation‑aware key broker.
5. Enclave giải mã payload, xử lý, mã hóa kết quả bằng CEK hoặc tạo response ciphertext.

**Pattern B — In‑enclave key & runtime decryption (direct decryption in enclave):**

* Client gửi ciphertext encrypted by public key whose private key is held in enclave (less scalable for many clients). Thích hợp khi public key distribution sẵn có.

Sinh viên nên triển khai Pattern A như baseline, và (nếu thời gian) PoC Pattern B.

### 7.2. Remote attestation flow & key provisioning

* Thiết lập attestation: enclave tạo quote (SGX quote / SEV attestation), gửi đến Attestation Service (Intel DCAP / AMD / Azure Attestation).
* Attestation Service trả kết luận; xác thực thành công → KMS cấp khoá (via unwrap/wrap or grant).
* KMS may be cloud provider KMS (Azure Key Vault, AWS KMS) or Fortanix DMS for enclave‑aware key grants.

### 7.3. Enclave implementation details

* Tối thiểu hoá TCB: chỉ code crypto & processing quan trọng chạy trong enclave; network stack & logging outside.
* Sử dụng libs được đánh giá: mbedTLS/mbedtls‑sgx, OpenSSL ported for enclave, ring/ or libsodium (cần audit constant‑time).
* Xử lý IO: host app nhận HTTP requests, write ciphertext to shared memory / vsock, ECALL to enclave; enclave processes and returns result.
* Caching & batching: cache session keys & attestation results để tránh attestation cho mỗi request.

### 7.4. Security mitigations

* Viết mã constant‑time cho crypto primitives; dùng vetted libs.
* Minimise enclave size and avoid heavy C++ std libs that increase attack surface.
* Defend side‑channels: restrict multi‑tenancy on enclave host, disable hyper‑threading if recommended, use latest mitigations for speculative attacks.
* Use SEV‑SNP (if possible) to reduce attacks by hypervisor.
* Protect against rollback: use monotonic counters or trusted time from platform to prevent replay of sealed state.

---

## 8. Implementation & Experiment Setup

### 8.1. Hardware & cloud options

* **Local dev:** Intel CPU supporting SGX (e.g., Intel i7/i9 with SGX) or Intel SGX emulator for initial dev (simulation mode).
* **Cloud:** Azure Confidential VMs (SGX), AWS Nitro Enclaves, Google Confidential VMs with AMD SEV, or Microsoft Azure Attestation service for attestation flows.
* **Optional:** Raspberry Pi / ARM not applicable for SGX; use VM setups for SEV if accessible.

### 8.2. Software stack

* **Frameworks:** Open Enclave SDK or Intel SGX SDK (for SGX), Fortanix EDP (enterprise), Open‑enclave sample code for remote attestation.
* **KMS & Attestation:** Azure Attestation, Azure Key Vault, AWS KMS + Nitro or AWS KMS with Nitro attestation, Fortanix DMS.
* **Host service:** Node/FastAPI/Go microservice to accept HTTPS, forward to enclave via vsock/ECALL.
* **Client libs:** sample clients to envelope‑encrypt payload (Python/JS) and perform calls.

### 8.3. Datasets & sample workloads

* **Use‑cases:** private analytics (sum/aggregate on sensitive dataset), secure ML inference (simple model, e.g., image classification small), encrypted search (keyword search on small DB), secure payment processing sample.
* Synthetic datasets preferred for privacy; include realistic sizes (payloads up to few KBs) to simulate request sizes.

---

## 9. Evaluation Plan & Metrics

* **Latency:** per‑request latency with and without enclave processing; breakdown: network, host forwarding, ECALL/OCALL, decryption, processing, response encryption.
* **Throughput:** requests/sec under concurrent clients; effect of batching & caching.
* **Attestation cost:** time to perform attestation & get key provisioning (cold vs warmed attestation flows).
* **Memory usage:** enclave EPC usage and host memory.
* **Security evaluation:** checklist for attestation correctness, key provisioning flow, and side‑channel risk analysis.
* **Comparison:** evaluate difference between SGX and SEV/SNP in terms of ease of integration, attestation flow, and performance (if both platforms available).

**Reporting:** present tables and charts: latency vs payload size, throughput vs concurrency, attestation latency distribution, EPC memory pressure observations.

---

## 10. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Survey literature, choose platform(s) & frameworks (Open Enclave recommended), set up dev environment and cloud trial accounts.
* **Tuần 3–4:** Implement host HTTP service + client envelope encryption scripts; integrate simple enclave skeleton and ECALL/OCALL scaffolding.
* **Tuần 5–6:** Implement remote attestation & key provisioning flow (integrate with cloud attestation service / simulated attestation for lab), implement CEK unwrap inside enclave.
* **Tuần 7–8:** Implement processing logic inside enclave (analytics / ML inference sample) and response sealing; add caching/batching.
* **Tuần 9:** Run performance experiments (latency, throughput), tune caching and batch sizes.
* **Tuần 10:** Security assessment: side‑channel threat analysis, implement recommended mitigations (reduce TCB, use constant‑time libs).
* **Tuần 11:** Aggregate data, statistical analysis, ablation studies (with/without caching, various payload sizes).
* **Tuần 12:** Finalize report, code repository (with run instructions), demo video & presentation.

---

## 11. Deliverables

1. **Mid‑term report/presentation:** architecture, attestation plan, initial PoC skeleton.
2. **Final report (PDF/MD):** full methodology, experimental results, security analysis, limitations & recommendations.
3. **Code repo:** host service, enclave code, client scripts, build scripts, container images (note: full enclave runs require hardware).
4. **Artifacts:** raw CSV logs, plots, attestation logs, EPC usage logs.
5. **Demo:** short video showing attestation, key provisioning, request processing and result delivery.

---

## 12. Assessment & Rubric (gợi ý)

* Technical understanding & literature grounding: 20%
* Correctness & completeness of implementation (attestation, key provisioning): 25%
* Experimental rigor (measurement methodology & analysis): 25%
* Security discussion & mitigations (side‑channels, rollback): 20%
* Report & presentation quality: 10%

---

## 13. Risks, Limitations & Mitigation

* **Hardware access:** SGX/SEV hardware might be limited — mitigation: use simulation mode for development, cloud confidential VMs for testing, clearly mark which experiments were in sim vs real hardware.
* **Side‑channel attacks:** cannot be fully mitigated — minimise TCB, use constant‑time libs, disable HT where recommended, consider data‑oblivious algorithms for critical parts.
* **Attestation complexity:** platform/vendor attestation APIs differ — use abstraction (Open Enclave) and document platform details.
* **Regulatory/legal:** handling real sensitive data requires permissions; use synthetic/anonymized data in experiments.

---

## 14. Ethics & Responsible Disclosure

* Không sử dụng dữ liệu nhạy cảm thật mà không có phép; nếu phát hiện lỗ hổng trong SDKs hoặc vendor services, thực hiện responsible disclosure tới vendor.
* Minh bạch về giới hạn bảo mật; không khuyến khích dựa hoàn toàn vào TEE cho mọi threat model.

---

## 15. Extensions & Future Work

* **Federated confidential computing:** combine enclaves + secure aggregation for distributed private analytics.
* **Hybrid with HE/MPC:** use HE or MPC to reduce TCB inside enclave or to preprocess data before enclave ingestion.
* **Scholia:** evaluate trusted HW root‑of‑trust differences across vendors at scale.
* **Automated verification:** formal verification of enclave entry/exit boundary code.

---

## 16. Tools & Resources gợi ý

* Open Enclave SDK, Intel SGX SDK, Fortanix EDP/SDK, Graphene.
* Azure Attestation & Azure Key Vault, AWS Nitro Enclaves SDK + KMS, AMD SEV docs & attestation interfaces.
* mbedTLS/OpenSSL (port for enclaves), libsodium, Rust crates for SGX (if using Rust).
* Monitoring & profiling: `perf`, SGX EPC profiling tools, cloud monitoring tools.

---

## 17. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ host/               # host HTTP service (node/go/python) that accepts ciphertext and communicates with enclave
  ├─ enclave/            # enclave source code (Open Enclave / SGX SDK) with processing logic
  ├─ client/             # client scripts to envelope-encrypt data and call APIs
  ├─ attestation/        # attestation helper scripts, verifier code, attestation logs
  ├─ scripts/            # build + run scripts, dockerfiles (for host), crosscompile instructions
  ├─ experiments/        # raw CSVs, plotting notebooks, benchmark harness
  └─ docs/               # report, slides, demo video, runbook
```

---
