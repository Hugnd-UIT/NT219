# Capstone Project — Migration Tool: Hỗ trợ thay thế RSA/ECC bằng PQC cho API / OpenSSL

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Migration Tool — xây dựng bộ công cụ và thư viện hỗ trợ chuyển đổi API/OpenSSL từ RSA/ECC sang Post‑Quantum Cryptography (PQC)

---

## 1. Tóm tắt đề tài (Project Synopsis)

Mục tiêu: thiết kế, triển khai và đánh giá một **công cụ chuyển đổi (migration tool)** giúp các ứng dụng server/API và kho thư viện crypto (OpenSSL) dễ dàng thử nghiệm, tích hợp, và từng bước thay thế hoặc bổ sung RSA/ECC bằng các primitive hậu‑lượng‑tử (KEMs, PQ signatures). Công cụ sẽ cung cấp: (1) runtime shim/provider cho OpenSSL (hoặc plugin/engine) để bật PQ primitives; (2) API‑level adapters (JWT, mTLS, TLS client/server libraries) để hỗ trợ hybrid & fallback; (3) migration assistant scripts (certificate/key reissuance, key rotation, compatibility testing) và (4) benchmark & compatibility test harness để đánh giá chi phí và coverage.

Mục tiêu thực tế: giúp devops/engineers giảm rủi ro khi thử nghiệm PQC, giữ khả năng tương tác với client legacy, và cung cấp artifacts để đưa vào CI/CD trước rollout.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu kiến trúc OpenSSL 3.x provider/legacy engine, EVP API, và cách tích hợp lib crypto bên ngoài (liboqs/PQClean).
2. Thiết kế giao diện migration (CLI + library) để tự động hoá: phát hiện sử dụng RSA/ECC, tạo khóa PQ tương ứng, sinh certificate hybrid/dual, và cập nhật cấu hình dịch vụ.
3. Triển khai shim/plugin cho OpenSSL để bật PQ algorithms (Kyber, Dilithium) dưới dạng provider hoặc engine, bao gồm fallback/hybrid logic.
4. Xây dựng adapter cho API (REST, gRPC) — mTLS, JWT signing/verification — để chuyển đổi an toàn, có thể rollback.
5. Thực hiện benchmarking, compatibility testing, và viết hướng dẫn triển khai an toàn cho production migration.

---

## 3. Tính cấp thiết & động lực (Relevance & Motivation)

* Việc chuyển sang PQC là cần thiết cho bảo vệ dữ liệu dài hạn; tuy nhiên, thực tế có nhiều rào cản: tương thích, băng thông, chi phí CPU/độ trễ, và quản lý khóa/cert.
* Công cụ migration sẽ giảm chi phí thao tác thủ công, tăng khả năng thử nghiệm trong môi trường staging, và cung cấp khung cho triển khai từng bước (gradual migration).

---

## 4. Câu hỏi nghiên cứu & giả thuyết

**RQ1:** Một migration tool có thể tự động hoá bao nhiêu step (issue PQ certs, update OpenSSL config, rotate keys) mà vẫn đảm bảo an toàn và khả năng rollback?

**RQ2:** Mức overhead (latency, payload size, CPU load) khi bật hybrid PQC cho TLS/mTLS/JWT là bao nhiêu trong môi trường thực tế (Linux server, ARM client)?

**RQ3:** Những chiến lược certificate/key deployment (dual‑cert, cross‑signed, extension fields) nào mang lại best compatibility vs lowest operational risk?

**Giả thuyết:** Migration tool với provider-based integration và hybrid handshake patterns (e.g., ECDHE + Kyber) có thể cung cấp lộ trình khả thi mà overhead ở mức chấp nhận được cho nhiều hệ thống server; tuy nhiên trên client nhúng/IoT có thể cần thêm bước tối ưu hoặc offloading.

---

## 5. Background & Technical Context (Tổng quan)

* **OpenSSL providers & EVP:** OpenSSL 3.0 chuyển sang kiến trúc provider cho phép đăng ký thuật toán. Trước đó, engine API được dùng để tích hợp crypto suitors.
* **liboqs / PQClean:** thư viện triển khai PQ primitives, thường dùng kết hợp với OpenSSL‑OQS fork hoặc provider.
* **TLS/mTLS/JWT:** đường đi chính cần migration — key exchange (KEM vs ECDHE), certificate signatures (Dilithium/Falcon vs ECDSA), token signing (JWT RS256/ES256 → PQ signatures).
* **Migration patterns:** hybrid handshake, dual certificates, transitional CA cross‑signing, PSK/KEM assisted key wrapping, API gateway layer performing PQ validation.

---

## 6. Literature review & existing tools

* Open Quantum Safe (liboqs) & OpenSSL‑OQS projects.
* PQClean, pqm4, RFC drafts about PQC integration.
* Industrial migration guides (cloud providers, TLS library notes), RFCs on KEM integration & hybrid handshakes.
* PKCS#11 providers & HSM support for PQC (limited, evolving).

> Yêu cầu: sinh viên cần liệt kê ít nhất 6 nguồn chính thức (liboqs documentation, NIST PQC notices, OpenSSL provider docs, relevant RFCs) và 3 codebases (OpenSSL‑OQS, PQClean, sample provider repos).

---

## 7. Methodology (Pipeline & Design)

### 7.1. Phạm vi công cụ

1. **Provider/Engine layer:** plugin cho OpenSSL (provider) tích hợp liboqs/PQClean — expose KEMs + PQ sig via EVP API.
2. **API adapter layer:** small library & middleware cho web servers (NGINX sidecar, API gateway plugin, Java/Python libs) để hỗ trợ JWT PQ signing/verification và mTLS PQ cert selection.
3. **Migration assistant CLI:** scripts để scan codebase/configs (nginx/apache, Java keystore, OpenSSL configs), generate PQ keys/certs, create dual certs, rotate keys, update config and restart in safe mode.
4. **Test & benchmark harness:** automated tests for compatibility (TLS handshake with legacy clients), benchmarks for performance, and compliance checks (certificate size, CT logs).

### 7.2. Migration strategies supported

* **Dual Certificates:** issue both classical (ECDSA/RSA) and PQ public keys; client chooses which to verify (requires client support or server chooses presented cert based on SNI/JA3).
* **Hybrid Signatures/Key Exchange:** perform both ECDHE and KEM and mix secrets (HKDF) — no immediate revocation of classical keys.
* **Certificate extension:** store PQ public key in X.509 extension (experimental) while still presenting classical cert for compatibility.
* **Off‑chain verification / attestation:** for API tokens, verify PQ signatures off‑chain and publish attestation on chain or in token metadata.

### 7.3. Compatibility & negotiation

* Implement capability discovery: server advertises PQ support via TLS extension; API gateway/clients detect and negotiate PQ-enabled flows; fallback to classical when peer doesn't support.
* Provide feature flags & canary rollout support for gradual deployment.

### 7.4. Safety & rollback procedures

* Always keep classical key as fallback until PQ rollout verified.
* Atomic config change scripts with health checks & automatic rollback on failures.
* Staging & Canary channels with percentage traffic routing (e.g., via Kubernetes ingress weights).

---

## 8. Implementation & Experiment Setup

### 8.1. Components & Tech Stack

* **Core libs:** OpenSSL 3.x, liboqs, PQClean.
* **Glue:** C for provider, Python/Go/Node for CLI and adapters, Rust bindings optional.
* **Deployment:** Docker images for services, Kubernetes for staged rollout, HashiCorp Vault plugin to store PQ keys.
* **Testing:** OpenSSL s\_client/s\_server, curl with custom SSL backend, browsers (with patched libs if needed), automated test suites.

### 8.2. Example flows to implement

1. Provider build & load into OpenSSL; verify EVP interfaces expose Kyber/Dilithium.
2. Web server (NGINX or Apache via OpenSSL) configured to use provider; perform TLS handshake with hybrid/ECDHE+Kyber option.
3. API server JWT signing: library produces PQ signature and sends in token; verify in gateway or client.
4. Migration CLI: detect target service, create PQ keypair, request CA to issue PQ cert (or cross‑sign), update service config and reload with health checks.

### 8.3. Benchmarking & environments

* **Platforms:** x86\_64 Linux (server), ARM (Raspberry Pi for client), optional cloud instances.
* **Metrics:** handshake latency, CPU/memory, signature size, token size, throughput, compatibility success rate (percentage of clients able to complete handshake).
* **Test harness:** scripted scenarios (legacy client, PQ‑enabled client, mixed traffic), CI runs.

---

## 9. Evaluation Plan & Metrics

* **Functionality:** success rate for TLS handshakes with PQ-enabled server and mix of client types.
* **Performance:** handshake latency median/mean, CPU cycles per handshake, JWT signing latency, API latency impact.
* **Resource & network impact:** key/cert sizes, token payload increase, memory footprint.
* **Operational metrics:** time to migrate a service, rollback success, automation coverage (percentage of steps auto‑handled).
* **Security posture:** validated mixing strategy (non‑degradation), key lifecycle correctness, proof of non‑regression for classical flows.

---

## 10. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Survey, define scope (which PQ primitives, which servers/APIs to support), setup dev env.
* **Tuần 3–4:** Implement OpenSSL provider prototype loading liboqs; expose Kyber/Dilithium via EVP.
* **Tuần 5–6:** Build migration CLI (keygen, cert request, config update), and adapter middleware for JWT/mTLS.
* **Tuần 7–8:** Integrate with web server (NGINX/Apache) and test handshake flows (hybrid & fallback).
* **Tuần 9:** Implement benchmark harness, run perf tests on x86 & ARM.
* **Tuần 10:** Hardening (atomic deploy, health checks), CI integration, documentation.
* **Tuần 11:** Run large scenario tests (canary rollouts simulated), finalize results.
* **Tuần 12:** Final report, release repo, demo & presentation.

---

## 11. Deliverables

1. **Migration tool codebase:** OpenSSL provider plugin, CLI migration assistant, API adapter libraries (Node/Python/Java), and Docker images.
2. **Test harness & benchmarks:** scripts, raw CSV, plots.
3. **Documentation:** migration guide, rollback procedures, security notes, integration examples.
4. **Demo:** video & live demo showing migration on sample service (staging).
5. **Final report:** methodology, results, recommendations for production rollout.

---

## 12. Assessment & Rubric (gợi ý)

* Technical design & security reasoning: 25%
* Implementation quality & reproducibility: 25%
* Experimental rigor & evaluation (benchmarks): 25%
* Documentation & operational readiness (guides, rollback): 15%
* Presentation & demo quality: 10%

---

## 13. Risks, Limitations & Mitigation

* **Client compatibility:** not all clients support PQC; mitigate via hybrid and dual‑cert strategy, plus phased rollout.
* **Standards & tooling maturity:** PQC ecosystem evolving; lock to specific well‑documented commits & clearly annotate versions.
* **HSM / PKCS#11 support limited:** initially rely on software keys or Vault plugin; track HSM vendor support.
* **Operational complexity:** provide strong automation & tested rollback; keep classical paths until full validation.

---

## 14. Ethics & Responsible Use

* Không dùng khóa/ứng dụng production thực tế cho thử nghiệm; tuân thủ quy định bảo mật nội bộ.
* Nếu tìm lỗi bảo mật trong thư viện, báo cáo maintainer theo responsible disclosure.

---

## 15. Extensions & Future Work

* HSM integration (PKCS#11 provider for PQ keys).
* Vault/KMS plugin maturity and secret rotation automation.
* Integration with Certificate Transparency / CT logs for PQ certificates.
* Static analysis tool to find crypto usage patterns in codebase to improve migration coverage.

---

## 16. Tools & Resources gợi ý

* OpenSSL 3.x provider docs, OpenSSL‑OQS, liboqs, PQClean.
* HashiCorp Vault, PKCS#11 providers, Kubernetes secrets.
* NGINX/Apache/OpenResty, NodeJS/Python/Java for adapters.
* Docker, Kubernetes (for canary), GitHub Actions for CI.

---

## 17. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ provider/           # OpenSSL provider plugin (C) that links liboqs/PQClean
  ├─ cli/                # migration assistant (Python/Go) scripts
  ├─ adapters/           # middleware libs: jwt-pqc, mTLS helper (Node/Python/Java)
  ├─ server-integration/ # NGINX / Apache config examples and Docker images
  ├─ tests/              # compatibility tests, pcap-like TLS scenarios
  ├─ benchmarks/         # harness scripts, raw CSVs, analysis notebooks
  ├─ docs/               # migration guide, rollback procedures, README
  └─ docker/             # Dockerfiles for provider + sample services
```

---

