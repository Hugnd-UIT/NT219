# Capstone Project — Multimedia Product Service Platform (Ví dụ: Netflix, Spotify)

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Thiết kế & Triển khai nền tảng dịch vụ nội dung đa phương tiện an toàn (Ví dụ: Netflix/Spotify) — kiến trúc, bảo mật mật mã, DRM, và kịch bản triển khai thực tế

---

## 1. Tóm tắt đề tài (Project Synopsis)

Đề tài hướng tới thiết kế một **nền tảng dịch vụ nội dung đa phương tiện** (streaming media) cấp thực nghiệm, tập trung vào các yêu cầu bảo mật mật mã cho: bản quyền & DRM, phân phối khóa, bảo vệ dữ liệu trên đường truyền, xác thực người dùng và thiết bị, anti‑piracy (watermarking, forensic watermark), và tích hợp CDN/edge để đảm bảo hiệu năng. Sinh viên sẽ:

* Thiết kế kiến trúc end‑to‑end (ingest → encode → pack → encrypt → CDN → client decrypt + playback),
* Triển khai PoC một pipeline nhỏ với HLS/DASH, Chaotic, AES‑CTR/GCM sample encryption, integration với DRM (Widevine/PlayReady/FairPlay emulation),
* Xây dựng hệ thống cấp — quản lý — phân phối khóa an toàn (KMS/HSM/License Server + attestation),
* Đánh giá hiệu năng và an ninh trong các kịch bản thực tế (cloud, edge, mobile, smart TV),
* Phân tích rủi ro mật mã (key leakage, nonce reuse, token replay, DRM bypass), và đề xuất controls operational.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu quy trình end‑to‑end của dịch vụ streaming: encoding, packaging (CMAF/HLS/DASH), encryption & key distribution, CDN integration, client playback.
2. Triển khai cơ chế bảo vệ nội dung: Common Encryption (CENC), SAMPLE‑AES, AES‑CTR/GCM, và tích hợp với DRM license servers (Widevine/PlayReady/FairPlay concepts).
3. Thiết kế hệ thống quản lý khóa (KMS) an toàn: key provisioning, rotation, attestation (device binding), and audit logging.
4. Thực hiện watermarking (robust & forensic), và phân tích trade‑offs giữa watermark robustness vs quality/latency.
5. Phân tích các yếu tố vận hành: scalability (CDN, edge), latency, storage costs, and legal/compliance (copyright, GDPR).

---

## 3. Relevance & Motivation

* Dịch vụ streaming là dịch vụ có doanh thu lớn nhưng cũng là mục tiêu chính của vi phạm bản quyền. Bảo vệ nội dung bằng mật mã và DRM là yêu cầu bắt buộc cho các nhà cung cấp nội dung.
* Thực hành thiết kế một hệ thống end‑to‑end giúp sinh viên hiểu cả mặt kỹ thuật (cryptography, protocols) và vận hành (scale, cost, monitoring).

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Thiết kế key distribution nào cân bằng tốt nhất giữa bảo mật (binding key tới thiết bị/phiên), độ trễ (handshake/license latency) và khả năng mở rộng (CDN/edge)?

**RQ2:** Watermarking forensic có thể phát hiện/pursue nguồn rò rỉ hiệu quả trong các kịch bản P2P/stream rip? Chi phí computation & false‑positive rate ra sao?

**RQ3:** Các vectơ tấn công mật mã (nonce/key reuse, license token replay, compromised edge caching) tồn tại ở đâu trong pipeline và mitigations thực tế có hiệu quả?

**Giả thuyết:** Kết hợp TEE/attestation + short‑lived keys + per‑device licensing giảm rủi ro leak; forensic watermarking với robust embedding và server‑side analytics cải thiện khả năng phát hiện leak nhưng tăng chi phí xử lý.

---

## 5. Kiến thức nền tảng (Background)

* **Packaging & streaming:** HLS/DASH, CMAF, media containers (MP4/fMP4), segmenting, chunked transfer.
* **Common Encryption (CENC):** standard for encrypting media samples (SAMPLE‑AES, cenc: ‘cenc’/‘cbcs’), using AES‑CTR/CBC/GCM with Key IDs (KIDs) in MP4 boxes.
* **DRM ecosystems:** Widevine (Google), PlayReady (Microsoft), FairPlay (Apple). License servers issue keys bound to client device/attestation.
* **Key management & KMS:** HSM/Cloud KMS (AWS KMS, Google Cloud KMS), license servers, ephemeral keys, key rotation.
* **Watermarking:** robust vs fragile, embedding in audio/video domain, forensic watermarking (per‑user identifiers) and detection pipelines.

---

## 6. Literature & industry references (gợi ý khảo sát)

* MPEG‑CENC and ISO/IEC 23001 specs (Common Encryption), Widevine documentation, PlayReady documentation.
* Papers on robust watermarking and forensics (embed & detection algorithms), and industry whitepapers on anti‑piracy and forensic tracking.
* Case studies on CDN/edge architectures (Netflix Open Connect, Spotify CDN strategies).

> Yêu cầu: sinh viên trích dẫn ít nhất 6 tài liệu tiêu chuẩn/technical reports và 3 repo/SDK (shaka‑packager, Bento4, libdash, sample license server implementations).

---

## 7. Thành phần hệ thống & tài nguyên (System Components & Resources)

### 7.1. Các thành phần chính

* **Content Ingest & Encoding:** transcoder (FFmpeg or AWS Elemental) để tạo các ABR renditions.
* **Packaging & Encryption:** packager (shaka‑packager / Bento4) để tạo CMAF/fMP4 segments, apply SAMPLE‑AES / CENC, generate KID metadata.
* **License Server / Key Manager:** issues license, validate client entitlement, perform device attestation (TPM/TEE/DRM platform) and send decryption key or key token. Backed by HSM/KMS.
* **CDN / Edge Cache:** store encrypted segments, serve clients globally (CloudFront, Fastly, custom CDN).
* **Client App / Player:** implements EME (Encrypted Media Extensions) for web, or native SDK (Widevine, FairPlay) to obtain license and decrypt segments via CDM/TEE.
* **Watermarking & Forensics Engine:** embed per‑user IDs during packaging or server‑side, detection tools to scan pirated content.
* **Auth & Billing & Analytics:** Identity provider (OAuth2/OpenID), entitlement service, play logs & analytics.

### 7.2. Tài nguyên & infra cần thiết

* Cloud VMs for encoding/transcoding, object storage (S3) for segments, CDN account, HSM or cloud KMS, license server (scaleable), dev devices (browsers, Android TV, iOS devices), monitoring & logging stack (Prometheus, ELK).
* Optional: TEE infrastructure for device attestation (Android Keystore/TrustZone, iOS Secure Enclave, TPM on set‑top boxes).

---

## 8. Phân tích rủi ro & weaknesses theo kịch bản triển khai thực tế

### 8.1. Key management & license distribution

* **Key leakage at license server or HSM compromise:** if private keys or KMS credentials leaked, attacker could decrypt content at scale.
* **Long‑lived keys & offline caching:** long key TTL allows copied segments to be decrypted later; short‑lived keys reduce window but increase license traffic.
* **License token replay / session hijacking:** attacker reuses license token from real client to get key — mitigations: binding token to device (attestation), TLS + mTLS for license calls, nonce challenge.

### 8.2. CDN & edge cache risks

* **Compromised edge cache with cached keys or improperly cached license responses** may leak keys or tokens. License responses must not be cached publicly; segments encrypted but keys must be safe.
* **Origin to edge TLS misconfig / downgrade** could allow MITM of license requests.

### 8.3. Client & device risks

* **Client‑side attacks (rooted/jailbroken devices):** attackers extract keys from device storage or memory (CDM extraction), or instrument player to dump decrypted frames.
* **Emulation & patched CDMs:** modified players that bypass license checks could be used to get decrypted content on non‑authorized devices.
* **Key provisioning to insecure devices (no TEE):** must restrict content quality or deny high‑res streams to insecure devices.

### 8.4. Watermarking & forensic challenges

* **Robustness vs detectability:** strong watermark robust to transcoding/pirate edits may affect quality; weak watermark easily removed.
* **False positives & legal implications:** watermark detection must have low false positives to avoid wrongful accusations.

### 8.5. Cryptographic‑level issues

* **Nonce reuse in SAMPLE‑AES/AES‑CTR or improper IV derivation:** may allow segment plaintext recovery across renditions if IV/KID misused.
* **Poor RNG for key generation or license nonce:** predictable keys/tokens enable attacks.
* **Algorithm misuse:** wrong mode (ECB) or misapplied authenticated encryption leading to forgery.

---

## 9. Methodology (Implementation & Experiments)

### 9.1. PoC scope (gợi ý)

* Build a minimal pipeline:

  1. Ingest raw source, transcode to ABR renditions (FFmpeg).
  2. Packager (shaka‑packager / Bento4) to create CMAF/fMP4 segments and encrypt with CENC (AES‑CTR or CBCS) using test KIDs.
  3. Implement a simple License Server: authenticate client (OAuth2), validate entitlement, perform device attestation (simulated), and issue license (key or key token). Use a software KMS or cloud KMS for key storage.
  4. Serve segments via a simple CDN emulation (NGINX + caching) and player (Shaka Player in browser with EME or ExoPlayer on Android) that requests licenses and plays.

### 9.2. Experiments to run

* **Latency / QoE tests:** measure startup latency, time‑to‑first‑frame (TTFF), and rebuffer events under different license TTLs and key rotation policies.
* **Scale tests:** simulate many concurrent clients requesting licenses and segments; measure license server throughput and CDN origin load.
* **Security tests:**

  * Attempt license token replay and test device binding mitigations.
  * Emulate rooted client to try dump decrypted frames (memory scraping) and measure success under TEE vs non‑TEE.
  * Test IV reuse across renditions / segments and attempt plaintext recovery.
  * Attempt removal / defeat of watermark on ripped content and measure detection rate.

### 9.3. Measurement & logging

* Collect metrics: license request latency, license server CPU/memory, CDN cache hit ratio, client TTFF, forensic watermark detection true/false rates, incidents of successful bypass.

---

## 10. Evaluation Plan & Metrics

* **Security metrics:** percentage of successful unauthorized decryptions in controlled attacks, number of successful token replays, watermark detection recall/precision.
* **Performance metrics:** license latency (median/p95/p99), TTFF distribution, throughput (licenses/sec), CDN hit ratio, additional CPU cost for encryption/watermarking.
* **Operational metrics:** cost estimate (storage, CDN egress, license server instances), complexity of key rotation flow, time to revoke entitlement.

---

## 11. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Requirement analysis, select tech stack (shaka‑packager, Bento4, shaka player, KMS choice), provision infra (cloud dev accounts).
* **Tuần 3–4:** Implement ingest → encode pipeline and packager to produce encrypted segments with simple key store.
* **Tuần 5–6:** Build license server (OAuth2 integration, simulated attestation) and integrate with player; basic end‑to‑end playback.
* **Tuần 7–8:** Implement CDN emulation, run scale tests, implement key rotation policy and short‑lived keys.
* **Tuần 9:** Implement watermarking & detection pipeline; create test scenarios of ripping/edits.
* **Tuần 10:** Security tests (token replay, rooted device emulation, IV misuse tests).
* **Tuần 11:** Aggregate results, ablation (varied key TTLs, attestation strictness), and tune mitigations.
* **Tuần 12:** Final report, reproducible repo (Docker/Helm), slides, demo & presentation.

---

## 12. Deliverables

1. **Mid‑term:** architecture diagram, prototype pipeline, initial ingestion & encrypted segment outputs.
2. **Final report (PDF/MD):** full architecture, experiments, security analysis & recommendations.
3. **Code repo:** scripts for encoding/packaging, license server code, player example, Docker/Helm for deployment.
4. **Artifacts:** sample encrypted segments, KIDs, license logs, watermark detection results, performance metrics (CSV/plots).
5. **Demo:** recorded demo of playback and a security test (e.g., token replay blocked or watermark detection shown).

---

## 13. Assessment & Rubric (gợi ý)

* System design & completeness (architecture, components): 25%
* Implementation quality & reproducibility (Docker/Helm): 25%
* Security analysis & experiments (coverage, rigor): 30%
* Report, documentation & presentation: 20%

---

## 14. Risks, Limitations & Mitigation

* **DRM licensing constraints:** full integration with Widevine/PlayReady/FairPlay in production requires licensor agreements and closed‑source CDMs; use emulation/simulation for PoC.
* **Legal/ethical:** watermarking & forensic analysis must respect privacy laws; do not fingerprint users beyond legal allowances.
* **Scale constraints:** full CDN scale tests may be expensive; emulate with local clusters and synthetic load.

---

## 15. Ethics & Compliance

* Respect copyright and use licensed sample content or synthetic assets.
* For watermarking and forensic tracing, design privacy‑preserving embedding and retention policies; obtain consent where appropriate.
* Follow applicable data protection laws (GDPR) for user telemetry and logs.

---

## 16. Tools & Resources gợi ý

* **Encoding/packaging:** FFmpeg, shaka‑packager, Bento4, GPAC.
* **License & DRM:** sample license server implementations (Widevine/PlayReady docs), OpenKeyWhitebox projects, cloud KMS (AWS/GCP/Azure), HSM (optional).
* **Player:** Shaka Player (web), ExoPlayer (Android), AVFoundation (iOS with FairPlay).
* **Watermarking:** open research implementations (e.g., OpenWatermarking research code), AES libs, monitoring & logging stack (Prometheus, ELK).
* **Testing & infra:** Docker, Kubernetes (k3s/minikube), JMeter/wrk for load tests.

---

## 17. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ ingest/             # scripts to transcode (FFmpeg) and generate source renditions
  ├─ packager/           # shaka‑packager / Bento4 configs and outputs (encrypted segments)
  ├─ license-server/     # OAuth2 + entitlement + license issuance code (node/go/python)
  ├─ cdn-sim/            # nginx based CDN emulator + caching configs
  ├─ player/             # sample web player (Shaka Player) + integration scripts
  ├─ watermark/          # embedding & detection scripts + test files
  ├─ infra/              # Docker Compose / Helm charts to run whole system locally
  ├─ benchmarks/         # load test scripts, raw CSVs, analysis notebooks
  └─ docs/               # report, slides, demo instructions
```

---

