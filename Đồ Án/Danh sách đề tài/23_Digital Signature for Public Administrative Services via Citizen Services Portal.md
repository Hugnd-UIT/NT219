# Capstone Project — Digital Signature for Public Administrative Services via Citizen Services Portal

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Chữ ký số cho Dịch vụ Hành chính Công qua Cổng Dịch vụ Công (Citizen Services Portal)

---

## 1. Tóm tắt đề tài (Project Synopsis)

Đề tài thiết kế, triển khai và đánh giá một hệ thống **chữ ký số** tích hợp cho cổng dịch vụ công (ví dụ: nộp hồ sơ, ký quyết định, thanh toán mức thuế, chứng thực văn bản) — bao gồm cả **quy trình ký của công dân** (client‑side signing với smartcard/USB token hoặc mobile signing) và **dịch vụ ký từ xa** (remote‑signing / cloud signature service) do TSP cung cấp. Sinh viên phải:

* Phân tích yêu cầu pháp lý & non‑repudiation (ví dụ: eIDAS‑style qualified signatures / local regulations),
* Thiết kế dòng ký end‑to‑end (authN, signature creation, TSA timestamping, long‑term validation),
* Triển khai PoC: portal + client signing demo + remote signing server (SoftHSM / PKCS#11),
* Đánh giá rủi ro kỹ thuật & vận hành (key compromise, malware trên client, revocation, timestamping compromise)
* Đề xuất operational checklist cho cơ quan hành chính (RA procedures, audit, retention & privacy).

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu các chuẩn chữ ký điện tử: X.509 PKI, CAdES/PAdES/XAdES, CMS/PKCS#7, RFC 3161 timestamping, OCSP/CRL, và khái niệm Qualified Electronic Signature.
2. Thiết kế & triển khai quy trình ký: client‑side (PKCS#11 / WebCrypto + smartcard), remote signing (CAdES/PAdES generation on server), và LTV (long‑term validation) bằng timestamp & archived OCSP.
3. Triển khai hạ tầng PKI & TSP minimal: CA/RA, OCSP responder, TSA, HSM or SoftHSM, RA workflow cho đăng ký công dân.
4. Phân tích rủi ro: key compromise, supply chain (HSM firmware), timestamp authority trust, UI deception (phishing), và cung cấp mitigations.
5. Viết báo cáo reproducible với PoC, scripts, test cases, và checklist vận hành.

---

## 3. Tính cấp thiết & động lực (Relevance)

* Việc số hóa dịch vụ hành chính yêu cầu các phương pháp đảm bảo tính pháp lý, toàn vẹn và không thể chối bỏ của văn bản điện tử.
* Thiết kế an toàn cho chữ ký số tránh được các vụ gian lận hành chính, giảm chi phí xử lý giấy tờ và đáp ứng quy định pháp luật về chữ ký điện tử.

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Client‑side signing (smartcard/USB/mToken) so với remote signing (TSP) — trade‑offs về bảo mật, khả năng sử dụng (usability), chi phí và khung pháp lý là gì?

**RQ2:** Những vectơ tấn công (malware trên client, CA compromise, TSA compromise, key escrow abuse) có thể dẫn tới việc giả mạo chữ ký như thế nào và mức độ dễ khai thác trong triển khai thực tế?

**Giả thuyết:** Client‑side signing trên smartcard/secure element cung cấp mức độ bảo vệ private key tốt hơn (khó chiết xuất) — nhưng gây ra rào cản tiện ích; remote signing với strong authentication + attestation + HSM bảo đảm tiện lợi cao nhưng yêu cầu TSP & quy trình RA rất chặt chẽ để duy trì non‑repudiation.

---

## 5. Background (Tổng quan ngắn)

* **PKI fundamentals:** CA/RA, certificate lifecycle, private/public key pairs, X.509 certs, signature creation and verification.
* **Signature formats:** CMS/PKCS#7 & CAdES (CMS advanced), PAdES for PDF, XAdES for XML—kèm thông tin xác thực, thời gian, và vết xác minh.
* **TSA & timestamping:** RFC 3161 time‑stamping authority để chứng minh thời điểm tạo chữ ký; quan trọng cho LTV.
* **OCSP/CRL:** revocation checking; staple OCSP responses with signatures to enable offline verification.

---

## 6. Literature review & standards (hướng khảo sát)

* eIDAS (EU), ETSI TS standards for CAdES/PAdES/XAdES, RFC 3161 (TSA), RFC 6960 (OCSP), and national regulations on electronic signatures.
* Papers & reports on remote signing security, threshold signatures, HSM attacks, and client malware that target signing workflows.

> Yêu cầu sinh viên trích dẫn tối thiểu 6 nguồn chính thức/academic + 3 thực hành codebases (OpenSSL, OpenSC/PKCS#11, SoftHSM, libre‑TSAs).

---

## 7. Thành phần hệ thống & tài nguyên (System Components & Resources)

### 7.1. Thành phần chính

* **Citizen Portal (Web):** giao diện nộp hồ sơ, hiển thị dữ liệu, khởi tạo yêu cầu ký; tích hợp WebAuthn/OIDC cho xác thực công dân.
* **Client Signing Agents:**

  * **Smartcard / USB token:** PKCS#11 driver, middleware (OpenSC), browser plugin / native app to access token.
  * **Mobile Signing SDK:** mobile eID / secure enclave signing (Secure Enclave / Android Keystore) + OTP or biometric.
  * **Remote Signing Client:** strong authentication (BankID, Mobile‑ID, Bank authentication) to request server‑side signature.
* **Signature Service (TSP):** HSM‑backed signing service implementing PKCS#11 or HSM API; logs every signing operation; provides signed timestamp and embeds OCSP responses for LTV.
* **PKI Components:** Root CA / Sub CA, RA (registration authority) processes, OCSP responder, CRL distribution point, TSA (timestamp authority).
* **Verification & Archive Service:** verify signatures, store documents, manage LTV (archive timestamps, stored OCSP/CRLs), provide audit trails.

### 7.2. Hạ tầng & phần mềm cần thiết

* HSM appliance (or SoftHSM for lab), CA software (e.g., EJBCA, OpenCA), OCSP responder (OpenCA/OSCP responders), TSA (OpenTSA or libre TSA), web server + portal stack, PKCS#11 libraries, PDF/XAdES libraries for signature embedding.

---

## 8. Kịch bản triển khai thực tế & phân tích weaknesses (Deployment Scenarios & Weakness Analysis)

### 8.1. Dịch vụ ký client‑side (smartcard/USB)

* **Weaknesses:** malware on client UI can intercept data before signing; users lose tokens; driver bugs/PKCS#11 misconfig; browser plugin trust issues.
* **Mitigations:** secure UI/UX (show digest), confirm data to sign, use secure elements, require PIN + biometric, tamper‑resistant hardware, user education.

### 8.2. Dịch vụ ký từ xa (TSP / cloud signing)

* **Weaknesses:** TSP compromise or coercion, insider threats, key extraction from HSM (rare but possible with firmware attacks), weak authentication to request signature, replay of requests.
* **Mitigations:** HSM with FIPS 140‑2/3 Level 3, multi‑factor strong auth (eID + OTP), attestation logs, dual control signing (threshold signatures / multi‑party), per‑signature audit trails.

### 8.3. Timestamping & LTV

* **Weaknesses:** compromised TSA or lack of archived OCSP responses may break long‑term verifiability; reliance on online OCSP leads to online requirement.
* **Mitigations:** archive OCSP responses and CRLs, embed signed timestamps (RFC 3161), periodic re‑timestamping.

### 8.4. PKI & revocation management

* **Weaknesses:** slow CRL updates, OCSP availability outage, CRL poisoning, or CA key compromise.
* **Mitigations:** OCSP stapling, short‑lived certificates, certificate transparency logs, robust RA process, CA key protection, cross‑validation practice.

### 8.5. Privacy & data minimization

* **Weaknesses:** Portal may store excessive PII; signable content could reveal sensitive data.
* **Mitigations:** data minimization, encryption at rest, access controls, GDPR compliance, pseudonymization where possible.

---

## 9. Methodology (Pipeline & Experiments)

### 9.1. Overall plan

1. **Requirement & legal mapping:** map local legal requirements for signature types (equivalent to QES/eIDAS if applicable).
2. **Build PoC stack:**

   * CA/RA + OCSP + TSA (use EJBCA/OpenCA & OpenTSA),
   * SoftHSM or test HSM for server signing,
   * Citizen Portal (web) with OIDC login (Keycloak) and endpoints for signature creation & verification,
   * Client signing demo: Smartcard via OpenSC + browser native app, Mobile signing demo using Android Keystore/Keychain,
   * Remote signing demo: authenticated request flow to TSP.
3. **Implement verification & LTV archiver:** verify signatures, store signed docs with archived OCSP/timestamps.
4. **Run experiments & attacks:** simulate client malware intercept, replay attacks, HSM misuse simulation (key usage logging), TSA outage & LTV verification, revoked cert scenarios.

### 9.2. Example experiments

* **Experiment A — Client malware & UI deception:** simulate a compromised browser extension that modifies document before user signs; measure detection probability and suggest UI mitigations (human‑readable hash, out‑of‑band confirmation).
* **Experiment B — Remote signing misuse & replay:** attempt to replay signed requests to TSP; verify that nonces, timestamping and per‑request audit thwart replay.
* **Experiment C — Revocation & OCSP stapling:** revoke signer cert and test verification against archived OCSP vs live OCSP; measure effects.
* **Experiment D — Threshold signing vs single HSM key:** implement threshold signing (e.g., Shamir or threshold PKI approach) to reduce single point compromise and measure operational cost.

---

## 10. Implementation & Tools

* **PKI & CA:** EJBCA or OpenCA for CA/RA, OpenSSL for ad‑hoc certs.
* **HSM & SoftHSM:** SoftHSM for development; AWS CloudHSM / Thales / Utimaco for production.
* **Client tooling:** OpenSC + PKCS#11, WebCrypto based signing where supported, Mobile Keystore examples.
* **Document signing libraries:** DSS (EU Digital Signature Services), PDFBox/iText for PAdES, Apache Santuario for XML/XAdES, BouncyCastle for CMS/CAdES.
* **TSA & OCSP:** OpenTSA, OpenSSL ocsp responder, EJBCA OCSP responder.
* **Portal & Auth:** Keycloak for IdP (OIDC), Node/Java/Spring web portal, Docker & k8s for orchestration.

---

## 11. Evaluation Plan & Metrics

* **Security:** success/failure rate of simulated attacks (malware, replay, HSM misuse), time to detect unauthorized signatures, ability to prove non‑repudiation in tests.
* **Usability:** time to complete a signature operation (client‑side vs remote), error rates in user studies (if feasible), accessibility metrics.
* **Operational:** signing throughput (signs/sec), HSM latency, archival storage & retrieval time, cost estimates for HSM & TSP operations.
* **Compliance:** mapping to legal requirements (checklist), gaps identified.

---

## 12. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Phân tích yêu cầu pháp lý, chọn chuẩn & công cụ, set up CA/RA/SoftHSM.
* **Tuần 3–4:** Xây dựng Citizen Portal skeleton, OIDC login, và client signing demo bằng smartcard (OpenSC).
* **Tuần 5–6:** Triển khai Remote Signing Service (HSM/SoftHSM), integrate TSA & OCSP, produce signed documents (PAdES/CAdES).
* **Tuần 7–8:** Implement verification & LTV archiver; create audit & logging pipeline.
* **Tuần 9:** Run attack simulations (client malware, replay, revocation), collect metrics.
* **Tuần 10:** Implement mitigations (threshold signing, UI improvements, OCSP stapling) and re‑test.
* **Tuần 11:** Usability tests & compliance checklist; prepare policy & RA playbook.
* **Tuần 12:** Finalize report, reproducible repo (Docker), slides & demo video.

---

## 13. Deliverables

1. **Mid‑term:** legal & technical requirements mapping, architecture diagram, CA/SoftHSM setup.
2. **Final report:** full methodology, PoC, attack results, mitigations & operational checklist for RA/TSP.
3. **Code repo & artifacts:** portal code, client agent demos, HSM integration scripts, archived OCSP/timestamp samples, test scripts.
4. **Compliance checklist:** mapping to national e‑signature rules & notes on QES equivalence (if applicable).
5. **Demo video:** end‑to‑end signing (client & remote), verification & LTV example, and one simulated attack demonstration.

---

## 14. Assessment & Rubric (gợi ý)

* Requirement analysis & legal mapping: 20%
* PoC correctness & reproducibility: 30%
* Security analysis & mitigation depth: 25%
* Documentation, usability & compliance checklist: 25%

---

## 15. Risks, Limitations & Ethical Considerations

* **Legal & regulatory:** do not produce fake qualified certificates; use test CA for PoC and map to legal requirements only conceptually.
* **User data & privacy:** use synthetic personal data or consented volunteers for any usability tests.
* **HSM handling:** do not use production HSM keys in PoC; SoftHSM is acceptable for lab.

---

## 16. Mitigations & Best Practices (summary recommendations)

* **Prefer hardware‑backed keys** (smartcard, secure element, HSM) for non‑repudiation; enforce PIN + biometric where possible.
* **Strong RA procedures:** in‑person identity proofing or trusted eID federations; strict logging & four‑eye approvals for TSP operations.
* **Use timestamps & archive OCSP responses** to provide LTV; periodically re‑timestamp as necessary.
* **Implement dual control / threshold signing** to reduce single point of compromise in remote signing services.
* **Minimize client attack surface:** secure signing UI that shows canonical digest and requires explicit user confirmation; limit browser plugins.

---

## 17. Extensions & Future Work

* **Threshold & distributed signing:** explore BFT threshold signatures or MPC signing for TSPs to avoid single HSM compromise.
* **Integration with national eID:** support eID federations (e.g., eIDAS) and cross‑border recognition.
* **Formal verification of verification codepaths** to ensure LTV and revocation checks are correct.

---

## 18. Tools & Resources gợi ý

* OpenSC, PKCS#11 libraries, SoftHSM, EJBCA/OpenCA, OpenTSA/LibreTSA, BouncyCastle, Apache Santuario, PDFBox/iText, Keycloak, OpenSSL, Docker/Kubernetes.

---

## 19. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ ca‑infrastructure/   # EJBCA/OpenCA configs, SoftHSM PKCS#11 setup
  ├─ portal/              # citizen portal (web) + OIDC configs
  ├─ client‑agents/       # smartcard demo (OpenSC), mobile signing demo
  ├─ tsp/                 # remote signing service, HSM integration, logging
  ├─ verifier/            # verification & LTV archiver
  ├─ attacks/             # simulation scripts (replay, malware sim, revocation tests)
  └─ docs/                # report, RA playbook, compliance checklist
```

---

*Ghi chú cho sinh viên:* Khi triển khai PoC, luôn phân biệt rõ phần nào là code/lab test (SoftHSM/test CA) và phần nào cần triển khai với nhà cung cấp TSP/HSM thật trong môi trường sản xuất. Lưu ý pháp lý về chứng thực chữ ký; tham vấn pháp chế nếu cần.

---