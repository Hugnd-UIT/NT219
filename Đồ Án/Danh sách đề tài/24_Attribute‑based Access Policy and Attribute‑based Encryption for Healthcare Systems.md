# Capstone Project — Attribute‑based Access Policy & Attribute‑based Encryption for Healthcare Systems

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Attribute‑based Access Policy và Attribute‑based Encryption (ABE) cho hệ thống Y tế — Thiết kế, triển khai và đánh giá cho EHR/FHIR cloud‑native deployments

---

## 1. Tóm tắt đề tài (Project Synopsis)

Mục tiêu: nghiên cứu, thiết kế và thực nghiệm một kiến trúc bảo vệ dữ liệu y tế (EHR, images, lab results) bằng **Attribute‑based Access Control (ABAC)** kết hợp **Attribute‑based Encryption (ABE)** để đạt truy cập chi tiết theo thuộc tính (role, specialty, organisation, consent, purpose) trong môi trường cloud‑native. Sinh viên sẽ xây dựng PoC gồm: authority for attributes (AA), ABE key issuance, client‑side or server‑side encryption (hybrid: ABE encrypts CEK), policy enforcement point (PEP) tích hợp với FHIR server, revocation & emergency („break‑glass”) mechanisms, và đo đạc hiệu năng & rủi ro triển khai thực tế.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu và phân biệt CP‑ABE vs KP‑ABE, multi‑authority ABE, và các thủ thuật revocation/outsourced‑decryption.
2. Thiết kế luồng attribute issuance và verify (RA/AA), tích hợp với IdP (OIDC/SAML) và FHIR authorization.
3. Triển khai PoC: encrypt/decrypt pipeline cho EHR (hybrid ABE + AES CEK), policy enforcement middleware (PEP/PDP), và audit logging với tamper‑evidence.
4. Đánh giá hiệu năng (latency, throughput, ciphertext size), khả năng mở rộng (số attribute, số người dùng), và security‑analysis (collusion, attribute forging, AA compromise).
5. Đề xuất operational best practices cho bệnh viện/healthcare provider: attribute lifecycle, RA procedures, break‑glass policy, consent handling và pháp lý (HIPAA/GDPR mapping).

---

## 3. Tính cấp thiết & động lực (Relevance)

* Dữ liệu y tế cực kỳ nhạy cảm; cloud storage và chia sẻ giữa nhiều tổ chức (hospitals, labs, insurers) đòi hỏi kiểm soát truy cập tinh vi hơn RBAC truyền thống.
* ABE cho phép mã hoá theo chính sách trực tiếp, giảm phụ thuộc vào KMS ở phía server và phù hợp cho scenarios patient‑centric sharing và auditing.

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Trong bối cảnh EHR lưu trữ trên cloud, CP‑ABE + hybrid encryption có thể cung cấp fine‑grained access với hiệu năng chấp nhận được cho workloads thực tế không?

**RQ2:** Multi‑authority ABE và revocation mechanisms (time‑based attrs, attribute update, proxy re‑encryption) có giảm thiểu rủi ro collusion & authority compromise hiệu quả không?

**Giả thuyết:** Giải pháp hybrid (ABE cho CEK, AES‑GCM cho bản dữ liệu) với outsourced decryption và attribute expiration cho phép cân bằng giữa bảo mật và hiệu năng; nhưng triển khai cần RA/AA nghiêm ngặt, và break‑glass phải được thực hiện bằng threshold re‑encryption với audit bắt buộc.

---

## 5. Background (Tổng quan ngắn)

* **ABE types:**

  * **Ciphertext‑Policy ABE (CP‑ABE):** encryptor embeds access policy into ciphertext; user's secret keys contain attributes.
  * **Key‑Policy ABE (KP‑ABE):** ciphertext labelled with attributes; user's key encodes policy.
  * **Multi‑Authority ABE (MA‑ABE):** attributes issued by multiple independent authorities.
* **Revocation & updates:** attribute expiration/time period, key update using key‑insulated schemes, proxy re‑encryption (PRE) and broadcast revocation techniques.
* **Outsourced decryption:** heavy pairing operations offloaded to cloud service while preserving confidentiality via transform keys.
* **Hybrid encryption pattern:** symmetric CEK encrypted under ABE, large files encrypted with AES‑GCM.

---

## 6. Literature review & tools (hướng khảo sát)

* Bethencourt et al. (2007) CP‑ABE, Lewko & Waters (MA‑ABE), Yu et al. (revocable ABE), Green & Ateniese (outsourced decryption), schemes for efficient revocation and predicate encryption.
* Implementations/tools: **libfenc / OpenABE / Charm Crypto / RELIC / PBC**, and PRE libraries (Umbral, Stanford's PRE prototypes).

> Yêu cầu: sinh viên trích ít nhất 6 bài báo hoặc standard reports và 3 codebases (OpenABE, Charm, libfenc).

---

## 7. Thành phần hệ thống & tài nguyên (System Components & Resources)

### 7.1. Thành phần chính

* **Client Apps:** EHR viewer / clinician portal / patient portal — thực hiện decrypt CEK (có thể outsourced transform) và decrypt dữ liệu; UI hiển thị provenance & consent.
* **Attribute Authorities (AA) / Registration Authorities (RA):** hospital HR AA (roles), lab AA (lab staff), national eID AA, patient consent AA — issue attribute secret keys to users.
* **Policy Decision Point (PDP) & Policy Enforcement Point (PEP):** PDP evaluates attributes/policy; PEP integrates với FHIR server / object store.
* **Encryption Service & Storage:** hybrid encryptor for files (CEK + ABE), storage (S3 / object store).
* **Outsourced Transform Service (Optional):** transforms ABE ciphertext to partially decrypted form (using transform key) to reduce client cost.
* **Audit & Logging:** append‑only audit log (tamper‑evident; ledger or signed logs) for access & break‑glass events.
* **KMS / HSM:** for root master keys of AA, HSM for signing tokens & audit integrity; not used to decrypt patient data if ABE applied correctly.

### 7.2. Hạ tầng & tài nguyên

* Kubernetes cluster, object storage, FHIR server (HAPI FHIR / OpenMRS integration), ABE libs (Charm/PBC) with pairing support, HSM or SoftHSM for AA root key management, test devices (clinician workstation, mobile), logging (ELK), optional SGX nodes for transform service.

---

## 8. Kịch bản triển khai thực tế & Weakness Analysis (Deployment Scenarios)

### 8.1. Single‑Hospital Cloud Storage

* Attributes issued by hospital AA (role=doctor, dept=cardiology). CP‑ABE encrypts records with policy `role:doctor AND dept:cardiology`.
* **Weaknesses:** AA compromise yields mass key issue; attribute forging if AA auth weak; performance for large imaging files (use hybrid AES+ABE CEK).

### 8.2. Multi‑Hospital Data Sharing (Research / Referral)

* Multi‑authority: each hospital/lab issues attributes; policy may require attributes from multiple AAs (e.g., `hospitalA:referral AND research:approved`).
* **Weaknesses:** coordination overhead, cross AA trust establishment; collusion possibilities if users pool attributes; revocation complexity.

### 8.3. Patient‑Mediated Sharing / Consent

* Patient issues consent attribute `consent:studyX` to share data with researchers. Patient may later revoke consent — must ensure revocation reachable (time‑based attributes or proxy re‑encrypt).
* **Weaknesses:** timely revocation is hard; existing ciphertexts may still decrypt unless re‑encryption/short TTL used.

### 8.4. Emergency (Break‑glass)

* In emergencies, clinician without matching attributes must access record; break‑glass mechanism (threshold PRE or multi‑party approval) allows access but logs and triggers retrospective audit.
* **Weaknesses:** abuse of break‑glass, insufficient audit or delayed review reduces deterrent. Need strong governance and automated alerts.

---

## 9. Methodology (Pipeline & Experiments)

### 9.1. PoC choices & scope

* **Select ABE scheme(s):** baseline Bethencourt CP‑ABE; MA‑ABE variant (Lewko); revocable ABE (Yu). Implement via Charm/OpenABE.
* **Hybrid encryption:** AES‑GCM for payloads; ABE encrypts CEK + metadata (policy, version, timestamp).
* **Attribute issuance:** implement AA with RA workflow integrated to IdP (Keycloak) — AA signs attributes and issues attribute keys via PKCS#11/REST.

### 9.2. Experiments to run

1. **Performance bench:** encryption/decryption time vs #attributes (encrypt CEK for policies with 3,5,10 attributes); measure ciphertext size and memory.
2. **Scale test:** number of users and attribute issuance throughput; AA key generation & distribution delays.
3. **Outsourced decryption test:** measure transform time and verification time on client; compare CPU/energy for mobile client.
4. **Revocation experiments:** implement time‑based attribute expiry and proxy re‑encryption; measure time to revoke and fraction of ciphertexts needing re‑encryption.
5. **Security test:** collusion simulation (combine keys from multiple users) to attempt unauthorized decryption; test attribute forgery attacks by compromised RA.
6. **Break‑glass prototype:** implement threshold PRE requiring k-of-n authorizers to re‑encrypt CEK and measure latency and audit logging.

### 9.3. Lab setup & safety

* Use synthetic patient datasets, HAPI FHIR server for EHR, S3-like object store (MinIO) to hold encrypted blobs, and K8s cluster for microservices. Keep keys & HSM in dev/SoftHSM for lab.

---

## 10. Implementation & Tools

* **ABE libs:** Charm Crypto (pairing), OpenABE, libfenc examples.
* **Cryptography primitives:** RELIC or PBC for pairings; OpenSSL for AES, HMAC.
* **FHIR / EHR:** HAPI FHIR server, OpenMRS demo.
* **IdP / AA integration:** Keycloak for identity + attribute issuance extension; Vault/SoftHSM for AA root key protection.
* **Outsourced transform:** custom transform microservice; optional SGX/Nitro for secure transforms.
* **Audit & log integrity:** ELK stack + signed logs; append‑only ledger (optional: Hyperledger Fabric or simple blockchain) for tamper evidence.
* **Dev env:** Docker, Kubernetes (minikube / k3s), JMeter for load tests, prometheus/grafana for metrics.

---

## 11. Evaluation Plan & Metrics

* **Functional security:** success/failure of authorized access, false accept rate under collusion experiments, attribute forgery success probability.
* **Performance:** encrypt/decrypt latency (ms), CEK ABE encrypt size (bytes), transform time, throughput (enc/sec, dec/sec), client CPU & energy (mobile).
* **Operational:** AA key issuance latency, revocation propagation time, storage overhead, scalability limits (attributes and users supported).
* **Usability / workflow:** time to get attribute from AA (user onboarding), complexity for clinicians to access in emergency.

---

## 12. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Literature review, scheme selection (CP‑ABE / MA‑ABE), provision lab infra (HAPI FHIR, MinIO, K8s).
* **Tuần 3–4:** Implement basic hybrid encryptor & storage pipeline; integrate FHIR file attachments encryption.
* **Tuần 5–6:** Implement AA + RA workflow (Keycloak extension) and attribute key issuance; baseline performance tests.
* **Tuần 7–8:** Implement outsourced transform service and test mobile client decryption; measure resource use.
* **Tuần 9:** Implement revocation (time‑based & proxy re‑encryption) and run revocation experiments.
* **Tuần 10:** Collusion & security tests; break‑glass prototype (threshold re‑encryption) and audit logging.
* **Tuần 11:** Aggregate results, ablation studies (vary #attributes / policy complexity), finalize mitigation recommendations.
* **Tuần 12:** Final report, reproducible repo (docker/k8s manifests), demo video & presentation.

---

## 13. Deliverables

1. **Mid‑term report:** design, lab infra, scheme choices, initial benchmarks.
2. **Final report:** methodology, experimental data (CSV/plots), threat analysis, mitigation checklist.
3. **Code repo & PoC:** encryptor, AA service, transform service (optional SGX), FHIR integration, revocation scripts.
4. **Artifacts:** sample encrypted records (synthetic), logs, performance graphs, attack scripts.
5. **Demo video & slides**: end‑to‑end encryption + revocation + break‑glass scenario.

---

## 14. Assessment & Rubric (gợi ý)

* Research grounding & design choices: 25%
* PoC correctness & reproducibility: 30%
* Experimental rigor & security analysis: 25%
* Documentation & presentation: 20%

---

## 15. Risks, Limitations & Ethical Considerations

* **Patient data:** dùng dataset tổng hợp hoặc anonymized sample; không sử dụng bệnh nhân thật.
* **Dual‑use:** publishable PoC may inform attackers; restrict network exposure and disclose vulnerabilities responsibly.
* **Performance limits:** ABE schemes can be heavy—document assumptions about scale and acceptable latency.

---

## 16. Mitigations & Best Practices (summary recommendations)

* **Use hybrid pattern:** ABE encrypts CEK; large payloads encrypted with AES‑GCM.
* **Minimize AA blast radius:** multi‑authority issuance, threshold protection for AA root keys (HSM), strict RA identity verification.
* **Implement revocation:** use time‑based attributes (short TTL), and where needed PRE-based re‑encryption for revocation/consent changes.
* **Outsource heavy ops safely:** provide verifiable transform (cloud transform + proof) to reduce client load.
* **Break‑glass governance:** require multi‑party approval + mandatory audit trails + automated alerts for emergency access.
* **Consent & policy UX:** clearly surface consent & access purpose to users and clinicians; provide revocation flow with audit.

---

## 17. Extensions & Future Work

* Explore **functional encryption** for richer queries over encrypted EHR (e.g., compute aggregate stats without revealing records).
* Formalize and verify AA trust policies using formal policy languages (XACML extensions).
* Integrate **verifiable logs** (blockchain or transparency logs) for AA actions and attribute issuance.

---

## 18. Tools & Resources gợi ý

* Charm Crypto, OpenABE, libfenc, RELIC/PBC, OpenSSL, HAPI FHIR/OpenMRS, Keycloak, Vault/SoftHSM, MinIO, Docker/K8s, Prometheus/Grafana, JMeter.

---

## 19. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ infra/              # docker-compose / k8s manifests (HAPI FHIR, MinIO, Keycloak)
  ├─ encryptor/          # hybrid encryptor (ABE + AES) + utils
  ├─ aa_service/         # Attribute Authority & RA workflow
  ├─ transform/          # outsourced transform microservice (optional SGX)
  ├─ revocation/         # scripts for TTL rekey, proxy re‑encryption, tests
  ├─ attacks/            # collusion simulations, attribute forgery tests
  ├─ benchmarks/         # perf scripts, raw CSVs, plotting notebooks
  └─ docs/               # report, runbooks, ethics note, demo scripts
```

---

*Ghi chú cho sinh viên:* Khi nộp báo cáo, nêu rõ scheme cụ thể (paper & params), commit hashes, pairing library & curve parameters, và phân biệt rõ phần nào là simulation vs hardware acceleration / SGX. Tuân thủ đạo đức và pháp luật khi thử nghiệm dữ liệu y tế.

---