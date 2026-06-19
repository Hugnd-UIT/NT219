# Capstone Project — Application Scenarios: Online Shopping Service Platform (Ví dụ: Amazon, Shopee)

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Thiết kế & Đánh giá an toàn mật mã cho nền tảng thương mại điện tử (Online Shopping Service Platform) — tập trung vào xác thực, thanh toán, bảo vệ dữ liệu, API & microservices, và kịch bản triển khai thực tế

---

## 1. Tóm tắt đề tài (Project Synopsis)

Mục tiêu của đề tài là thiết kế một prototype **nền tảng thương mại điện tử** (catalog, cart, checkout, order processing, payment gateway integration) với trọng tâm là các thành phần mật mã học và an toàn: TLS/mTLS, OAuth2/OpenID Connect cho SSO, tokenization & PCI‑DSS‑compliant payment flows, key management (KMS/HSM), database encryption (TDE, field‑level encryption), API gateway hardening, và anti‑fraud telemetry. Sinh viên sẽ xây dựng kiến trúc end‑to‑end, triển khai prototype (microservices trong Kubernetes), mô phỏng các kịch bản tấn công thực tế (token replay, payment fraud, API abuse, supply‑chain tamper), và đề xuất chính sách vận hành & mitigations.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu & triển khai các mẫu xác thực hiện đại cho web/mobile (OAuth2 Authorization Code + PKCE, OIDC, device auth), và quản lý session/token (JWT, opaque tokens, refresh tokens).
2. Thiết kế luồng thanh toán an toàn: tokenization, PCI‑DSS constraints, integration với payment gateway (3DS / SCA), and secure card data handling (no PAN retention).
3. Triển khai key management (KMS/HSM), envelope encryption, database TDE vs field‑level encryption, and secrets management (Vault).
4. Khắc phục vectơ tấn công API (rate limiting, signed requests, HMAC, mTLS for service‑to‑service), và phát hiện gian lận (behavioural analytics, ML scoring).
5. Đo & phân tích: latency/throughput trade‑offs, cost estimation (KMS calls, HSM rents), and security posture (attack surface, vulnerability scenarios).

---

## 3. Relevance & Motivation

* Nền tảng mua sắm trực tuyến xử lý dữ liệu nhạy cảm (thông tin thanh toán, PII) và chịu nhiều rủi ro (fraud, account takeover, supply chain attacks). Thiết kế hệ thống an toàn theo nguyên tắc least‑privilege, defense‑in‑depth và tuân thủ chuẩn (PCI‑DSS, GDPR) là then chốt.

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Những điểm yếu mật mã (key management mistakes, token misuse, TLS misconfig, improper encryption at rest) nào thường dẫn đến compromise trong hệ thống thương mại điện tử?

**RQ2:** Chiến lược tokenization + attested key provisioning (e.g., device binding, TEE) có giảm đáng kể rủi ro gian lận thanh toán không trong khi vẫn chấp nhận được về latency?

**RQ3:** Độ hiệu quả của việc dùng HSM/KMS cho signing/payment keys so với software keys về mặt an ninh & chi phí?

**Giả thuyết:** Kết hợp tokenization (thay PAN bằng token), KMS/HSM cho signing & key wrapping, và mTLS/HMAC cho service‑to‑service giúp giảm đáng kể rủi ro; tuy nhiên mô hình này cần đánh đổi về độ trễ, phức tạp vận hành và chi phí.

---

## 5. Tổng quan kiến trúc & các thành phần hệ thống (System Components)

### 5.1. Frontend & Clients

* Web (SPA) with OAuth2/OIDC via Authorization Code + PKCE.
* Mobile (iOS/Android) native apps with secure storage (Keychain / Keystore) and attestation (SafetyNet/Device Check).

### 5.2. API Gateway & Edge

* API Gateway (Envoy/Kong) for TLS termination, JWT validation, rate limiting, request signing verification (HMAC), WAF rules, and authentication delegation to IdP.
* CDN for static assets; caching rules must avoid caching authenticated/private content.

### 5.3. Identity & Access

* Identity Provider (Keycloak/Auth0) for SSO, user management, MFA (TOTP, WebAuthn), and token introspection.
* OAuth2 scopes and RBAC for internal service access.

### 5.4. Microservices (sample services)

* Catalog Service (public read), Cart Service (user state, authenticated), Order Service (checkout orchestration), Payment Service (tokenization + gateway), Inventory, Shipping, Notification.
* Each service uses mTLS or mutual authentication for service‑to‑service calls and principle of least privilege.

### 5.5. Payment & Card Data Handling

* Payment Gateway integration (use test sandbox): implement tokenization flow (client obtains payment token via gateway SDK or server‑side tokenization), no PAN stored in own DB. 3DS / SCA flows for web checkout.
* License & PCI considerations: use gateway as PSP; if in‑house tokenization, ensure PCI‑DSS scope and use HSM for PAN encryption/wrapping.

### 5.6. Key Management & Secrets

* Cloud KMS (AWS/GCP/Azure) for key storage & envelope encryption; HSM for high‑value signing keys (code signing, payment key). Use Vault for secrets distribution in cluster.
* Rotations & key versioning automated with CI/CD hooks.

### 5.7. Data Storage & Encryption

* Database (Postgres) with TDE on disk + field‑level encryption for PII (email, address) and tokenized card references.
* Backups encrypted and keys managed via KMS with limited access.

### 5.8. Monitoring & Anti‑Fraud

* Telemetry pipelines (Kafka) for events, ML scoring service for fraud risk, rate limiting, anomaly detection (sudden high‑value orders, shipping address changes).
* Audit logs (append‑only, signed) stored for forensics and compliance.

### 5.9. CI/CD & Supply Chain Security

* Code signing (CI signs artifacts using HSM or signing keys), package verification in deployment, artifact provenance tracking (SBOM), and vulnerability scanning.

---

## 6. Kịch bản triển khai thực tế & tài nguyên (Deployment Scenarios & Resources)

### 6.1. Small‑scale / University lab (PoC)

* Kubernetes (k3s/minikube), 4–8 VMs, local KMS emulator (HashiCorp Vault), mock payment gateway sandbox, private Docker registry.
* Cost‑effective: use cloud free tiers or university hardware.

### 6.2. Production‑like (Cloud) deployment

* Cloud provider (AWS/GCP/Azure): managed KMS/HSM, managed DB, managed Kubernetes (EKS/GKE/AKS), CDN (CloudFront/Cloudflare), and PSP integration.
* Resources: autoscaling groups for services, load testing (JMeter), observability stack (Prometheus/Grafana, ELK), SRE runbooks.

### 6.3. High‑security deployment

* Use HSM appliances for payment key operations, isolated VPCs, dedicated signing hosts, strict IAM roles, and attestation/TPM for devices and set‑top boxes if applicable.

---

## 7. Phân tích rủi ro & weaknesses theo từng kịch bản thực tế (Weakness Analysis)

### 7.1. Token & session management

* **JWT misconfiguration:** long‑lived JWT with HS256 and shared secret leakage, or accepting alg\:none. Use short‑lived opaque tokens with refresh tokens stored securely and rotate secrets.
* **Refresh token theft:** refresh tokens must be revocable and bound to device (thumbprint) where possible; use refresh token rotation.

### 7.2. Payment & Card data

* **PAN exposure risk:** storing PAN or partial PAN without HSM and PCI controls leads to heavy compliance and risk. Prefer PSP tokenization and do not retain PAN.
* **Replay & double‑spend:** protect against replay of payment requests by nonce + idempotency keys and strict merchant order state machines.

### 7.3. API misuse & automated abuse

* **Credential stuffing & account takeover:** use rate limiting, MFA, device fingerprinting, and credential hygiene (bcrypt/argon2 + pepper).
* **API key leakage for internal services:** rotate keys, use short‑lived certs (mTLS), avoid static long‑lived tokens in code repos.

### 7.4. Key management & operational mistakes

* **Improper key rotation or expanded access:** principle of least privilege and breakglass procedures required; logging & alerting for key usage anomalies.
* **KMS calls cost & latency:** excessive KMS use per request (e.g., encrypting many fields synchronously) adds latency and cost — use envelope encryption and caching of unwrapped keys in secure memory for short duration.

### 7.5. CDN & caching pitfalls

* **Caching authenticated payloads:** misconfigured CDN can leak private content; ensure proper cache control and signed URLs for private assets.
* **Edge compromise exposing tokens:** avoid storing token material at edge; license servers should be centralized or use per‑edge attested mechanisms.

### 7.6. Supply chain & CI/CD risks

* **Compromised CI secrets:** employ ephemeral signing keys and HSM for signing artifacts; rotate keys and use signed SBOM to track provenance.

---

## 8. Methodology (Experiments & PoC plan)

### 8.1. Build the prototype

* Implement microservices (Catalog, Cart, Order, Payment) in containers; use API gateway (Envoy) and IdP (Keycloak). Integrate with mock PSP sandbox (Stripe test mode / Braintree sandbox). Use Vault as KMS emulator.

### 8.2. Security experiments

* **Experiment 1 — Token replay & binding:** obtain refresh/access token via legit flow, attempt replay from another device; test device binding and token rotation.
* **Experiment 2 — Payment fraud simulation:** simulate compromised card/token, test rate limiting, 3DS & SCA flows, and fraud scoring to block transactions.
* **Experiment 3 — API abuse & rate limiting:** run automated load & credential stuffing to test detection & mitigation (CAPTCHA, progressive delays, lockout).
* **Experiment 4 — Key compromise & rotation drills:** simulate KMS key compromise, perform rotation & validate rollback/recovery procedures.
* **Experiment 5 — Supply chain tamper:** inject modified artifact in CI pipeline (in lab) to validate artifact verification & deployment gating.

### 8.3. Performance experiments

* Measure added latency from KMS calls (envelope encryption vs direct), license/token issuance latency, overall checkout latency, and throughput under concurrent checkouts.

---

## 9. Evaluation Plan & Metrics

* **Security metrics:** fraction of successful replay/fraud attempts under test; time to detect & respond; number of incidents allowed.
* **Performance metrics:** checkout latency median/p95/p99, KMS call rates & cost per 10k requests, system throughput.
* **Operational metrics:** time to rotate keys & redeploy, MTTR for security incidents, false positive rates for fraud detection.

---

## 10. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Requirements & threat model, choose stack, provision lab infra.
* **Tuần 3–4:** Implement microservices skeleton, API gateway & IdP (Keycloak).
* **Tuần 5–6:** Implement payment integration with tokenization (PSP sandbox), KMS/Vault integration, DB encryption.
* **Tuần 7–8:** Implement anti‑fraud ML scoring stub, monitoring & logging pipelines; run baseline functional tests.
* **Tuần 9:** Security experiments (token replay, API abuse, payment fraud simulations).
* **Tuần 10:** Operational drills (key rotation, incident response), performance tuning.
* **Tuần 11:** Aggregate results, ablation studies, cost analysis.
* **Tuần 12:** Final report, reproducible repo (Docker Compose / Helm), slides & demo.

---

## 11. Deliverables

1. **Mid‑term:** architecture docs, PoC skeleton, initial security plan.
2. **Final report:** design, experiments, results, mitigations & runbooks.
3. **Code repo:** microservices, API gateway configs, Keycloak realm export, Vault scripts, PSP sandbox integration, test harnesses.
4. **Artifacts:** logs, CSVs of experiments, dashboard screenshots, cost model.
5. **Demo video:** show end‑to‑end checkout and at least two security experiments (token replay blocked, payment fraud detection).

---

## 12. Assessment & Rubric (gợi ý)

* Architecture & security design: 30%
* Implementation & reproducibility (PoC): 25%
* Experimental rigor & analysis: 25%
* Documentation, runbooks & presentation: 20%

---

## 13. Risks, Limitations & Ethical Considerations

* **Payment integrations:** use only sandbox/test modes; do not process real card data except test numbers.
* **User data privacy:** simulate PII or use synthetic data; follow GDPR guidelines for telemetry.
* **Dual‑use experiments:** do not target external systems; run all attacks in lab environment.

---

## 14. Mitigations & Best Practices (summary recommendations)

* **Tokenization & no PAN retention:** use PSP tokenization; if in‑house, use HSM and strict PCI controls.
* **Short‑lived tokens & device binding:** prefer opaque short tokens, refresh rotation, and bind refresh tokens to device.
* **Envelope encryption & caching:** minimize KMS calls per request via short‑lived unwrapped keys in secure memory; use envelope encryption at rest.
* **mTLS & HMAC for internal APIs:** all service‑to‑service calls authenticated & authorized; avoid static secrets in repos.
* **Monitor & ML scoring for fraud:** telemetry + thresholds + human review for suspicious orders.
* **Supply chain security:** artifact signing, SBOMs, CI secrets management.

---

## 15. Tools & Resources gợi ý

* **Frameworks & infra:** Kubernetes (k3s/EKS), Envoy/Kong, Keycloak, HashiCorp Vault, PostgreSQL, Kafka.
* **Payment sandbox:** Stripe/Braintree sandbox, 3DS test sandbox.
* **Testing & monitoring:** JMeter/wrk, Prometheus/Grafana, ELK, Sentry.
* **Security tooling:** OWASP ZAP, Burp, security scanners, dependency scanners (Snyk, Dependabot).

---

## 16. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ infra/              # docker‑compose / helm charts for k8s
  ├─ services/           # catalog/, cart/, order/, payment/ microservices
  ├─ gateway/            # envoy/kong configs + TLS certs (dev)
  ├─ idp/                # Keycloak realm export + scripts
  ├─ vault/              # Vault policies, secrets engines, encryption scripts
  ├─ experiments/        # replay_tests/, fraud_sim/, key_rotation_drill/
  ├─ benchmarks/         # load tests, raw csvs, analysis notebooks
  └─ docs/               # report, runbooks, slides, demo video
```

---