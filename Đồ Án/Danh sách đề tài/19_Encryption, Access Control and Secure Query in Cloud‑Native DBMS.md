# Capstone Project — Encryption, Access Control & Secure Query in Cloud‑Native DBMS

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Encryption, Access Control, and Secure Query in Cloud‑Native DBMS — Thiết kế, triển khai và đánh giá các giải pháp bảo vệ dữ liệu và thực thi truy vấn an toàn cho hệ quản trị cơ sở dữ liệu cloud‑native

---

## 1. Tóm tắt đề tài (Project Synopsis)

Đề tài nghiên cứu các phương pháp bảo vệ dữ liệu trong hệ quản trị cơ sở dữ liệu **cloud‑native** (managed DB & distributed SQL/NoSQL): **mã hoá ở nghỉ (TDE, field‑level, columnar), mã hoá bên khách (client‑side encryption), searchable/functional encryption (SSE, OPE, FHE), và kỹ thuật dựa trên TEE/MPC để chạy truy vấn trên dữ liệu được mã hoá**. Sinh viên sẽ thiết kế nhiều kiến trúc triển khai (client‑side encryption + policy service, SSE index, TEE‑backed query engine, hybrid approaches), triển khai các prototype, đo hiệu năng/chi phí, phân tích rò rỉ thông tin (leakage) thực tế, và đề xuất khuyến nghị kỹ thuật‑vận hành để áp dụng trong sản xuất.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu các mô hình mã hoá cho DB: TDE, column/field encryption, deterministic & randomized encryption, order‑preserving/deterministic encryption, format‑preserving; ưu‑nhược về bảo mật và khả năng truy vấn.
2. Nắm các kỹ thuật cho truy vấn trên dữ liệu đã mã hoá: Searchable Symmetric Encryption (SSE), Deterministic/Order‑Preserving Encryption (DTE/OPE), Homomorphic Encryption (FHE/HEAAN), Secure Enclave (SGX/Nitro Enclaves), and MPC primitives; trade‑offs hiệu năng vs leakage.
3. Thiết kế & triển khai chính sách truy cập: RBAC/ABAC cho hàng/cột, row‑level security, attribute‑based encryption (ABE) cho chia sẻ dữ liệu.
4. Triển khai PoC: tích hợp client‑side encryption với PostgreSQL/CockroachDB/MongoDB, SSE index cho full‑text search, hoặc TEE‑based secure query prototype (SQLite/duckDB in SGX).
5. Phân tích leakage: frequency, access pattern, order, size & timing; đề xuất mitigations (padding, ORAM, result batching, differential privacy).

---

## 3. Tính cấp thiết & động lực (Relevance)

* Nhiều tổ chức chuyển dữ liệu lên cloud nhưng lo ngại rủi ro thuê ngoài (honest‑but‑curious cloud operators, compromised admins). Cần giải pháp cho truy vấn hữu dụng trong khi bảo đảm confidentiality.
* Áp dụng đúng loại mã hoá và truy vấn an toàn giúp tuân thủ quy định (GDPR, HIPAA) và giảm rủi ro rò rỉ dữ liệu nhạy cảm.

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Các kỹ thuật mã hoá & query‑over‑encrypted-data (SSE, OPE, FHE, TEE) mang lại mức bảo mật / leakage nào trong bối cảnh triển khai cloud‑native?

**RQ2:** Chiến lược kết hợp (ví dụ: client‑side deterministic encryption cho key columns + SSE index cho search + TEE cho aggregations) có thể cân bằng tốt giữa tính thực dụng và bảo mật không?

**RQ3:** Chi phí (latency, throughput, storage, operational complexity) để triển khai một hệ DB bảo mật so với DB truyền thống là bao nhiêu?

**Giả thuyết:** Một hybrid approach (client‑side encryption + SSE for search + enclave for heavy compute) thường là realistic cho nhiều workloads: SSE cho text search, deterministic encryption cho joins, TEE/FHE cho 1–2 heavy aggregations; toàn bộ FHE cho OLTP chưa practical.

---

## 5. Background (Tổng quan ngắn)

* **Encryption at rest (TDE)**: mã hoá file/volume, bảo vệ dữ liệu nếu đĩa bị lộ nhưng không bảo vệ khỏi admin cloud.
* **Field/column encryption:** cho phép hạn chế rủi ro khi chỉ mã hoá cột nhạy cảm; cần thiết cho partial queries.
* **Deterministic vs randomized encryption:** deterministic cho phép equality search nhưng rò rỉ frequency; randomized (non‑deterministic) bảo mật hơn nhưng không hỗ trợ equality.
* **SSE (Searchable Symmetric Encryption):** index + tokens cho phép search từ khóa mà server không biết plaintext (có leakage như access pattern).
* **Order‑preserving encryption (OPE)/Order‑revelation:** cho phép range queries nhưng rò rỉ order relations và distribution.
* **FHE:** hỗ trợ tính toán trực tiếp trên ciphertext nhưng chi phí tính toán rất lớn (hiện tại limited to specific workloads).
* **TEE / Enclave:** chạy plaintext processing inside secure hardware (SGX, Nitro Enclaves); trade‑off: smaller TCB, but side‑channel & attestation concerns.

---

## 6. Literature review & tools (hướng khảo sát)

* Hệ thống tiền bối: **CryptDB**, **Monomi** (query rewriting), **Cipherbase**, **Mylar** (client‑side encryption), **SEAL / HEAAN** (FHE libraries), **Open Enclave / Graphene / Gramine** for enclave apps.
* SSE literature: Curtmola et al., Bost et al. (OXT), leakage profiles.
* ORAM and its overhead; differential privacy for query result release.

> Yêu cầu: sinh viên trích ít nhất 6 paper/tech reports và 3 codebases (CryptDB forks, SEAL/HEAAN, PQClean not needed here).

---

## 7. Thành phần hệ thống & tài nguyên (System Components & Resources)

### 7.1. Thành phần chính

* **Client SDK / Middleware:** thực hiện client‑side encryption, token generation, access control checks, và giao tiếp với key service.
* **Key Management Service (KMS):** quản lý master keys, hỗ trợ envelope encryption, key rotation, HSM/Cloud KMS (AWS KMS, Cloud HSM).
* **Policy & Access Control Service:** RBAC/ABAC engine, policy decision point (PDP) and enforcement point (PEP).
* **DBMS (cloud‑native):** PostgreSQL/CockroachDB/TiDB (SQL), MongoDB/DocumentDB (NoSQL) with plugin/hooks or proxy to handle encrypted fields and SSE indexes.
* **Indexing & SSE Service (optional):** outsourced index server storing encrypted indexes and handling search tokens.
* **Enclave Service (optional):** SGX/Nitro Enclave node running secure query execution (for aggregation/joins).
* **Audit & Monitoring:** logging, query analytics (to quantify leakage), SIEM.

### 7.2. Hạ tầng & tài nguyên

* Kubernetes cluster (GKE/EKS), managed DB instances, VMs with SGX or Nitro for enclave experiments, KMS (cloud or HashiCorp Vault with HSM), load generators, storage for indexes and ORAM structures.

---

## 8. Kịch bản triển khai thực tế & Weakness Analysis (Deployment Scenarios)

### 8.1. Managed DB as a Service (Cloud RDS/Cockroach)

* **Threats:** cloud DB admin can access plaintext in DB memory/disk unless client‑side encryption or enclave used. Metadata & query logs leaked.
* **Weaknesses:** reliance on TDE insufficient; index leakage (deterministic columns) reveals frequency; query patterns leak access correlation.

### 8.2. Multi‑tenant distributed SQL (CockroachDB, Spanner) in shared infra

* **Threats:** co‑tenant side‑channels, backup snapshots exposing ciphertext & metadata, replication/logging exposing query patterns.
* **Weaknesses:** ORAM expensive; row‑level encryption challenges joins and transactions; key distribution complexity for multi‑tenant schemas.

### 8.3. Edge caching & analytics pipelines

* **Threats:** analytics engines ingesting encrypted data may leak aggregates; data movement to analytics services increases exposure.
* **Weaknesses:** transferring ciphertext + index tokens opens up additional attack surfaces if tokens reused or compromise of index server.

### 8.4. Compliance/Forensics requirements

* **Trade‑offs:** strong encryption may hinder auditing & lawful access; must design controlled decryption paths (key escrow, threshold decryption with audit).

---

## 9. Methodology (Design options & Experiments)

Sinh viên chọn một hoặc nhiều kiến trúc để triển khai và đánh giá. Dưới đây là các phương án gợi ý và kịch bản thí nghiệm tương ứng.

### 9.1. Kiến trúc A — Client‑side encryption + deterministic columns

* **Mô tả:** client mã hoá cột nhạy cảm (email, ssn) bằng deterministic encryption để hỗ trợ equality joins/search; KMS quản lý master key; DB lưu ciphertext.
* **Thí nghiệm:** đo overhead insert/select, đánh giá leakage frequency bằng phân tích phân phối ciphertext, thử tấn công thống kê để khôi phục phổ biến plaintext (nếu corpus predictable).

### 9.2. Kiến trúc B — SSE index for full‑text search

* **Mô tả:** xây dựng SSE index server (OXT or Bost et al. protocols) để hỗ trợ search tokens; DB stores encrypted docs and index pointers.
* **Thí nghiệm:** benchmark search latency/throughput, measure leakage via access pattern (simulate repeated queries), test forward/backward privacy variants.

### 9.3. Kiến trúc C — TEE‑backed secure query engine

* **Mô tả:** deploy an enclave that receives encrypted blobs, fetches wrapped keys from KMS after attestation, performs decrypt & query in enclave, returns encrypted results.
* **Thí nghiệm:** implement small SQL engine (SQLite/duckDB) inside SGX or use Nitro Enclave; measure attestation overhead, per‑query latency, throughput; analyze side‑channel leakage & required mitigations.

### 9.4. Kiến trúc D — Hybrid: deterministic keys + enclave for aggregations

* **Mô tả:** equality joins on deterministic columns client‑side; heavy aggregations (SUM/AVG) inside enclave.
* **Thí nghiệm:** compare hybrid to pure enclave and pure client‑side for latency & leakage; evaluate practicality for typical OLAP queries.

### 9.5. Optional advanced experiments — FHE for aggregation

* **Mô tả:** use CKKS/HEAAN for approximate aggregations (sum, mean) on encrypted numeric columns.
* **Thí nghiệm:** implement small prototype for SUM on encrypted salaries, measure compute cost and accuracy vs plaintext baseline.

---

## 10. Implementation & Tools

* **DBs:** PostgreSQL (column encryption extensions like pgcrypto), CockroachDB (distributed SQL), MongoDB (client‑side Field Level Encryption).
* **SSE libs & tools:** OXT implementations, PySSE, OpenSearch with encrypted index prototypes.
* **FHE libs:** Microsoft SEAL, HEAAN/CKKS.
* **Enclave frameworks:** Open Enclave, Gramine, Nitro Enclaves SDK.
* **KMS & secrets:** AWS KMS / Cloud HSM, HashiCorp Vault.
* **Measurement:** JMeter/wrk/pgbench, Prometheus/Grafana for metrics.
* **Leakage analysis:** statistical analysis with Python (pandas, scipy), frequency histogram & attack scripts.

---

## 11. Evaluation Plan & Metrics

* **Performance:** latency (median/p95/p99) for common queries (point lookup, range query, full‑text search, aggregation), throughput (QPS), CPU & memory, storage overhead (index size).
* **Security / Leakage:** leakage catalogue (equality, order, frequency, access pattern, size/timing); success of reconstruction or inference attacks; measure forward/backward privacy for SSE.
* **Operational:** cost model (KMS calls, enclave instances), key rotation impact, complexity of deployment & dev ergonomics.
* **Accuracy (for FHE):** numerical error vs plaintext.

---

## 12. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Literature review, choose use cases (OLTP vs OLAP), pick DB & tech stack, provision lab infra.
* **Tuần 3–4:** Implement baseline DB & client SDK (no encryption) and workload generator.
* **Tuần 5–6:** Implement Architecture A (client‑side deterministic encryption) and run benchmarks + leakage analysis.
* **Tuần 7–8:** Implement Architecture B (SSE index) and measure search performance & leakage; optionally integrate forward/backward privacy variant.
* **Tuần 9–10:** Implement Architecture C (TEE‑backed secure queries) or hybrid approach; measure attestation & per‑query costs.
* **Tuần 11:** Compare results, run ablation (vary parameters: deterministic vs randomized, index size, enclave batching), finalize mitigations.
* **Tuần 12:** Final report, reproducible repo (Docker/K8s), slides & demo video.

---

## 13. Deliverables

1. **Mid‑term:** architecture selection, lab setup, baseline benchmarks.
2. **Final report (PDF/MD):** methodology, experiments, leakage analysis, recommendations for deployment.
3. **Code repository:** client SDKs, DB configs, SSE index code, enclave images (if used), benchmark scripts.
4. **Data & artifacts:** raw CSVs, plots, attack scripts, processed logs.
5. **Demo:** recorded demo showing end‑to‑end encrypted query (search/lookup/aggregate) and one leakage demonstration (e.g., frequency inference).

---

## 14. Assessment & Rubric (gợi ý)

* Problem framing & literature grounding: 20%
* Implementation & reproducibility: 25%
* Experimental rigor & leakage analysis: 30%
* Practical recommendations & documentation: 15%
* Presentation & demo quality: 10%

---

## 15. Risks, Limitations & Ethical Considerations

* **Dual‑use / privacy:** leakage experiments must use synthetic or consented datasets; do not attempt to reconstruct real personal data.
* **Hardware availability for enclaves:** SGX/Nitro might be limited — simulation allowed but must be labeled.
* **FHE computation cost and energy:** limit experiments to small datasets and explain scalability limits.

---

## 16. Mitigations & Best Practices (summary recommendations)

* **Apply client‑side encryption for highly sensitive fields** and use deterministic only when acceptable (after risk assessment).
* **Prefer SSE with forward/backward privacy** for search if access pattern leakage unacceptable; otherwise accept trade‑offs.
* **Use enclaves for limited trusted compute** (aggregations, joins) and combine with audit & side‑channel mitigations.
* **Key management & envelope encryption:** centralize keys in KMS/HSM, minimize number of unwraps, implement short‑lived unwrapped keys in secure memory.
* **Audit & monitoring:** continuously measure access patterns and deploy anomaly detection to detect inference attempts.
* **Documentation & policy:** document leakage profiles and train developers to choose appropriate primitives.

---

## 17. Extensions & Future Work

* Automated tool to estimate leakage for a given schema & workload (static + dynamic analysis).
* Integration with differential privacy for open analytics queries.
* Explore combining ORAM+TEE for transactional workloads at scale (research prototype).

---

## 18. Tools & Resources gợi ý

* PostgreSQL + pgcrypto, CockroachDB, MongoDB Field Level Encryption, CryptDB papers & code, Microsoft SEAL, Open Enclave / Gramine, AWS Nitro Enclaves, HashiCorp Vault, Prometheus/Grafana, fplll not required here.

---

## 19. Appendix: Repository Structure (mẫu)

```ini
project-root/
  ├─ infra/              # docker-compose / k8s manifests for DB, KMS, enclave nodes
  ├─ client-sdk/         # encryption SDKs, deterministic & randomized modes
  ├─ sse-index/          # SSE server & index build scripts
  ├─ enclave/            # SGX/Nitro enclave code (if any)
  ├─ benchmarks/         # workload generators, raw csv outputs
  ├─ attacks/            # leakage analysis & inference scripts
  └─ docs/               # report, slides, demo scripts
```

---
