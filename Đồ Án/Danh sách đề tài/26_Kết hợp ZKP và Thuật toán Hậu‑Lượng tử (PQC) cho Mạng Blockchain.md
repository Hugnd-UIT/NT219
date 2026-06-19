# Capstone Project — Kết hợp ZKP và Thuật toán Hậu‑Lượng tử (PQC) cho Mạng Blockchain

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Integrate ZKP (Zero‑Knowledge Proofs) và các thuật toán Post‑Quantum Cryptography cho Mạng Blockchain — thiết kế, triển khai và đánh giá lộ trình chuyển đổi an toàn cho hệ thống phân tán

---

## 1. Tóm tắt đề tài (Project Synopsis)

Mục tiêu: nghiên cứu và triển khai một prototype blockchain/sidechain/L2 proof‑system *được thiết kế để chịu được cuộc tấn công lượng tử trong tương lai* bằng cách kết hợp:

* **ZKP** an toàn (ví dụ: zk‑STARKs để có tính kháng lượng tử cho lớp bằng chứng),
* **PQC** cho chữ ký & trao đổi khóa (ví dụ: CRYSTALS‑Dilithium / SPHINCS+ cho chữ ký; CRYSTALS‑Kyber cho khóa tạm thời / KEM),
* **Crypto‑agility** và lộ trình chuyển đổi hybrid (ECDSA/Schnorr + PQC) để giảm gián đoạn.

Sinh viên sẽ thiết kế kiến trúc, triển khai PoC (ví dụ: đơn giản blockchain node + validator signatures thay thế bằng PQC, zk‑based privacy/rollup module), đo hiệu năng (TPS, kích thước block, latency), phân tích ảnh hưởng lên kích thước chuỗi & chi phí gas, và đưa ra khuyến nghị migration plan cho mạng thực tế.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu khác biệt giữa các hệ chứng minh zero‑knowledge (zk‑SNARK vs zk‑STARK) và hậu‑lượng tử hóa (POST‑quantum).
2. Triển khai & so sánh PQC signatures (Dilithium, SPHINCS+, FALCON) trên client & validator; tích hợp KEM (Kyber) cho kênh tin cậy tạm thời.
3. Thiết kế mô hình hybrid‑migration (dual‑signatures, aggregated proofs, threshold signing) giúp backward compatibility.
4. Đo lường tác động thực tế: kích thước tx, kích thước block, throughput, chi phí lưu trữ & băng thông, và latency xác nhận.
5. Viết runbook migration (key rotation, replay protection, fallback) và mô tả trade‑offs an ninh / hiệu năng.

---

## 3. Tính cấp thiết & động lực (Relevance)

* Chuỗi khối công cộng và nhiều hệ thống permissioned hiện đang dựa vào RSA/ECC (ECDSA, Schnorr) cho chữ ký giao dịch và bằng chứng. Những primitives này có thể bị phá vỡ bởi máy lượng tử mạnh (Shor).
* Chuyển đổi sớm có lợi cho dữ liệu 'harvest now, decrypt later' và giữ an toàn dài hạn cho tài sản on‑chain.

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Việc thay thế chữ ký ECC bằng chữ ký hậu‑lượng tử (Dilithium, SPHINCS+) ảnh hưởng như thế nào đến throughput, kích thước chuỗi và chi phí lưu trữ ở các mạng blockchain (permissionless vs permissioned)?

**RQ2:** ZK‑proofs dựa trên hàm băm (zk‑STARKs) có thể đóng vai trò như lớp tính toán chứng minh *post‑quantum‑secure* cho rollups/zkVM — chi phí kiểm tra & kích thước bằng chứng có thể chấp nhận được không?

**Giả thuyết:** Kết hợp zk‑STARKs cho lớp bằng chứng với PQC cho chữ ký giao dịch cho phép migration đảm bảo kháng lượng tử; trade‑offs: tăng kích thước tx và chi phí xác minh (gas) nhưng có thể chấp nhận cho L2/rollup hoặc permissioned chains; hybrid dual‑signature (ECC + PQC) cho phép chuyển đổi có thể thực hiện dần.

---

## 5. Nền tảng & tài liệu tham khảo ngắn (Background)

* **ZK families:** zk‑SNARKs thường dựa trên cấu trúc nhóm/elliptic‑curve; nhiều SNARKs không kháng lượng tử. zk‑STARKs xây dựng trên hàm băm và PCP/ILS và được coi là có tính kháng lượng tử hơn.
* **PQC standardization:** NIST đã chuẩn hóa/đề xuất các thuật toán PQC (CRYSTALS‑KYBER, CRYSTALS‑Dilithium, SPHINCS+, FALCON) làm lựa chọn chính cho KEM & signatures.

> (Tài liệu nền tảng, ví dụ: NIST PQC; StarkWare về STARKs — tài liệu tham khảo được kèm trong chat sau khi file được tạo).

---

## 6. Thành phần hệ thống & tài nguyên (System Components & Resources)

### 6.1. Thành phần chính (kiến trúc prototype)

* **Node / Full node:** hỗ trợ TX creation, verify signatures (PQC &/or hybrid), mempool, block propagation.
* **Validator / Miner:** signing blocks with PQC keys or threshold PQC scheme (BLS analogues for PQC are nontrivial).
* **Light client & Wallets:** tạo tx, tích hợp PQC signature libs (reference libs CRYSTALS‑Dilithium, SPHINCS+); dual‑sig UX for hybrid mode.
* **ZK proof module (offchain prover / onchain verifier):** prover tạo zk‑STARK/zk‑SNARK cho rollup batches; verifier onchain (smart contract) chạy verify.
* **Key management:** HSM / KMS for validator key storage; wallet key storage with PQC libs & secure elements.
* **Interop & migration layer:** node logic for validating transactions signed by legacy ECC, PQC, or dual signatures; state machine migrate tool.

### 6.2. Hạ tầng & phần cứng tham khảo

* Máy dev & testnet: 4–8 vCPU, 16–64GB RAM cho prover; SSD for-store proofs & chain.
* HSM or Cloud KMS for validator keys (FIPS/PKCS#11 support for PQC libs).
* Network: high bandwidth for proof upload/download (STARK proofs có kích thước lớn hơn SNARKs).

---

## 7. Kịch bản triển khai thực tế (Deployment Scenarios)

### 7.1. Permissioned Consortium Chain (ngân hàng, liên tổ chức)

* Tập hợp nhỏ validator có thể chấp nhận overhead lớn hơn; dễ áp dụng threshold PQC & provider HSM.
* Migration: thay validator signing key sang Dilithium + zk‑STARK based validity proofs cho cross‑ledger settlement.

### 7.2. Public L1 with zk‑rollup L2

* L1 giữ bảo mật & backwards compatibility (hybrid signatures); L2/rollup dùng zk‑STARK proofs (post‑quantum) cho batch validity; L1 smart contract cần verify STARK proofs (chi phí gas & calldata tăng).

### 7.3. Wallet Ecosystem Migration

* Wallets hỗ trợ dual‑sig (user signs tx bằng ECC và PQC) hoặc sign‑then‑encapsulate model: PQC‑signature included as additional field to allow future-proof verification.

---

## 8. Phân tích điểm yếu & rủi ro (Weakness Analysis)

### 8.1. Kích thước chữ ký & bloat chain

* PQC signatures (không phải tất cả) lớn hơn ECC; SPHINCS+ signature sizes có thể vài KB → tăng kích thước block, chi phí lưu trữ & truyền.

### 8.2. Xác minh & hiệu năng

* Verification cost tăng trên nodes nhẹ; verifier smart contract (EVM) có giới hạn gas — onchain verify PQC hoặc STARK verification code có thể tốn kém.

### 8.3. Aggregation & threshold signing khó khăn

* Nhiều giao thức tổng hợp chữ ký (BLS) dựa trên pairing groups không tương thích với hầu hết PQC schemes; xây dựng threshold/multi‑signature PQC cần nghiên cứu thêm hoặc dùng hybrid MPC.

### 8.4. Proof sizes & prover resources

* zk‑STARK proofs lớn và prover CPU‑intensive; cần kết hợp prover pools hoặc trusted‑prover farms (tuy nhiên trust giảm).

### 8.5. Crypto‑agility implementation bugs

* Migration logic (dual‑sig, replay protection, key rotation) dễ sai — ví dụ chấp nhận tx có signature cũ/chữ ký mới sai lệch làm mở cửa cho replay/phishing.

---

## 9. Methodology (PoC Plan & Experiments)

Sinh viên nên chia PoC thành ba tracks: *signatures*, *ZK proofs*, *migration & integration*.

### 9.1. Track A — PQC Signatures for transactions

* Implement node+wallet where transactions can be signed with Dilithium and/or SPHINCS+ (use reference libs). Measure:

  * tx size delta (bytes),
  * CPU cost for sign/verify (ms),
  * mempool throughput & TPS impact.

### 9.2. Track B — ZK proof module

* Build minimal rollup prover that batches transactions and generates zk‑STARK proofs (or use an existing STARK lib). Onchain verifier is a simple smart contract that accepts proof and applies state transition. Measure:

  * proof generation time per batch,
  * proof size (bytes),
  * gas cost to verify (if on EVM) or verifier cost on L1.

### 9.3. Track C — Migration & hybrid modes

* Implement hybrid acceptance rules: node validates ECC only, PQC only, or both (dual‑sig). Test migration scenarios: soft fork (accept new PQC txs), hard fork (require PQC), and dual‑sig rollout. Tests:

  * backward compatibility, replay protection,
  * key rotation procedure & emergency rollback,
  * validator consensus with PQC keys (use HSM simulation).

### 9.4. Additional experiments

* Simulate economic cost: per‑block storage increase → node disk/ bandwidth cost; gas cost estimation for L1 calldata increases.
* Evaluate threshold signing approaches: simulate an MPC sign (e.g., FROST‑like) vs HSM threshold—compare latency.

---

## 10. Evaluation Plan & Metrics

* **Security:** ability to resist known classical & quantum attacks (qualitative), correctness of verification, key compromise test.
* **Performance:** sign/verify latency, prover time, proof size, TPS, mempool latency.
* **Operational:** storage growth per day, bandwidth, validator CPU/RAM requirements, HSM integration complexity.
* **Usability:** wallet UX (dual‑sig friction), migration friction measured by sample user tests.

---

## 11. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Literature review (PQC, zk families), choose libs (Dilithium/Kyber/SPHINCS+, STARK lib), provision infra.
* **Tuần 3–4:** Implement PQC signing in wallet & node; baseline sign/verify benchmarks.
* **Tuần 5–6:** Implement ZK‑rollup prover (STARK) prototype & simple onchain verifier; measure proof sizes & costs.
* **Tuần 7–8:** Integrate hybrid validation rules; simulate testnet with both ECC & PQC txs; implement key rotation tests.
* **Tuần 9:** Run stress tests for TPS, storage & bandwidth; measure prover pool scaling.
* **Tuần 10:** Simulate threshold signing/MPC fallback and HSM integration.
* **Tuần 11:** Security evaluation & leakage analysis; prepare mitigation & migration playbook.
* **Tuần 12:** Final report, reproducible repo (Docker & scripts), slides & demo video.

---

## 12. Deliverables

1. **Mid‑term:** architecture diagram, chosen libs, minimal PQC sign/verify PoC.
2. **Final report:** experiments, metrics, migration playbook & security analysis.
3. **Code repo:** node/wallet PoC, prover & verifier code, testnet scripts, HSM simulation.
4. **Artifacts:** benchmark CSVs, proof files, gas cost estimates, demo video.
5. **Policy checklist:** crypto‑agility checklist & recommended migration phases.

---

## 13. Assessment & Rubric (gợi ý)

* Correctness & security design: 30%
* Implementation & reproducibility (PoC quality): 30%
* Experimental analysis & insights (trade‑offs): 25%
* Documentation & presentation: 15%

---

## 14. Risks, Limitations & Ethical Considerations

* **Resource intensity:** STARK proving & some PQC ops heavy — test on limited datasets and report scaling.
* **Chain fragmentation risk:** poorly designed migration can split network; follow established migration governance (EIPs, upgrade proposals).
* **Legal & economic:** gas cost increases affect users; evaluate cost allocation.
* **Responsible disclosure:** if discover weak implementations in PQC libs, follow coordinated disclosure.

---

## 15. Mitigations & Best Practices (summary recommendations)

* **Hybrid dual‑signature rollout:** begin with dual‑sig mode (ECC + PQC) so clients/validators can migrate gradually.
* **Use STARKs for post‑quantum ZK proofs:** where ZK is needed and post‑quantum resilience is a goal, prefer STARKs or lattice‑based ZK research variants.
* **Careful parameter choice & testing:** measure real signature sizes & verification cost for chosen PQC algorithms before commit.
* **Threshold signing / HSM:** use threshold signing or HSMs for validator keys to reduce single‑point compromise.
* **Crypto‑agility:** design codepaths for multiple algorithms, feature flags, and clear key‑rotation & revocation procedures.

---

## 16. Tools & Resources gợi ý

* **PQC libs:** liboqs (Open Quantum Safe), reference CRYSTALS‑Dilithium/Kyber implementations, SPHINCS+ reference code.
* **ZK libs & stacks:** libSTARK / StarkWare resources, Cairo/Starknet demos, zkSTARK libs or academic implementations.
* **Blockchain frameworks:** Geth/parity forks for testnet, Substrate (Polkadot) for rapid chain prototyping.
* **HSM & KMS:** SoftHSM for dev, AWS CloudHSM for cloud tests.
* **Bench & infra:** Docker, Kubernetes, load generators, profiling tools.

---

## 17. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ node/               # forked testnode with PQC verify hooks
  ├─ wallet/             # wallet code with PQC signing (Dilithium/SPHINCS+), dual‑sig support
  ├─ prover/             # STARK prover / batcher
  ├─ verifier/           # onchain verifier contract & test harness
  ├─ hsm/                # HSM integration & PKCS#11 stubs (SoftHSM)
  ├─ benchmarks/         # scripts, raw CSVs, plots
  └─ docs/               # report, migration playbook, slides, demo
```

---

*Ghi chú cho sinh viên:* Kết quả PoC cần ghi rõ các tham số: phiên bản thư viện PQC, độ an toàn (bits), kích thước chữ ký & bằng chứng, và phân biệt rõ phần nào là 'simulation' (ví dụ threshold signing) so với thử nghiệm thực tế với HSM.

---
