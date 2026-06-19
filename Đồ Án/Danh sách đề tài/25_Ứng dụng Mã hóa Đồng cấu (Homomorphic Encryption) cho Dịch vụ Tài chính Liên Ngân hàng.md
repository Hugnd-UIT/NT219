# Capstone Project — Ứng dụng Mã hóa Đồng cấu (Homomorphic Encryption) cho Dịch vụ Tài chính Liên Ngân hàng

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Ứng dụng Homomorphic Encryption (HE/FHE) để thực hiện xử lý, phân tích và mô hình hóa tài chính giữa nhiều ngân hàng mà vẫn bảo vệ tính riêng tư dữ liệu (Interbank Privacy‑Preserving Analytics & Clearing)

---

## 1. Tóm tắt đề tài (Project Synopsis)

Mục tiêu của đề tài là nghiên cứu và thực nghiệm **giải pháp dùng Homomorphic Encryption (HE/FHE)** trong các kịch bản liên ngân hàng: tổng hợp rủi ro tín dụng, tính toán phơi nhiễm (exposure aggregation), cảnh báo thanh khoản, phân tích chống rửa tiền/giả mạo giao dịch phối hợp, và chạy các mô hình ML phân tích rủi ro trên dữ liệu được mã hóa. Sinh viên sẽ thiết kế kiến trúc end‑to‑end (banks → secure evaluator → regulator/clearing), triển khai PoC với thư viện HE (ví dụ Microsoft SEAL / PALISADE / TenSEAL / Lattigo), thực hiện benchmark về độ chính xác (CKKS), hiệu năng, băng thông, phân tích rò rỉ thông tin (result‑leakage), và đề xuất chiến lược triển khai thực tế (multi‑key HE, threshold decryption, hybrid HE+TEE/MPC).

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Nắm vững lý thuyết nền tảng của HE/FHE: học LWE/ RLWE, encoding/packing (batching), ciphertext levels, noise growth, relinearization, Galois rotations, bootstrapping.
2. Hiểu sự khác biệt giữa các sơ đồ: BFV/BGV (số nguyên), CKKS (số thực xấp xỉ), multi‑key HE, threshold HE, và trade‑offs bảo mật/hiệu năng.
3. Thiết kế kiến trúc privacy‑preserving cho interbank workflows: public key distribution, evaluation key management, decryption policy, and auditability.
4. Triển khai PoC: encrypt dữ liệu mẫu của nhiều ngân hàng, chạy các phép toán (sum, dot‑product, polynomial evaluation), triển khai inference cho mô hình ML (logistic regression hoặc neural net inference trên CKKS), và測 thử trên môi trường cluster.
5. Phân tích rủi ro: kết quả trả về có thể rò rỉ thông tin, parameter selection, implementation bugs, và đề xuất mitigations (differential privacy, output clipping, query budgets).

---

## 3. Tính cấp thiết & động lực (Relevance)

* Ngân hàng và tổ chức thanh toán cần phối hợp để đánh giá rủi ro hệ thống, phòng ngừa rủi ro chéo, và thực hiện các dịch vụ bù trừ (clearing) — tuy nhiên dữ liệu giao dịch, số dư và danh sách khách hàng là cực kỳ nhạy cảm.
* HE/FHE hứa hẹn cho phép thực hiện tính toán hữu ích trên dữ liệu mã hóa, giảm rào cản chia sẻ dữ liệu nhạy cảm giữa ngân hàng mà không cần tiết lộ bản gốc.

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Trong các kịch bản liên ngân hàng điển hình (tổng hợp exposure, tính toán VAR, inference mô hình ML), HE (đặc biệt CKKS cho số thực) có thể cung cấp độ chính xác và hiệu năng chấp nhận được để triển khai pilot không?

**RQ2:** Hình thức khóa & kiến trúc nào giảm rủi ro tiết lộ mà vẫn cho phép evaluator tính toán (multi‑key HE, threshold HE, dùng TEE, hoặc kết hợp)?

**Giả thuyết:** Với CKKS và packing/batching hợp lý, các phép toán linear (sum, dot product, linear model inference) có thể thực hiện với độ trễ chấp nhận được cho workflow không thời gian thực (batch nightly analytics). Tuy nhiên, tính toán phức tạp (non‑linear models, deep nets) hoặc yêu cầu interactive low‑latency vẫn cần hybrid HE+TEE hoặc MPC.

---

## 5. Background (Tổng quan kỹ thuật)

* **CKKS vs BFV/BGV:** CKKS hỗ trợ phép toán số thực xấp xỉ (phù hợp cho thống kê & ML), BFV/BGV dùng cho số nguyên & chính xác.
* **Packing / SIMD:** mã hoá nhiều giá trị vào một ciphertext để tận dụng khả năng xử lý song song; tiết kiệm băng thông và phép toán.
* **Noise & levels:** mỗi phép toán làm tăng noise; cần relinearization, rescaling; bootstrapping phục hồi nếu cần tính toán sâu hơn.
* **Multikey & Threshold HE:** multi‑key HE cho phép các bên mã hoá bằng khóa riêng nhưng phép tính được thực hiện trên ciphertext hợp nhất; threshold HE cho phép mở khóa tập thể bằng nhiều phiếu.
* **Evaluation keys:** eval keys (relin, Galois) phải được cấp cho evaluator; điều này đặt ra yêu cầu về phân phối khóa an toàn.

---

## 6. Ứng dụng & kịch bản cụ thể (Use Cases)

1. **Aggregate Exposure / Interbank Netting:** ngân hàng A,B,C mã hoá các phơi nhiễm đối với counterparty X; evaluator tính tổng phơi nhiễm & xác định if limit exceeded mà không biết phơi nhiễm từng ngân hàng.
2. **Privacy‑preserving Credit Scoring / Risk Models:** ngân hàng chia sẻ features để một mô hình tập trung chạy inference trên dữ liệu mã hoá và trả về score mà không thấy dữ liệu đầy đủ.
3. **AML / Fraud Detection across Banks:** chạy chỉ số anomalous behavior học tập/score trên dữ liệu mã hóa kết hợp để phát hiện patterns cross‑bank.
4. **Secure Interbank Auctions & Clearing:** ví dụ auction cho liquidity, hoặc netting computations trong CCP, nơi cần compute sums/dot products.
5. **Private Set Union / Set Intersection (hybrid):** không hoàn toàn HE, nhưng HE có thể hỗ trợ phối hợp với PSI/MPC để tìm overlap khách hàng giới hạn.

---

## 7. Thành phần hệ thống & kiến trúc (System Components)

### 7.1. Actors

* **Data Owners (Banks):** giữ dữ liệu gốc & private keys; thực hiện local preprocessing & encrypt bằng public key(s).
* **Evaluator (Compute Node/Consortium Processor):** nhận ciphertext, thực hiện phép tính HE theo hợp đồng (agreements & auditable code), trả ciphertext kết quả. Could be central regulator (central bank) or neutral cloud operator.
* **Key Management Authority / Consortium CA:** điều phối multi‑key setup, tạo eval keys, quản lý threshold decryption policies.
* **Result Consumers / Auditors:** nhận kết quả giải mã (thông qua threshold decryption) hoặc các kết luận đã được chứng thực.

### 7.2. Components & data flow

1. **Key setup & distribution:** banks generate keypairs; consortium protocol tạo evaluation keys (relin/Galois) and optionally a common public key for MK‑HE.
2. **Local preprocessing & encoding:** banks normalize & scale numeric features (CKKS needs fixed‑point scaling), pack vectors into ciphertexts.
3. **Encryption & upload:** encrypt and upload ciphertexts to evaluator (via secure channel).
4. **Homomorphic evaluation:** evaluator performs linear algebra (sums, dot products, matrix×vector) on ciphertexts; may use optimized BLAS‑like kernels for HE.
5. **Result handling & decryption:** evaluator returns ciphertext result; decryption via threshold scheme or sending back to data owners for partial decryption.
6. **Audit & logging:** all operations logged and signed, with reproducible scripts and policy enforcement.

### 7.3. Deployment options

* **Centralized evaluator (Regulator/Consortium):** easiest but trust/election issues; use threshold decryption to remove single point of trust.
* **Federated eval across consortium nodes (distributed evaluation):** each node does parts; combine results or use MPC for final stage.
* **Hybrid with TEE:** use enclave to hold secret for complex parts, reduce HE depth and computational cost.

---

## 8. Weaknesses & practical limitations (Deployment Weakness Analysis)

### 8.1. Performance & cost

* **Computation heavy:** HE operations (especially rotations, rescalings) rất tốn CPU và bộ nhớ; bootstrapping (nếu cần) rất đắt.
* **Ciphertext expansion & bandwidth:** ciphertexts có kích thước lớn (hàng chục đến hàng trăm KB); truyền nhiều vector lớn là tốn kém.
* **Latency:** unsuitable cho real‑time low‑latency use cases (payment clearing in seconds) — phù hợp cho batch analytics.

### 8.2. Accuracy (CKKS specific)

* **Xấp xỉ & error accumulation:** CKKS chỉ xấp xỉ số thực; nếu scaling/precision chọn sai thì kết quả sai lệch; cần careful parameter tuning.

### 8.3. Leakage từ kết quả

* **Result leakage:** trả về aggregate số liệu có thể rò rỉ dữ liệu nguồn (nhất là khi số bên tham gia ít hoặc queries có thiết kế tách biệt) — attacker có thể craft queries để infer single bank data.
* **Query budget & inference attacks:** cần policy để giới hạn các truy vấn có thể rút thông tin từng ngân hàng (differential privacy / noise, query auditing, minimum aggregation set size).

### 8.4. Key management & trust model

* **Eval key distribution rủi ro:** eval keys (relinearization/Galois) nếu rò rỉ hoặc bị lạm dụng có thể làm giảm an toàn; việc tổng hợp khóa MK hoặc threshold setup phức tạp.
* **Single point of compromise:** nếu evaluator có secret (trong hybrid) sẽ là single point of failure; threshold schemes giúp giảm rủi ro nhưng tăng phức tạp.

### 8.5. Implementation & side‑channels

* **Implementation bugs:** parameter mistakes, wrong rescaling/relinearization order gây incorrectness.
* **Side‑channels trên evaluator host:** CPU/GPU leaks, timing or memory patterns may leak info about inputs; need hardened environment and constant‑time libs where possible.

### 8.6. Legal & regulatory issues

* **Compliance & auditability:** regulators may yêu cầu access to raw data in investigations; HE only helps in analytics but legal frameworks must be considered.
* **Cross‑border data sharing:** data residency & privacy laws may restrict ciphertext movement or evaluation jurisdiction.

---

## 9. Methodology — PoC & Experiments (Pipeline)

### 9.1. Chọn thư viện & scheme

* **CKKS (SEAL / TenSEAL / PALISADE / Lattigo)** cho workloads số thực (VAR, ML inference).
* **BFV/BGV** nếu cần chính xác số nguyên (counts).
* **Multi‑key / Threshold extension** (nếu lib hỗ trợ) để tránh việc chia sẻ private keys.

### 9.2. Experiments gợi ý

* **Experiment 1 — Aggregate exposure:** mỗi ngân hàng mã hoá vector exposure; evaluator tính tổng và trả về; đo thời gian mã hóa, upload, evaluation, decryption time; đo kích thước ciphertext.
* **Experiment 2 — Linear model inference (credit risk):** model weights plaintext at evaluator; compute dot product w·x where x encrypted; compare plaintext vs HE inference accuracy (CKKS precision).
* **Experiment 3 — Query leakage tests:** craft multiple queries with different subsets and attempt inference of single bank's data; quantify leakage and test mitigations (noise, minimum group size).
* **Experiment 4 — Multi‑key & threshold flow:** implement multi‑party key setup (if library supports) and threshold decryption; test resilience vs one node failure.
* **Experiment 5 — Hybrid HE+TEE:** implement heavy parts in enclave and compare cost vs pure HE.

### 9.3. Metrics to thu thập

* Latency (encrypt, transfer, eval, decrypt), throughput (ops/sec), CPU & memory usage, ciphertext sizes, accuracy/error (CKKS MSE), energy use (optional), and security metrics (inference risk, #queries to breach threshold).

---

## 10. Implementation & Tools

* **Libraries:** Microsoft SEAL (C++), TenSEAL (Python wrapper), PALISADE, HElib, Lattigo (Go).
* **Environment:** Docker containers, Kubernetes cluster (for evaluator, scaled workers), CPU/GPU instances for performance tests, secure channels (TLS) for transfer.
* **Support tools:** Jupyter notebooks for plots, fplll not required here, load generators, profiling tools (perf, gprof).
* **Data:** synthetic interbank datasets (balances, exposures, transaction features) with realistic distributions; ensure anonymized & synthetic.

---

## 11. Evaluation Plan & Metrics

* **Functional correctness:** HE results matching plaintext baseline within acceptable CKKS error bounds.
* **Performance:** per‑operation latency, end‑to‑end time for example pipelines (per night batch), cost estimation (CPU‑hours, network).
* **Scalability:** grow #banks and vector sizes; measure throughput & memory scaling.
* **Security & privacy:** measured leakage risk under query workloads; effectiveness of mitigation strategies (DP noise, minimum aggregation size).
* **Operational:** complexity of key management, failure recovery time, auditorability of logs.

---

## 12. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Literature review (FHE basics, CKKS), chọn lib (SEAL/TenSEAL), thiết lập môi trường dev & synthetic dataset.
* **Tuần 3–4:** Implement basic encrypt→eval→decrypt pipeline for sums & dot products (single banker scenario).
* **Tuần 5–6:** Implement multi‑bank flow & packing (batching) to improve throughput; benchmark encryption/transfer costs.
* **Tuần 7–8:** Implement ML inference PoC (linear/logistic regression) and measure CKKS accuracy & performance.
* **Tuần 9:** Conduct leakage experiments and test mitigations (DP, query budgets, minimum group sizes).
* **Tuần 10:** Implement multi‑key / threshold variant (or simulate), and hybrid HE+TEE comparison.
* **Tuần 11:** Aggregate results, cost model, ablation studies (vary params), write recommendations.
* **Tuần 12:** Final report, reproducible repo (Docker/K8s), scripts, slides & demo video.

---

## 13. Deliverables

1. **Mid‑term:** architecture, chosen libraries & dataset, baseline pipeline working.
2. **Final report:** methodology, experimental results, security analysis, cost & deployment recommendations.
3. **Code repo:** PoC scripts, Dockerfiles, notebooks for benchmarking, synthetic data generator.
4. **Artifacts:** plots (latency, throughput, accuracy), sample ciphertexts, parameter configs used.
5. **Demo video:** show end‑to‑end example (encrypt by banks → evaluate → threshold decrypt) and one leakage mitigation in action.

---

## 14. Assessment & Rubric (gợi ý)

* Research & design choices: 25%
* PoC reproducibility & code quality: 30%
* Experimental rigor & analysis (performance & security): 30%
* Documentation & presentation: 15%

---

## 15. Risks, Limitations & Ethical Considerations

* **Dual‑use / misuse:** HE PoC details may be repurposed—run all experiments on synthetic datasets in isolated environment.
* **Operational feasibility:** HE currently best for batch analytics; be explicit about limits for real‑time clearing.
* **Legal/regulatory:** coordinate with domain experts for cross‑border data and regulator needs; do not assume HE alone solves compliance.

---

## 16. Mitigations & Best Practices (summary recommendations)

* **Use hybrid architectures:** HE for linear/batch analytics + TEE/MPC for low‑latency or non‑linear heavy ops.
* **Limit result leakage:** enforce minimum aggregation group size, add differential privacy noise, audit query patterns and apply query budgets.
* **Secure key management:** prefer threshold HE or multi‑key schemes to avoid single point secret; use HSMs for key material that must be protected.
* **Parameter & precision tuning:** carefully choose CKKS scale/params to balance accuracy vs noise; document parameter choices.
* **Operational monitoring & provenance:** sign and log all eval jobs, keep auditable transcripts, and require multi‑party approvals for sensitive queries.

---

## 17. Extensions & Future Work

* Explore GPU acceleration for HE evaluation kernels; evaluate library support (SEAL GPU, cuHE).
* Research combining HE with MPC/PSI for richer privacy‑preserving workflows (e.g., join + analytics).
* Formal privacy analysis combining DP with HE to provide provable leakage bounds for interbank queries.

---

## 18. Tools & Resources gợi ý

* Microsoft SEAL, TenSEAL, PALISADE, HElib, Lattigo, Docker/Kubernetes, Jupyter, Prometheus/Grafana for metrics, standard profiling tools.

---

## 19. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ infra/              # docker compose / k8s manifests for evaluator & bank clients
  ├─ data/               # synthetic dataset generator & samples
  ├─ banks/              # client scripts for bank A/B/C (encrypt & upload)
  ├─ evaluator/          # homomorphic kernels, eval scripts, multi‑key setup
  ├─ notebooks/          # benchmarks, analysis & plots
  ├─ docs/               # report, runbooks, parameter choices
  └─ demo/               # scripts to replay demo + recorded video
```

---

*Ghi chú cho sinh viên:* khi nộp, ghi rõ phiên bản thư viện, tham số HE (sec level, poly degree, scale), commit hashes, và phân biệt rõ simulation vs production. Tránh dùng dữ liệu thực; tuân thủ đạo đức nghiên cứu và responsible disclosure nếu tìm được lỗ hổng trong thư viện.

---

