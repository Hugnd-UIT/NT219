# Capstone Project — Post‑Quantum Blockchain: Thử nghiệm chữ ký Dilithium / Falcon cho Smart Contract

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Post‑Quantum Blockchain — Thử nghiệm và đánh giá chữ ký hậu‑lượng‑tử (Dilithium, Falcon) cho smart contract

---

## 1. Tóm tắt đề tài (Project Synopsis)

Mục tiêu của đề tài là nghiên cứu, triển khai và đánh giá khả năng ứng dụng **chữ ký hậu‑lượng‑tử** (PQ signatures) — cụ thể **Dilithium** và **Falcon** — trong bối cảnh blockchain và smart contract. Sinh viên sẽ thiết kế nhiều chiến lược triển khai (on‑chain verification, off‑chain verification + on‑chain attestation, và zk‑proof assisted verification), xây dựng các prototype (Solidity/WASM/Off‑chain), đo đạc chi phí thực tế (gas, latency, storage, bandwidth), và phân tích trade‑offs kỹ thuật, an ninh và vận hành.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu cơ chế chữ ký hậu‑lượng‑tử (Dilithium, Falcon) — ý tưởng nền tảng, các rủi ro thực thi (ví dụ sampling, constant‑time).
2. Triển khai code-sign/verify với thư viện PQC (ví dụ PQClean, liboqs) và build vào môi trường blockchain (EVM/Solidity, Substrate/WASM, hoặc L2).
3. So sánh chi phí thực tế: kích thước chữ ký, kích thước public key, chi phí lưu trữ on‑chain, gas cho verify (nếu on‑chain), chi phí băng thông trong giao dịch, thời gian xác thực off‑chain.
4. Thử các mô hình thiết kế: on‑chain verify, off‑chain verify + merkle/anchor, zkSNARK proof của verification, và đánh giá ưu/nhược điểm mỗi phương án.
5. Viết báo cáo khoa học, cung cấp mã nguồn reproducible và khuyến nghị cho áp dụng PQ signatures trong hệ thống blockchain.

---

## 3. Relevance & Motivation

* Khi công nghệ lượng tử trở nên khả thi, các chữ ký dựa trên RSA/ECDSA có thể bị phá vỡ; blockchain (đặc biệt là các hệ thống giữ asset lâu dài) cần lộ trình chuyển đổi tới PQC.
* Smart contract thường phụ thuộc vào khả năng xác thực chữ ký on‑chain; hiểu chi phí thực tế của PQ signatures là cần thiết để lên kế hoạch migrate.

---

## 4. Câu hỏi nghiên cứu & giả thuyết

**RQ1:** Chi phí (gas, bytes lưu trữ, latency) để xác thực Dilithium/Falcon on‑chain so với ECDSA là bao nhiêu trên EVM/Solidity và trên nền tảng WASM (Substrate/CosmWasm)?

**RQ2:** Có những thiết kế hybrid/auxiliary (off‑chain verification + on‑chain attestation, hoặc zk‑proof of verification) nào giúp giảm chi phí on‑chain mà vẫn giữ được tính bảo mật/khả năng audit không?

**RQ3:** Có sự khác biệt thực tiễn trong việc triển khai Dilithium vs Falcon (cân nhắc: kích thước chữ ký, công đoạn sampling/FFT, constant‑time difficulty) ảnh hưởng tới lựa chọn cho blockchain hay không?

**Giả thuyết:** Triển khai verify trực tiếp trên EVM sẽ tốn gas lớn và có thể không thực tế; WASM‑based smart contract hoặc off‑chain + attestation / zk‑proof là các hướng thực nghiệm khả thi hơn. Falcon có chữ ký nhỏ hơn ở một số cấu hình nhưng yêu cầu thực thi phức tạp hơn; Dilithium dễ thực thi an toàn hơn nhưng chữ ký có thể lớn hơn.

---

## 5. Background (Tổng quan ngắn)

* **Smart contract verification patterns:** on‑chain verification (verify trực tiếp trong contract), off‑chain verification + on‑chain commit/anchor (ví dụ publish hash/merkle root), và succinct proof verification (on‑chain verify SNARK/PLONK proof).
* **EVM constraints:** gas cho tính toán, kích thước calldata, no native support for heavy number‑theory operations or big polynomial arithmetic; Solidity không phù hợp cho tính toán nặng.
* **WASM chains:** Substrate/Polkadot, CosmWasm cho phép chạy code biên dịch từ Rust/WebAssembly, phù hợp cho workloads nặng hơn.
* **PQC practicalities:** Dilithium (simple lattice operations, Fiat‑Shamir based), Falcon (FFT/GPV sampling → hơn phức tạp, side‑channel considerations).

---

## 6. Literature review (các hướng cần khảo sát)

* Bài gốc/tiêu chuẩn hoá cho Dilithium & Falcon (submit papers / NIST PQC materials).
* Các báo cáo/benchmarks về PQC triển khai trong môi trường nhúng và trong context blockchain.
* Công trình về on‑chain verification của các chữ ký phi‑ECDSA (trong Ethereum, Substrate, Cosmos).
* Nghiên cứu/voucher về zk‑proof cho việc chứng minh một chữ ký là hợp lệ (SNARK for signature verification).

> Yêu cầu: sinh viên phải trích dẫn tối thiểu 6 nguồn học thuật/technical reports và 3 repo/codebases hữu ích (ví dụ PQClean/liboqs, implementations cho WASM, demo tích hợp PQC vào blockchain).

---

## 7. Methodology (chi tiết đề xuất)

### 7.1. Thiết kế các kịch bản triển khai (để so sánh)

1. **On‑chain verification (EVM/Solidity naive):** implement verify function in Solidity (direct port of verification algorithm) — mục tiêu: đo gas cost, feasibility.
2. **On‑chain verification (WASM contract):** compile PQ verify code to WASM and run on a WASM‑based chain (Substrate/Canvas/CosmWasm) — đo gas/weight, latency.
3. **Off‑chain verification + on‑chain attestation:** verifier kiểm tra chữ ký off‑chain; gửi trên‑chain một attest (ví dụ merkle root / hash hoặc signed status) để chứng minh ownership/validity.
4. **zk‑proof assisted:** off‑chain generate SNARK/zk proof that signature verifies; on‑chain verify small proof. So sánh chi phí: proof generation time vs on‑chain verification gas.

### 7.2. Implementation plan (chi tiết)

* **Libraries:** sử dụng PQClean / liboqs (C) hoặc bindings Rust (pqcrypto/oxide‑pqc) để implement sign/verify.
* **On‑chain EVM prototype:** viết Solidity contract chứa implementation verify (minimal, thử nghiệm) và deploy trên testnet/local (Hardhat/Ganache) để đo gas.
* **WASM prototype:** biên dịch verify routine (Rust) sang WASM target và deploy vào Substrate node dev chain hoặc CosmWasm sandbox; benchmark execution weight/time.
* **Off‑chain + attestation:** xây dựng server/cli tool thực hiện verify và publish attestation TX (containing hash/merkle root) to chain; measure latency and extra TX cost.
* **zk‑proof pipeline:** use a proving system (Circom + snarkjs, or Halo2/Plonk stacks) to encode signature verification circuit for either Dilithium or Falcon (tùy feasibility), generate proof off‑chain, and verify on‑chain; measure proving time + verify gas.

### 7.3. Data & test cases

* Sinh/ngenerate keypairs và chữ ký representative cho cả Dilithium và Falcon ở các parameter sets phù hợp.
* Tạo kịch bản giao dịch smart contract đại diện (ví dụ: chuyển token có kèm PQ signature, đăng nhập bằng PQ signature, or multisig‑style flows).
* Tập trung vào worst‑case và typical‑case: verify 1 signature per TX; verify batch of signatures (gas amortization) nếu applicable.

### 7.4. Measurement methodology

* **Gas / weight / compute cost:** deploy contract & call verify functions; record gas used per verification.
* **Calldata & storage:** bytes added to transaction & storage per signature/public key.
* **Latency:** time to perform verify on‑chain (including TX propagation & block inclusion for on‑chain attestation), and off‑chain proof generation time.
* **Memory & binary size (WASM):** WASM module size, memory usage.
* **Security checklist:** check constant‑time, side‑channel concerns especially for Falcon (if implementing sampling), and validate correctness against reference vectors.

---

## 8. Implementation & Experiment Setup

### 8.1. Recommended platforms & tools

* **EVM local test:** Hardhat/Ganache, geth dev, or Ethereum testnets for realistic gas prices.
* **WASM chain:** Substrate local node, Canvas/LocalCosmos chain, or CosmWasm playground.
* **PQC libs:** PQClean (C), liboqs (C), Rust pqcrypto wrappers.
* **zk stacks (optional):** Circom/snarkjs, Bellman/Halo2/Plonk libraries (Rust).
* **Benchmarking harness:** scripts (Node.js/Hardhat for EVM; Rust scripts + substrate‑cli for WASM), CSV logging, plotting scripts (Python/pandas/matplotlib).

### 8.2. Reproducibility

* Ghi rõ commit hashes cho libs, compiler versions, toolchain (WASM target), node versions.
* Cung cấp Dockerfile(s) cho chạy local devnets và build môi trường (Rust toolchain, cargo wasm target, Node.js toolchain).

---

## 9. Evaluation Plan & Metrics

* **Gas per verify (EVM):** average & median gas for single verify call; gas for batch verification (if implemented).
* **Transaction size:** calldata bytes for sending signature + pubkey.
* **WASM weight/time:** execution time in WASM environment and module size.
* **Off‑chain verification cost:** time to verify and TX cost to post attestation (publish root/hash).
* **zk approach:** proof generation time vs on‑chain verify gas.
* **Security considerations:** discuss side‑channel/constant‑time feasibility, and code complexity (implementation risk).

---

## 10. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Survey tài liệu, chọn parameter sets cho Dilithium & Falcon, thiết lập môi trường dev (Hardhat, Substrate, PQ libs).
* **Tuần 3–4:** Implement sign/verify toolchains (PQClean/liboqs), generate test vector sets.
* **Tuần 5–6:** Prototype EVM naive verify contract (Solidity), deploy local, measure gas for single verify.
* **Tuần 7–8:** WASM prototype (Rust → WASM), deploy on Substrate dev node, measure weight/time.
* **Tuần 9:** Implement off‑chain attestation flow and measure latency/tx cost.
* **Tuần 10:** Implement zk‑proof pipeline for verification (proof gen + on‑chain verify) if feasible.
* **Tuần 11:** Aggregate results, run ablation/parameter sensitivity (different parameter sets).
* **Tuần 12:** Finalize report, reproducible repo, slides & demo.

---

## 11. Deliverables

1. **Mid‑term report/presentation:** design choices, dataset test vectors, initial EVM gas numbers.
2. **Final report (PDF/MD):** toàn bộ phương pháp, kết quả, so sánh, khuyến nghị cho deployers.
3. **Code repository:** signer/verify tool, Solidity contracts, WASM contracts, attestation server, zk circuits (nếu có), Dockerfile.
4. **Data & artifacts:** raw CSV measurements, plots, commit hashes, config scripts.
5. **Demo:** video ghi lại chạy thử EVM & WASM verify, attestation flow, và zk proof demo (nếu thực hiện).

---

## 12. Đánh giá & Rubric (gợi ý)

* Technical grounding & literature: 20%
* Correctness & reproducibility (code, hashes, scripts): 25%
* Experimental rigor & clarity (metrics, stats): 30%
* Analysis & recommendations (practicality, security trade‑offs): 15%
* Presentation & documentation: 10%

---

## 13. Risks, Limitations & Mitigation

* **Complexity thực thi Falcon:** Falcon yêu cầu sampling và FFT; cần cẩn trọng về side‑channel; nếu không có expertise/time, ưu tiên Dilithium prototype trước.
* **EVM gas prohibitively high:** chuẩn bị fallback designs (off‑chain attestation, zk proof).
* **zk circuit complexity:** encoding full PQ verify into SNARK circuit có thể rất khó; chọn sub‑set hoặc sử dụng existing zk friendly primitives.
* **Chuẩn hoá & thay đổi thông số:** PQC parameters có thể được tổ chức/điều chỉnh — ghi rõ commit hashes và tham chiếu các tiêu chuẩn trong báo cáo.

---

## 14. Ethics & Responsible Disclosure

* Không sử dụng khoá thực / account live để thử nghiệm.
* Nếu tìm thấy lỗi trong implementation hoặc lib nguồn mở, thông báo cho maintainers theo responsible disclosure.

---

## 15. Extensions & Future Work

* Evaluate multi‑signature / multisig schemes with PQ signatures (giao dịch đa chủ sở hữu).
* Design migration strategies for existing chains (e.g., soft‑fork via precompile addition).
* Explore zk‑friendly PQ variants or tailor lightweight PQ signatures for on‑chain verification.

---

## 16. Tools & Resources gợi ý

* PQ libs: PQClean, liboqs, pqcrypto wrappers
* Blockchain tools: Hardhat/Ganache, geth, Substrate dev node, CosmWasm sandbox
* zk stacks (optional): Circom/snarkjs, Bellman/Halo2
* Build & reproducibility: Docker, GitHub Actions for CI benchmarks

---

## 17. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ pq-libs/            # submodules: PQClean/liboqs and selected commits
  ├─ signer/             # CLI tools to sign/verify (Rust or C)
  ├─ evm-contracts/      # Solidity naive verify contracts + tests (Hardhat)
  ├─ wasm-contracts/     # Rust -> WASM verify code for Substrate/CosmWasm
  ├─ attestation/        # off-chain verifier + attestation broadcaster
  ├─ zk/                 # circuits + proof harness (if any)
  ├─ docker/             # Dockerfiles for reproducible envs
  ├─ benchmarks/         # raw CSV, plotting scripts
  └─ docs/               # report, slides, demo video
```

---