# Capstone Project — Generative AI for Key/Nonce Management

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Generative AI cho Key/Nonce Management — phát hiện sinh khóa hoặc nonce yếu trong giao thức

---

## 1. Tóm tắt đề tài (Project Synopsis)

Đề tài nghiên cứu và triển khai hệ thống sử dụng mô hình sinh (generative models) và kỹ thuật học máy để:

1. **Phát hiện** các key/nonce/IV yếu hoặc có đặc điểm dễ tiên đoán trong hệ thống (API, TLS, IoT, blockchain).
2. **Sinh** các ví dụ khóa/nonce yếu (adversarial examples) dùng để kiểm thử và huấn luyện hệ thống phòng thủ.

Mục tiêu là tạo pipeline khép kín: thu thập dữ liệu (hoặc sinh dữ liệu), đặc trưng hoá, huấn luyện mô hình generative / density-estimation để tính xác suất (likelihood) cho sequence, phát hiện bất thường (anomaly detection), và đánh giá trên kịch bản thực tế (ví dụ: JWT nonces, TLS client nonces, random IV cho AES-GCM, seed RNG trên IoT).

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

* Hiểu cơ chế sinh số ngẫu nhiên (PRNG, CSPRNG) và các lỗi phổ biến (seeding sai, reuse, low entropy).
* Triển khai và so sánh các mô hình generative: VAE, GAN, Normalizing Flows, Autoregressive & Transformer sequence models.
* Thiết kế hệ thống anomaly-detection dựa trên likelihood/reconstruction error và classifier kết hợp.
* Sinh dữ liệu weak-key/weak-nonce có kiểm soát để benchmark.
* Thực hiện reproducible experiments, báo cáo và đề xuất mitigation (design/operational fixes).

---

## 3. Tính cấp thiết & động lực (Relevance & Motivation)

* Nonce/IV/key không đủ ngẫu nhiên dẫn đến phá vỡ bảo mật (ví dụ: reuse IV trong AES-GCM, seed lỗi dẫn đến tái tạo khóa).
* Các hệ thống đám mây, API, IoT thường có nguồn entropy hạn chế — phát hiện sớm weak RNG giúp giảm rủi ro.
* Generative AI có thể học phân phối "bình thường" của chuỗi bytes và phát hiện bất thường, đồng thời sinh hằng loạt mẫu tấn công để test hệ thống.

---

## 4. Câu hỏi nghiên cứu & giả thuyết

**RQ1:** Mô hình generative nào (VAE, Flow, Autoregressive, Transformer) phù hợp nhất để ước lượng phân phối nonces/keys và phát hiện weak-samples?

**RQ2:** Mô hình trained-only-on-good-data (unsupervised) hiệu quả đến đâu so với supervised classifier trained trên weak/good-labeled data?

**RQ3:** Có thể dùng generative models để tự động tạo test-cases (adversarial nonces) làm tiêu chuẩn kiểm thử cho hệ thống? Mức độ "realism" của mẫu sinh có đủ để lừa các hệ thống kiểm tra hiện có?

**Giả thuyết:** Density estimation bằng Normalizing Flows hoặc Autoregressive Transformer sẽ cho likelihood scoring ổn định, giúp phát hiện weak nonces chính xác hơn các thống kê truyền thống (entropy window) trong nhiều kịch bản.

---

## 5. Background (Tổng quan ngắn)

* **PRNG (pseudo-random):** hàm sinh dựa trên công thức; không nhất thiết an toàn mật mã.
* **CSPRNG (crypto-secure):** đảm bảo không thể dự đoán được state từ output.
* **Các lỗi phổ biến:** seed lấy từ thời gian (timestamp), low entropy tại boot, reuse nonces, truncated RNG outputs, insecure libraries (sử dụng `rand()`), bug implementation (Debian OpenSSL 2006...).
* **Thống kê truyền thống:** NIST STS, Dieharder, PractRand — test thống kê không phải luôn đủ cho phát hiện weak nonces trong context ứng dụng.

---

## 6. Literature review (các hướng cần khảo sát)

* Randomness testing và NIST SP 800-22, PractRand, Dieharder.
* Anomaly detection trên sequence dữ liệu bằng likelihood/reconstruction (VAE, Normalizing Flows, AutoRegressive).
* GAN/Adversarial generation for synthetic weak samples and evaluation metrics for realism.
* Works on RNG failures in deployed systems (case studies) and mitigations (entropy gathering, hardware TRNG).

> Yêu cầu: sinh viên cần liệt kê ít nhất 6 bài báo / report kỹ thuật và các repo công cụ (NIST STS, PractRand, frameworks cho VAE/GAN/Flow).

---

## 7. Methodology (pipeline chi tiết)

### 7.1. Mục tiêu & phạm vi

* Chọn 1–2 kịch bản thực tế làm target: ví dụ TLS client/server nonces, JWT nonce/iat, blockchain nonce (transaction nonce), IoT device boot-time RNG.
* Xác định mục tiêu: detection (anomaly/non-anomaly) & generation (produce weak-samples).

### 7.2. Pipeline chính

1. **Data collection & synthesis**

   * Thu thập output RNG thật (nếu có access) hoặc sinh: CSPRNG (OpenSSL RAND\_bytes, libsodium), PRNG (`rand()` / LCG), low-entropy strategies (timestamp-seed, repeated seed), partial entropy outputs.
2. **Preprocessing & Representation**

   * Byte-level sequences (fixed-length nonces), bit-level vectors, sliding windows.
   * Feature engineering: entropy per-window, autocorrelation, run-length encoding, byte-frequency, bigram/trigram counts.
3. **Modeling**

   * **Unsupervised density models:** Normalizing Flows (RealNVP, Masked Autoregressive Flows), Autoregressive models (PixelCNN-like for bytes), Transformer-based language models (causal LM over bytes), VAE for reconstruction likelihood.
   * **Generative adversarial models:** conditional GAN to produce weak nonces given a weakness pattern; discriminator can be reused for detection.
   * **Supervised classifiers:** RandomForest, XGBoost, CNN/Transformer classifier on labeled weak/good samples for comparison.
4. **Scoring & Detection**

   * Likelihood score (Flows/Autoregressive), reconstruction error (VAE), discriminator score (GAN), confidence score (classifier).
   * Thresholding strategy with calibration (e.g., use ROC on validation).
5. **Adversarial generation & evaluation**

   * Use generative model to synthesize weak nonces designed to maximize the chance of fooling a target test (e.g., high-likelihood under generator but failing security tests).

### 7.3. Preprocessing kỹ thuật

* Fixed-length padding/truncation, endian normalization.
* Sliding-window entropy for long streams.
* Domain-specific normalization (e.g., extract nonce fields from protocol traces).

### 7.4. Baselines

* NIST STS suite pass/fail
* Statistical features + Random Forest classifier
* Heuristic checks: reuse detection, uniqueness window, timestamp-based seed detection

---

## 8. Implementation & Experiment Setup

### 8.1. Hardware

* Development machine with GPU (training Flows/Transformer), cloud GPU optional.

### 8.2. Software & Libraries

* Python, Jupyter Notebooks
* PyTorch or TensorFlow/Keras
* Flow libraries (e.g., `nflows`), Hugging Face Transformers (byte-level modeling), PyTorch Lightning (optional)
* scikit-learn, numpy, pandas
* NIST STS, PractRand / Dieharder for baseline testing

### 8.3. Datasets & Synthetic Generators

* **Good-data:** outputs from /dev/urandom, OpenSSL RAND\_bytes, libsodium randombytes\_buf.
* **Weak-data scenarios (synthesize):**

  * Timestamp-seeded PRNG: `seed = time()` then LCG outputs
  * Reused nonce sequences (replay)
  * Truncated RNG: only low bits used
  * Device-specific artifacts (simulate low-entropy at boot: few unique seeds)
* **Optional real traces:** capture nonces from lab TLS handshake logs (ensure privacy/permission), IoT boot logs (anonymized).

---

## 9. Evaluation Plan & Metrics

* **Detection metrics:** Precision, Recall, F1-score, ROC-AUC, PR-AUC, confusion matrix.
* **Anomaly scoring metrics:** Calibration of likelihood scores, false positive rate at fixed detection rate, detection latency (time to flag bad device).
* **Generative quality:** Inception-like metrics not applicable; propose: pass-rate of statistical tests (NIST) for generated samples, adversarial success rate (fraction of generated weak samples that bypass baseline checks but are flagged by model or vice versa).
* **Operational metrics:** Throughput (nonces/sec), model size, inference latency (suitable for inline detection in proxy/gateway).

**So sánh với baseline:** NIST/SP800-22 pass/fail, heuristic rules, supervised classifier.

---

## 10. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Literature survey, chọn target protocol(s), design data generation plan.
* **Tuần 3–4:** Implement data generators (good + weak scenarios), EDA và feature engineering.
* **Tuần 5–7:** Implement generative models (Flow / VAE / Transformer) và baseline classifiers.
* **Tuần 8:** Develop detection thresholding, calibration, initial evaluation.
* **Tuần 9:** Adversarial generation experiments, stress tests across scenarios.
* **Tuần 10–11:** Robustness tests, cross-device generalization, ablation studies.
* **Tuần 12:** Finalize report, code, demo & presentation.

---

## 11. Deliverables

1. **Mid-term presentation/report:** problem statement, dataset plan, baseline results.
2. **Final report (PDF/MD):** method, models, experiments, analysis, reproducibility.
3. **Code repository:** data generator, model training/eval, inference scripts, Dockerfile.
4. **Dataset / generator scripts:** hướng dẫn tái tạo dữ liệu (do không chia sẻ dữ liệu nhạy cảm).
5. **Demo:** notebook or short video showing detection integration (e.g., simple API gateway plugin detecting weak nonces in incoming requests).

---

## 12. Đánh giá & Rubric (gợi ý)

* Research grounding & novelty: 20%
* Methodology & implementation correctness: 30%
* Experimental rigor & analysis: 25%
* Reproducibility (code, Docker, docs): 15%
* Presentation & final report: 10%

---

## 13. Risks, Limitations & Mitigation

* **Access to real-world traces limited:** Mitigation: realistic synthetic generators, clear assumptions.
* **False positives impacting operations:** Must design conservative thresholds and human-in-the-loop review.
* **Ethical concern:** avoid harvesting sensitive data; anonymize and obtain permission.
* **Model overfitting to synthetic weaknesses:** Use multiple weak-generation strategies and test transfer to unseen patterns.

---

## 14. Ethics & Responsible Disclosure

* Không dùng kết quả để tấn công hệ thống thực tế. Nếu tìm lỗ hổng trong hệ thống thuộc tổ chức khác, thực hiện responsible disclosure qua kênh chính thức.
* Không lưu trữ/sàng lọc các key thực tế của người dùng.

---

## 15. Extensions & Future Work

* Real-time deployment as an API-gateway plugin / SIEM integration.
* Federated anomaly detection across multiple devices without sharing raw nonces (privacy-preserving detection).
* Hardware TRNG monitoring: apply model to entropy-source health monitoring (drift detection).

---

## 16. Tools & Resources gợi ý

* NIST SP800-22 Statistical Test Suite, PractRand, Dieharder
* PyTorch / TensorFlow, nflows, Hugging Face Transform
* OpenSSL, libsodium for CSPRNG outputs
* Docker, GitHub repo

---

## 17. Appendix: Mẫu cấu trúc repo

```
project-root/
  ├─ data/               # generator scripts and small example files (no sensitive data)
  ├─ notebooks/          # EDA, demo notebooks
  ├─ src/
  |   ├─ data_gen/       # generators for good + weak nonces
  |   ├─ models/         # VAE, Flow, Transformer, classifiers
  |   ├─ train.py
  |   └─ infer.py        # inference / scoring
  ├─ experiments/        # configs, results, logs
  ├─ docker/             # Dockerfile, requirements.txt
  └─ report/             # final report, slides, demo video
```

---
