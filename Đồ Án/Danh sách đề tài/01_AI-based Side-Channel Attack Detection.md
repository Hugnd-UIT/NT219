# Capstone Project — AI-based Side-Channel Attack Detection

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** AI-based Side-Channel Attack Detection — Phát hiện tấn công kênh kề bằng ML/DL

---

## 1. Tóm tắt đề tài (Project Synopsis)

Đề tài nghiên cứu và triển khai hệ thống dùng kỹ thuật Machine Learning / Deep Learning để phát hiện và/hoặc mô phỏng tấn công kênh kề (side-channel attack — SCA) dựa trên các tín hiệu đo (power traces, electromagnetic emissions, timing). Mục tiêu là xây dựng pipeline thu thập dữ liệu, xử lý tín hiệu, huấn luyện mô hình, đánh giá hiệu quả trên các kịch bản tấn công thực tế và so sánh với các phương pháp baseline (ví dụ: correlation power analysis, template attack).

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu rõ khái niệm tấn công kênh kề, cơ chế rò rỉ thông tin qua năng lượng/timing/EM.
2. Biết cách thu thập, căn chỉnh và xử lý trace (preprocessing) cho ML.
3. Thiết kế, huấn luyện và đánh giá các mô hình ML/DL (CNN, RNN, Transformer, hybrid) cho detection/analysis.
4. So sánh hiệu năng giữa ML-based và classical SCA techniques.
5. Viết báo cáo khoa học và triển khai demo có thể lặp lại (reproducible).

---

## 3. Relevance & Motivation

* SCA là một trong các kênh tấn công thực tế tác động lên mọi thiết bị thực thi mật mã (embedded, IoT, smartcards).
* ML/DL đã chứng tỏ khả năng phát hiện pattern phức tạp trong dữ liệu liên tục; áp dụng vào SCA giúp:

  * phát hiện sớm (real-time) các tấn công trên hệ thống; hoặc
  * tự động hóa quá trình cryptoanalysis (dịch ngược khóa) trong môi trường nghiên cứu.

---

## 4. Câu hỏi nghiên cứu & giả thuyết

**RQ1:** ML/DL có thể phát hiện tấn công kênh kề với độ chính xác cao hơn baseline truyền thống (CPA/template) trong điều kiện nhiễu/đời thực không?

**RQ2:** Kỹ thuật preprocessing (alignment, filtering, wavelet, PCA) nào giúp mô hình học tốt nhất?

**RQ3:** Mô hình có kháng nhiễu (robust) với các biến thể phần cứng/biến thiên môi trường không? (tính tổng quát)

**Giả thuyết:** Mô hình CNN kết hợp augmentation + proper alignment sẽ đạt chỉ số detection tốt hơn so với threshold-based hoặc CPA khi số lượng trace lớn.

---

## 5. Background (Tổng quan ngắn)

* **Loại SCA:** Power analysis (SPA, DPA), EM analysis, timing attacks.
* **Classical techniques:** Correlation Power Analysis (CPA), Differential Power Analysis (DPA), Template Attacks.
* **Datasets & platforms thường dùng:** ASCAD, ChipWhisperer traces, datasets từ bài báo công bố, bo mạch MCU (AVR, ARM Cortex-M).

---

## 6. Literature review (những hướng cần khảo sát)

* ML/DL applied to side-channel: CNN-based key recovery, LSTM for sequential traces.
* Preprocessing methods: trace alignment (synchronization), denoising (bandpass, wavelet denoise), dimensionality reduction (PCA/ICA).
* Augmentation & synthetic traces.
* Explainable AI for model interpretability in SCA context.

> Gợi ý: sinh viên cần lập danh sách ít nhất 6 bài báo/technical reports & 3 mã nguồn dataset/tools.

---

## 7. Methodology (chi tiết đề xuất)

### 7.1. Tổng quan pipeline

1. **Thiết kế mục tiêu**: detection (binary classification: attack/no-attack) hoặc key-recovery (multi-class/regression/ranking).
2. **Chuẩn bị target**: chọn implementation AES (software/hardware) để làm mục tiêu.
3. **Thu thập trace**: sử dụng oscilloscope/ChipWhisperer hoặc dataset public.
4. **Preprocessing**: denoise, alignment, normalization, cropping, dimensionality reduction.
5. **Feature engineering**: raw trace, spectrogram/Short-Time Fourier Transform (STFT), wavelet coefficients, statistical moments.
6. **Modeling**: thử nghiệm nhiều kiến trúc (CNN 1D, Residual CNN, LSTM, Transformer 1D, hybrid CNN+LSTM).
7. **Training**: hyperparameter search, class balancing, augmentation (noise injection, time shift).
8. **Evaluation**: detection metrics & key rank analysis (guessing entropy) theo tập test.

### 7.2. Preprocessing chi tiết

* Alignment: cross-correlation, dynamic time warping (DTW), trigger-based alignment.
* Filtering: band-pass, moving average, wavelet denoising.
* Dimensionality reduction: PCA, down-sampling, feature selection by mutual information.

### 7.3. Kiến trúc mô hình (gợi ý)

* **Baseline models:** Logistic Regression, Random Forest, SVM trên features time-domain.
* **DL models:** 1D-CNN (several conv + pooling), ResNet-like 1D, Bi-LSTM, Transformer encoder (1D), CNN -> LSTM pipeline.
* **Output:** binary (attack/no-attack) hoặc distribution over key bytes (softmax)

### 7.4. Robustness & Adversarial testing

* Kiểm tra performance khi thay sampling rate, thay target device, thêm nhiễu.
* Thử tấn công nghịch (adversarial traces) để xem mô hình dễ bị lừa không.

---

## 8. Implementation & Experiment Setup

### 8.1. Hardware

* Development PC (GPU cho training), optional: AWS/GCP GPU instances.
* Measurement: ChipWhisperer kit hoặc oscilloscope + probe (nếu có access lab); target MCU (STM32, AVR, RISC-V).

### 8.2. Software & Libraries

* Python, Jupyter Notebook
* PyTorch hoặc TensorFlow / Keras
* Scikit-learn, NumPy, SciPy, librosa (cho spectrogram), PyWavelets
* ChipWhisperer software (nếu dùng)
* Dockerfile để đảm bảo reproducibility (gợi ý cung cấp `Dockerfile`/`requirements.txt`)

### 8.3. Datasets

* Public: ASCAD, ChipWhisperer traces.
* Nếu thu thập tự nhiên: mô tả định dạng CSV/NumPy array (N\_traces x length\_trace), metadata (key, plaintext, timestamp).

---

## 9. Evaluation Plan & Metrics

* **Detection task:** Accuracy, Precision, Recall, F1-score, ROC-AUC, confusion matrix.
* **Key-recovery task:** Key rank, Guessing Entropy (GE), success rate after N traces.
* **Efficiency:** Training time, inference latency per trace, model size.
* **Robustness:** performance under noise, device shift, unseen operating conditions.

**So sánh với baselines:** CPA, Template Attack, thresholding methods.

---

## 10. Timeline & Milestones (12 tuần / 3 credit semester adaptation)

* **Tuần 1–2:** Literature review sâu, chọn target & dataset, định nghĩa câu hỏi nghiên cứu.
* **Tuần 3–4:** Thiết lập môi trường, thu thập dataset (hoặc chuẩn hóa public dataset), exploratory analysis.
* **Tuần 5–7:** Preprocessing pipeline, feature extraction, baseline models (non-deep-learning).
* **Tuần 8–10:** Thiết kế & huấn luyện mô hình DL, hyperparameter tuning.
* **Tuần 11:** Robustness experiments, adversarial tests, ablation studies.
* **Tuần 12:** Chuẩn bị báo cáo cuối, trình bày, demo & nộp mã nguồn.

---

## 11. Deliverables (bắt buộc)

1. **Mid-term report/presentation:** vấn đề, khảo sát tài liệu, dataset mẫu, kế hoạch triển khai.
2. **Final report (markdown/PDF):** đầy đủ nội dung, kết quả, phân tích, mã nguồn.
3. **Code & Notebook reproducible:** Git repo + Dockerfile + hướng dẫn chạy.
4. **Dataset (hoặc hướng dẫn tái tạo):** tệp trace hoặc script thu thập.
5. **Demo video / live demo:** chạy mô hình trên vài trace, show detection/key rank.

---

## 12. Đánh giá & Rubric (gợi ý cho giảng viên)

*Breakdown suggestion (tương thích với NT219):*

* Originality & literature grounding: 20%
* Methodology & implementation quality: 30%
* Experiments & evaluation rigor: 25%
* Reproducibility (code/docs): 15%
* Presentation & report quality: 10%

*Quality levels (Distinction/Merit/Pass/Fail) tương ứng với tiêu chí chi tiết: novelty, depth of evaluation, correctness of implementation, clarity of report.*

---

## 13. Risks, Limitations & Mitigation

* **Không có access thiết bị đo:** dùng public datasets hoặc mô phỏng trace (synthetic).
* **Dữ liệu ít/noisy:** augmentation, denoising, hoặc chuyển hướng sang detection thay vì key-recovery.
* **Ethical/legal:** tránh công bố payloads có thể làm tổn hại — giữ dataset public/benign.

---

## 14. Ethics & Responsible Disclosure

* Không sử dụng dataset/thiết bị để tấn công hệ thống thực tế mà không có phép.
* Nếu phát hiện lỗ hổng trong hệ thống thương mại, thực hiện responsible disclosure theo chuẩn.

---

## 15. Extensions & Future Work (đề xuất để mở rộng sau capstone)

* Federated learning để chia sẻ mô hình detection giữa nhiều device mà không chia sẻ trace raw.
* Explainable AI để định vị nguyên nhân rò rỉ trên trace (saliency maps).
* Transfer learning across device families (generalization).

---

## 16. Tools & Resources gợi ý

* ChipWhisperer (hardware + software)
* Datasets: ASCAD, public CW datasets
* PyTorch / TensorFlow, scikit-learn
* PyWavelets, librosa (signal processing)

---

## 17. Appendix: Mẫu cấu trúc repo

```
project-root/
  ├─ data/               # raw & processed traces (giảm thiểu chia sẻ key thực)
  ├─ notebooks/          # EDA, training notebooks
  ├─ src/                # preprocessing, models, training scripts
  ├─ experiments/        # configs, results, logs
  ├─ docker/             # Dockerfile, requirements.txt
  └─ report/             # final report, slides, demo video
```

---

*Ghi chú:* khi nộp project, ghi rõ tất cả nguồn dữ liệu, tham khảo, và làm rõ những phần mình tự phát triển so với mã nguồn tham khảo.

---