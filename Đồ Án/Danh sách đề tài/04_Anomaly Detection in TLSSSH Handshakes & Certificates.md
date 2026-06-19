# Capstone Project — Anomaly Detection in TLS/SSH Handshakes & Certificates

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Anomaly Detection in TLS/SSH — Dùng ML để phát hiện bất thường trong handshake hoặc certificate

---

## 1. Tóm tắt đề tài (Project Synopsis)

Đề tài nghiên cứu và triển khai hệ thống sử dụng kỹ thuật Machine Learning để phát hiện bất thường trong các giao thức bảo mật lớp vận chuyển TLS và giao thức SSH, tập trung vào:

* **Handshake-level anomalies:** chuỗi các thông điệp handshake, phiên bản TLS, cipher suites, extensions, JA3/JA3S fingerprints, temporal/timing patterns.
* **Certificate-level anomalies:** thuộc tính X.509 (issuer, subject, validity, signature algorithm, key size), chuỗi chứng chỉ, OCSP/CRL status, sự xuất hiện bất thường trong Certificate Transparency (CT).

Mục tiêu là xây dựng pipeline: thu thập/trích xuất đặc trưng từ pcap/flow/SSL logs, thiết kế mô hình ML (unsupervised / semi-supervised / supervised) để phát hiện các hoạt động đáng ngờ như man-in-the-middle (forged certificates), TLS downgrade, sử dụng cipher yếu, certificate spoofing hoặc các kết nối TLS giả mạo của botnet/malware.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu cấu trúc TLS/SSL handshake, trường certificate X.509 và fingerprinting (JA3/JA3S).
2. Trích xuất và biểu diễn features chuyên biệt cho TLS/SSH (packet sequence, timings, cipher suite vector, cert fields).
3. Thiết kế mô hình phát hiện bất thường phù hợp: autoencoder, Isolation Forest, One-Class SVM, LSTM/Transformer cho sequence, GNN cho certificate graph.
4. Triển khai pipeline thu thập — preprocessing — model — alerting, tích hợp mô hình vào thử nghiệm (offline hoặc inline SIEM/proxy).
5. Đánh giá hiệu năng trong các kịch bản tấn công (MitM, forged cert, downgrade, botnet TLS) và phân tích false-positive/false-negative.

---

## 3. Relevance & Motivation

* TLS/SSH là nền tảng bảo mật giao tiếp Internet; bất thường ở layer này thường là dấu hiệu của tấn công (MitM, malware C2, data-exfiltration cloaked in TLS).
* Signature-based IDS thường bỏ sót các trường hợp mới; ML có thể phát hiện hành vi bất thường không có signature trước đó.
* Certificate transparency và telemetry ngày càng phong phú — mở ra cơ hội kết hợp nguồn dữ liệu lớn cho phát hiện bất thường.

---

## 4. Câu hỏi nghiên cứu & giả thuyết

**RQ1:** Những feature handshake/certificate nào đóng vai trò quyết định cho việc phân biệt traffic hợp lệ và traffic bất thường?

**RQ2:** Phương pháp unsupervised (autoencoder/flow/isolation) có phát hiện được mẫu tấn công chưa thấy trước hơn supervised classifier trained-on-known-attacks không?

**RQ3:** Mức độ false positives có giảm được khi kết hợp nguồn dữ liệu (network-level + CT logs + endpoint telemetry)?

**Giả thuyết:** Kết hợp feature-level (JA3/JA3S + cipher/extension buckets) với temporal/context features (connection frequency, session duration) và certificate-chain graph signals giúp cải thiện precision mà không tăng nhiều false positive.

---

## 5. Background (Tổng quan ngắn)

* **TLS handshake:** ClientHello, ServerHello, Certificate, ServerKeyExchange, ClientKeyExchange, Finished. Quan trọng: phiên bản TLS, cipher suites, extensions (SNI, ALPN), compression.
* **JA3/JA3S:** fingerprinting chuỗi TLS ClientHello / ServerHello dựa trên ordered list của cipher suites, extensions, elliptic curves, point formats.
* **X.509 certificate:** subject, issuer, serial, validity, public key info, signature algorithm, extensions (SAN, key usage).
* **Certificate Transparency (CT):** public logs ghi nhận chứng chỉ được phát hành — sử dụng để phát hiện certificate mis-issuance.

---

## 6. Literature review (các hướng cần khảo sát)

* Các công trình về JA3/JA3S fingerprinting và ứng dụng trong malware detection.
* ML for network anomaly detection: autoencoders for flow data, LSTM for sequence anomalies, Isolation Forest.
* Certificate analysis: detection of misissued/fake certs using CT logs, graph-based detection of fraudulent CAs.
* Hybrid systems: combining signature-based IDS (Suricata) with ML detections.

> Yêu cầu: sinh viên nêu ít nhất 6 bài báo / technical reports và ít nhất 3 công cụ / repo tham khảo (Zeek/Bro logs parsing, JA3 implementations, Suricata).

---

## 7. Methodology (chi tiết đề xuất)

### 7.1. Scope & Use-cases

* **Use-cases mẫu:**

  * MitM with forged certificate (self-signed or CA-spoofed)
  * TLS downgrade / weak-cipher negotiation
  * Malware C2 channels mimicking legitimate TLS (JA3 evasion)
  * Certificate mis-issuance observed via CT logs

### 7.2. Data sources & collection

* **Passive network capture:** pcap files, Zeek/Bro logs, Suricata alerts.
* **Certificate sources:** parsed X.509 from pcap, CT logs (public), Certificate Transparency monitoring (certstream).
* **Meta/endpoint:** server/client IP reputations, WHOIS, DNS records (optional).

Tools: *tshark/pyshark*, *Zeek*, *Bro logs*, *scapy*, *ja3* implementations, *OpenSSL* for cert parsing.

### 7.3. Feature engineering

* **Handshake features:** JA3/JA3S strings, cipher suites one-hot or hashed, extension presence vector, ALPN, SNI (domain tokenized), TLS version, session resumption flag.
* **Temporal/context features:** connection duration, bytes exchanged, packet inter-arrival time, number of sessions from same client to same server.
* **Certificate features:** issuer common name, signature algorithm (e.g., SHA1 vs SHA256), public key size, key type (RSA/ECDSA), validity window length, SAN entries count/type, OCSP/CRL check status, CT inclusion.
* **Graph features:** certificate chain nodes, distances to known-root CAs, graph centrality if modeling many certs per time window.
* **Derived features:** entropy of SNI, prevalence of JA3 fingerprint in baseline window, rate-of-change features.

### 7.4. Modeling approaches

* **Unsupervised / anomaly detection:**

  * Autoencoder (dense or sequence) on feature vectors — anomaly if reconstruction error high.
  * Isolation Forest / One-Class SVM on baseline benign data.
  * Temporal models: LSTM/Transformer-based sequence anomaly detection for streams of handshakes.
* **Supervised classification:** RandomForest / XGBoost / Neural Networks trained on labeled benign vs malicious handshakes (if labeled data available).
* **Hybrid:** Ensemble of unsupervised scores + supervised classifier; use CT-based suspiciousness as additional signal.
* **Graph-based detection:** GNN on certificate chains (if modeling many certs across domains) to detect anomalous issuer behavior.

### 7.5. Thresholding & Calibration

* Use validation set to set thresholds that balance false positives vs detection rate; consider time-based smoothing and human-in-the-loop confirmation to reduce alert fatigue.

---

## 8. Implementation & Experiment Setup

### 8.1. Environment & Tools

* **Network tools:** Zeek (for full-featured logs), tshark/pyshark/scapy (pcap parsing), Suricata (IDS signatures).
* **Data store:** Elasticsearch/TimescaleDB/CSV for logs and features.
* **ML stack:** Python, pandas, scikit-learn, PyTorch/TensorFlow (for deep models), networkx (graph features).
* **Deployment:** Prototype as a plugin for Zeek or as a sidecar service (Flask/FastAPI) consuming logs from SIEM.

### 8.2. Datasets

* **Public pcaps & datasets:** CAIDA, MAWI, CT logs (public), malware TLS datasets (where available), academic datasets (e.g., ISCX), internal lab-generated traces (simulate MitM, forged certs).
* **Labeling:** simulate attacks to produce labeled malicious samples; for real-world unlabeled data, use semi-supervised methods.

### 8.3. Reproducibility

* Provide scripts to parse pcap → feature CSV, notebooks for training and evaluation, and Dockerfile with environment.

---

## 9. Evaluation Plan & Metrics

* **Detection metrics:** Precision, Recall, F1-score, ROC-AUC, PR-AUC. For operational fit: False Positive Rate per 1000 connections or alerts/day.
* **Time-to-detect / latency:** time from handshake to alert generation (important for inline blocking).
* **Explainability:** feature importance, saliency maps for sequence models, reasons for flagging (e.g., unknown JA3 + invalid cert signature).
* **Robustness:** test on unseen benign traffic (to measure false positives) and on varied attack techniques (to measure generalization).

**Baselines to compare:** rule-based heuristics (expired cert, self-signed, weak RSA key), JA3 fingerprint blacklist/whitelist, Suricata/Zeek signature alerts.

---

## 10. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Survey tài liệu, setup Zeek/tshark, thu thập dataset mẫu (benign + attack simulations).
* **Tuần 3–4:** Build feature extraction pipeline (pcap → features), EDA, baseline heuristics.
* **Tuần 5–6:** Implement unsupervised models (Isolation Forest, Autoencoder), evaluate on synthetic attacks.
* **Tuần 7–8:** Develop sequence/temporal models (LSTM/Transformer), incorporate certificate/CT signals.
* **Tuần 9:** Integrate ensemble/hybrid approach, threshold calibration.
* **Tuần 10:** Robustness tests, cross-dataset evaluation, ablation studies.
* **Tuần 11:** Prepare reproducible artifacts (Dockerfile, scripts), finalize experiments.
* **Tuần 12:** Final report, slides, demo & presentation.

---

## 11. Deliverables

1. **Mid-term presentation/report:** feature design, datasets, baseline results.
2. **Final report (PDF/MD):** full methodology, experiments, analysis, limitations.
3. **Code repository:** feature extraction scripts, model training/eval, Dockerfile, notebooks.
4. **Dataset excerpts / parsers:** small pcap examples and scripts to reproduce feature CSVs.
5. **Demo:** notebook or live demo showing detection on sample pcap or Zeek logs.

---

## 12. Assessment & Rubric (gợi ý)

* Research grounding & novelty: 20%
* Feature engineering & data pipeline correctness: 20%
* Modeling & evaluation rigor: 25%
* Reproducibility & code quality (Docker + docs): 20%
* Presentation & report quality: 15%

---

## 13. Risks, Limitations & Mitigation

* **Label scarcity:** use synthetic attack simulation and semi-supervised methods.
* **High false positives:** combine signals (CT + JA3 + heuristics), conservative thresholds, human-in-loop review.
* **Privacy/legal:** ensure pcap data sanitized/anonymized; obtain permission for any real traffic capture.
* **Evasion by attackers:** periodic model retraining, update JA3/CT whitelists/blacklists, incorporate adversarial robustness techniques.

---

## 14. Ethics & Responsible Use

* Không sử dụng hệ thống để tấn công; nếu phát hiện vấn đề thực tế, thực hiện responsible disclosure.
* Bảo vệ dữ liệu nhạy cảm trong pcap (PII), tuân thủ quy định dữ liệu.

---

## 15. Extensions & Future Work

* Real-time deployment as Zeek script or SIEM rule + model scoring service.
* Transfer learning to generalize across networks (enterprise → cloud).
* Integrate certificate transparency monitoring with model outputs for proactive alerting.

---

## 16. Tools & Resources gợi ý

* Zeek (Bro), Suricata, tshark/pyshark, scapy
* JA3/JA3S fingerprinting libraries
* OpenSSL for cert parsing; certstream / CT logs
* Python ML stack: scikit-learn, PyTorch/TensorFlow, networkx
* Datasets: MAWI, CAIDA, public pcaps, CT public logs

---

## 17. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ data/               # small pcap examples, parsed CSVs
  ├─ parsers/            # pcap -> zeek -> feature CSV scripts
  ├─ notebooks/          # EDA, demo notebooks
  ├─ src/
  |   ├─ features.py
  |   ├─ models/
  |   ├─ train.py
  |   └─ infer.py        # live scoring / offline scoring
  ├─ docker/             # Dockerfile, requirements.txt
  └─ report/             # final report, slides, demo
```

---
