# Capstone Project — Secure Network Protocols in IoT‑based Traffic Monitor for Smart Cities

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Secure Network Protocols in IoT‑based Traffic Monitor for Smart Cities — Bảo mật giao thức mạng cho hệ thống giám sát giao thông thông minh dựa trên IoT

---

## 1. Tóm tắt đề tài (Project Synopsis)

Mục tiêu: Thiết kế, triển khai và đánh giá một **mô hình hệ thống giám sát giao thông đô thị** (camera, loop sensor, radar/LiDAR, inductive sensors, vehicle probe via cellular, parking sensors) tập trung vào **bảo mật lớp mạng và giao thức** cho môi trường IoT có giới hạn tài nguyên. Sinh viên sẽ: (1) phân tích kiến trúc end‑to‑end (sensor → gateway → edge compute → cloud), (2) chọn và so sánh các giao thức mạng an toàn phù hợp (CoAP+OSCORE, DTLS, MQTT+TLS, LwM2M, LoRaWAN security), (3) triển khai prototype thu thập dữ liệu traffic, (4) mô phỏng tấn công thực tế (spoofing, replay, MITM, jamming, node capture), (5) đánh giá hiệu năng, năng lượng, khả năng mở rộng và rủi ro privacy, (6) đề xuất design patterns & operational playbooks để triển khai an toàn tại quy mô thành phố.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu các giao thức IoT phổ biến (6LoWPAN/RPL, CoAP, MQTT, LwM2M, LoRaWAN, NB‑IoT) và các lựa chọn bảo mật tương ứng (DTLS, OSCORE, TLS, LoRaWAN keys, cellular SIM/AKA).
2. Triển khai cơ chế xác thực & ủy quyền thiết bị (certificate‑based, PSK, ACE/OAuth for constrained devices, bootstrap protocols).
3. Thiết kế key management & provisioning an toàn (zero‑touch provisioning, EST/Enrollment over Secure Transport, LwM2M bootstrap, TPM/secure element).
4. Đo & so sánh overhead (latency, handshake cost, energy) giữa các giải pháp: DTLS vs OSCORE, certs vs PSK, ECDH vs PSK handshake.
5. Xây dựng testbed thí nghiệm (Raspberry Pi gateways, sensor nodes: ESP32/STM32/LoRa nodes) và thực hiện attack/emulation scripts để đánh giá rủi ro.

---

## 3. Tính cấp thiết & động lực (Relevance)

* Thành phố thông minh (Smart City) phụ thuộc vào mạng cảm biến phân tán để thu thập dữ liệu vận tải — nếu dữ liệu này bị giả mạo, bị gián đoạn hoặc rò rỉ, hậu quả bao gồm điều phối giao thông sai, tai nạn, xâm phạm quyền riêng tư công dân và mất tin cậy hệ thống.
* IoT devices thường có giới hạn về CPU, bộ nhớ và năng lượng; do đó, cần lựa chọn giao thức bảo mật phù hợp, lightweight nhưng vẫn an toàn.

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Giao thức bảo mật nào (CoAP+OSCORE, DTLS, MQTT/TLS, LwM2M bootstrap+DTLS) cân bằng tốt nhất giữa bảo mật, năng lượng và độ trễ trong use‑case traffic monitoring?

**RQ2:** Với tấn công thực tế (node capture, spoofing, jamming), mức độ rủi ro tài nguyên và dữ liệu là bao nhiêu và biện pháp phát hiện/khắc phục nào hiệu quả?

**RQ3:** Các chiến lược key provisioning (zero‑touch + TPM/SE vs pre‑shared keys) ảnh hưởng thế nào đến khả năng mở rộng, revocation và chi phí vận hành?

**Giả thuyết:** OSCORE + ACE (Token‑based constrained authorization) hoặc DTLS với certs (ECDHE, short‑lived certs) sẽ cung cấp sự bảo vệ đủ tốt cho hầu hết sensor→gateway flows; PSK rẻ và nhanh nhưng rủi ro khi phải revoke/scale. Tăng cường phát hiện bất thường (anomaly detection) giúp phát hiện node compromise nhanh hơn và giảm thời gian phơi nhiễm.

---

## 5. Kiến thức nền tảng (Background)

* **Network stacks:** 6LoWPAN + RPL cho IPv6 low‑power lossy networks; LoRaWAN (star‑of‑stars) cho long range low power; NB‑IoT / LTE‑M cho cellular connectivity.
* **Application layer protocols:** CoAP (RESTful for constrained devices), MQTT (pub/sub), LwM2M (device management).
* **Security primitives:** DTLS for UDP, TLS for TCP, OSCORE (object security for CoAP) — provides end‑to‑end security over intermediaries; EDHOC/EDHOC-like lightweight handshakes for constrained ECDH; ACE framework for constrained authorization (OAuth2 adaptation).
* **Device identity:** X.509 certs (full PKI) vs raw PSK vs ECDSA keys in secure elements; secure boot, firmware signing, TPM / Secure Element for root‑of‑trust.

---

## 6. Thành phần hệ thống & tài nguyên (System Components & Resources)

### 6.1. Edge & device tiers

* **Sensing layer:** inductive loops, magnetometer loops, camera units, radar/LiDAR units, vehicle probe (cellular). Devices vary widely: microcontrollers (STM32, nRF52), SoC (ESP32), camera SOCs (Raspberry Pi/Jetson Nano).
* **Gateway/Edge compute:** Raspberry Pi / NUC / industrial gateways that perform protocol translation (LoRaWAN → IPv6), local aggregation, basic analytics, and TLS/DTLS termination.
* **Secure element / TPM:** hardware module on device/gateway for key storage and attestations.

### 6.2. Network & connectivity

* **Short range LPWANs:** 6LoWPAN, Thread, BLE mesh (for local sensor mesh).
* **Long range LPWAN:** LoRaWAN with Network Server (ChirpStack) and Join server (OTAA).
* **Cellular:** NB‑IoT/LTE‑M for vehicle probes; SIM/A‑SIM for authentication.

### 6.3. Backend & cloud

* **Edge orchestration & stream ingestion:** Kafka/MQTT Broker/NGINX or MQTT/EMQX, data lake (TimeSeries DB like InfluxDB/Timescale), stream processing (Flink/ksql).
* **Device management & provisioning:** LwM2M server (Eclipse Leshan), EST/ACME/EST for cert provisioning, HashiCorp Vault for secret management.
* **Analytics & control center:** dashboards (Grafana), anomaly detection (ML models), command & control for actuations (signal timing changes).

### 6.4. Testbed hardware & software

* MCU dev boards (STM32 Nucleo, ESP32), LoRa nodes + gateways (Dragino, The Things Stack or ChirpStack), Raspberry Pi for gateway/edge, SDR (USRP/RTL‑SDR) for radio testing & jamming simulation, wired network lab, virtualization (k8s/minikube) for backend.

---

## 7. Kịch bản triển khai thực tế (Deployment Scenarios)

### 7.1. City‑wide Baseline Deployment

* Thousands of low‑power sensors (loops/parking sensors) communicate via 6LoWPAN mesh to regional gateways; cameras & radars use cellular or wired links; gateways forward encrypted telemetry to regional edge nodes for real‑time processing; central cloud aggregates long‑term analytics.

### 7.2. High‑Density Downtown Scenario

* Many camera & radar units with higher bandwidth → use LTE/5G or fiber backhaul; focus on low latency for traffic control. Higher security requirements (video PII) → hardware TEE on device and end‑to‑end encryption.

### 7.3. Opportunistic/Temporary Deployment

* Events (festivals) require temporary sensors and pop‑up gateways; zero‑touch provisioning & fast, secure enrollment needed.

---

## 8. Phân tích weaknesses & kịch bản tấn công thực tế (Deep Weakness Analysis)

### 8.1. Physical & Node Capture

* **Threat:** attacker obtains physical access to sensor node (camera/loop) and extracts keys (flash memory) or replaces firmware.
* **Impact:** impersonation, data spoofing, loss of confidentiality/regulatory breach (video).
* **Root causes:** lack of secure boot, no secure element, plaintext firmware or keys in flash.

### 8.2. Spoofing & Replay Attacks

* **Threat:** forged sensor reports or replayed legitimate telemetry cause wrong traffic decisions.
* **Impact:** false congestion alerts, misrouted traffic, safety issues.
* **Contributing factors:** absence of per‑message freshness (nonces/timestamps), use of unauthenticated UDP, PSK reuse.

### 8.3. MITM & TLS/DTLS downgrade

* **Threat:** attacker in network path strips or downgrades security, or terminates TLS at rogue gateway.
* **Impact:** data interception, commands injection.
* **Contributing factors:** weak certificate validation on device, accepting self‑signed certs, lack of pinning.

### 8.4. Jamming & Denial of Service (radio & network)

* **Threat:** RF jamming (LoRa, NB‑IoT) or network DDoS on brokers/edge nodes.
* **Impact:** data loss, loss of situational awareness.
* **Contributing factors:** single radio technologies dependency, no multi‑path redundancy, lack of anomaly detection.

### 8.5. Supply Chain & Firmware Tampering

* **Threat:** compromised firmware image distributed via OTA or compromised vendor supply chain.
* **Impact:** backdoor in fleet, mass compromise.
* **Contributing factors:** unsigned firmware updates, weak OTA auth, weak CI/CD signing.

### 8.6. Key management & scalability failures

* **Threat:** widespread use of shared PSK or static keys leads to large blast radius on compromise.
* **Impact:** mass impersonation and inability to revoke keys effectively.
* **Contributing factors:** no zero‑touch PKI, manual provisioning, lack of revocation mechanism for constrained devices.

### 8.7. Privacy & Data Retention Risks

* **Threat:** traffic camera feeds, vehicle trajectories reveal PII.
* **Impact:** privacy violations (GDPR), reputational & legal consequences.
* **Contributing factors:** long‑term retention of raw video, lack of anonymization, inadequate access controls.

---

## 9. Methodology (Pipeline & Experiments)

### 9.1. Lab testbed design

* **Topology:** multiple sensor nodes (ESP32, LoRa nodes) → gateway (Raspberry Pi) → edge compute (k8s) → cloud backend.
* **Protocol variants to evaluate:** CoAP+OSCORE, CoAP+DTLS, MQTT+TLS, LoRaWAN OTAA vs ABP, LwM2M bootstrap + DTLS, NB‑IoT simulated via emulator.

### 9.2. Experiments (suggested)

1. **Performance & energy benchmarks:** measure handshake energy/time for DTLS (ECDHE\_ECDSA), OSCORE (no handshake but token provisioning), EDHOC (if available) on sensor MCU; evaluate message overhead and round‑trip latency for telemetry rates (1 msg/sec, 1 msg/min).
2. **Provisioning & scalability:** test zero‑touch enrollment flow (EST/ACME or LwM2M Bootstrap) for bulk enrollment (1000s devices) and measure time to provision & key distribution cost.
3. **Attack emulation:** run spoofing/replay tests (Scapy), MITM (rogue gateway), and jamming simulation (SDR) to quantify detection & recovery time.
4. **Node capture simulation:** emulate node compromise by extracting keys from dev‑board image and attempt impersonation of device; evaluate revocation & re‑provisioning.
5. **Privacy & retention policy tests:** evaluate anonymization pipeline for video (blur license plates, faces), and measure impact on analytics accuracy.

### 9.3. Detection & mitigation experiments

* **Anomaly detection:** implement simple anomaly detector (statistical/ML) on edge to spot unusual telemetry patterns (sudden identity changes, duplicate IDs) and measure true/false positive rate.
* **Key revocation drills:** simulate key compromise and execute revocation & re‑enrollment playbook; measure time to isolate compromised device.

---

## 10. Implementation & Tools

* **Device OS & stacks:** RIOT OS / Contiki‑NG / Zephyr for constrained nodes; MbedTLS / TinyDTLS / tinydtls / wolfSSL for DTLS; libcoap + OSCORE implementations (Californium, copper for CoAP testing), Eclipse Leshan (LwM2M server).
* **LoRaWAN:** ChirpStack (network + application servers) and LoRa nodes (SX127x modules).
* **MQTT & brokers:** EMQX, Mosquitto.
* **Provisioning & PKI:** HashiCorp Vault, Smallstep/step‑ca (ACME-like), EST server; TPM/secure element (ATECC608A), secure boot toolchains.
* **Testing & attack tools:** Scapy, Wireshark, GNU Radio + SDR (RTL‑SDR/USRP) for jamming/emulation, Sediq for RPL attacks, node emulators.
* **Backend & analytics:** Kubernetes, Kafka, InfluxDB/Timescale, Grafana, Python ML stack (scikit‑learn, pytorch) for anomaly detection.

---

## 11. Evaluation Plan & Metrics

* **Security metrics:** % successful spoofing attempts, % detected anomalies, time‑to‑detect compromise, revocation latency, false positive/negative rates.
* **Performance metrics:** handshake latency (median/p95), message RTT, energy per message & per handshake (mJ), throughput (msg/sec per gateway), CPU/memory on constrained nodes.
* **Operational metrics:** provisioning time per device, key rotation time, OTA update time & success rate, cost estimate for city scale.

---

## 12. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Survey giao thức (CoAP, OSCORE, DTLS, MQTT), chọn testbed hardware, thiết lập infra k8s.
* **Tuần 3–4:** Build basic sensor → gateway → cloud pipeline; implement CoAP+DTLS and MQTT+TLS flows.
* **Tuần 5–6:** Implement provisioning flow (EST / LwM2M bootstrap) and test zero‑touch enrollment at scale (emulation).
* **Tuần 7–8:** Run performance & energy benchmarks for handshake & messaging; compare DTLS vs OSCORE.
* **Tuần 9:** Conduct attack emulation (spoofing/replay/MITM) and evaluate detection/mitigation.
* **Tuần 10:** Run jamming & node capture simulations; test revocation & re‑enrollment playbook.
* **Tuần 11:** Privacy & retention experiments (video anonymization), finalize recommended architecture.
* **Tuần 12:** Final report, reproducible repo (Docker/helm + device images), slides & demo video.

---

## 13. Deliverables

1. **Mid‑term:** architecture, testbed plan, selected protocols & threat model.
2. **Final report:** implementation details, experiments, metrics, recommendations & playbooks.
3. **Code repo & artifacts:** device code, gateway code, backend k8s manifests, attack scripts, measurement logs & plots.
4. **Operational runbooks:** zero‑touch provisioning, incident response, revocation & re‑enrollment procedures.
5. **Demo:** recorded demo showing secure telemetry flow and at least two attack/mitigation scenarios.

---

## 14. Assessment & Rubric (gợi ý)

* Design & threat modeling: 20%
* Implementation & reproducibility (testbed & scripts): 30%
* Experimental rigor & analysis (benchmarks + attacks): 30%
* Documentation & operational guidance: 20%

---

## 15. Risks, Limitations & Ethical Considerations

* **Radio experiments & jamming:** do not perform RF jamming in public spectrum—use shielded lab or local legal channels; prefer simulation.
* **Privacy:** video data must be synthetic or anonymized; do not collect real citizen PII without consent and legal review.
* **Hardware availability:** constrained devices/secure elements may be limited; use emulation when necessary and document differences.

---

## 16. Mitigations & Best Practices (summary recommendations)

* **Hardware root‑of‑trust:** use secure element / TPM for key storage and attestations; enable secure boot and signed firmware.
* **Protocol choices:** prefer OSCORE for CoAP when intermediaries present; DTLS with ECDHE & certificates for gateways; MQTT over TLS with client certs for higher‑bandwidth nodes.
* **Provisioning & revocation:** zero‑touch enrollment with per‑device certs, short‑lived certs & automatic rotation, and scalable revocation (OCSP/short‑lived tokens).
* **Defense‑in‑depth:** network segmentation, redundant comm channels (cellular + LoRa), edge anomaly detection, signed telemetry & per‑message freshness (nonces/timestamps).
* **Privacy by design:** anonymize or aggregate PII at edge; retention policies & access controls; differential privacy for shared analytics.

---

## 17. Extensions & Future Work

* **EDHOC & ACE integration:** evaluate EDHOC (lightweight ECDH) + ACE OAuth for constrained environments.
* **PQC readiness:** roadmap for PQC in IoT (where to use hybrid handshakes) and impact on energy.
* **Automated device attestation pipelines:** integration with cloud attestation services (Azure/Google attestation) for fleet‑wide integrity checks.

---

## 18. Tools & Resources gợi ý

* RIOT OS, Contiki‑NG, Zephyr, MbedTLS, TinyDTLS, libcoap, Eclipse Leshan, ChirpStack, Mosquitto/EMQX, HashiCorp Vault, Smallstep/step‑ca, Scapy, Wireshark, GNU Radio, RTL‑SDR, USRP (lab), Prometheus/Grafana, Kafka.

---

## 19. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ devices/            # MCU code (Contiki/Zephyr) + dockerized MC emulator
  ├─ gateway/            # RaspberryPi gateway code (coap/mqtt proxies, DTLS/OSCORE configs)
  ├─ backend/            # k8s manifests, ingestion pipelines, analytics services
  ├─ provisioning/       # EST/LwM2M bootstrap scripts, step‑ca configs
  ├─ attacks/            # scapy scripts, sdr jamming stubs (simulated), node capture emulation
  ├─ benchmarks/         # handshake energy scripts, latency tests, raw CSVs
  └─ docs/               # report, runbooks, slides, demo video
```

---
