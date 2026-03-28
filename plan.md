# Kế hoạch Thực nghiệm Thạc sĩ — An toàn Máy tính
# Đề tài: Phát hiện Ransomware dựa trên phân tích hành vi (NIST CSF 2.0)
# Thời gian: 6 ngày | Môi trường: Windows

---

## Mục tiêu

Xây dựng hệ thống phát hiện ransomware bằng SIEM (Wazuh) trên Windows,
ánh xạ vào hàm **Detect** của NIST CSF 2.0 và kiểm soát ISO 27001:2022.

---

## Kiến trúc hệ thống

```
Máy Windows (Host)
├── Wazuh Server (Docker Desktop for Windows)  ← SIEM, Dashboard
├── VirtualBox
│   └── VM Windows 10 (Host-Only network)      ← Victim, chạy ransomware
│       ├── Sysmon                              ← Thu log hành vi
│       └── Wazuh Agent                        ← Gửi log về server
└── Python 3.x (trên Host)                     ← Phân tích log, vẽ biểu đồ
```

---

## Lịch trình 6 ngày

### Ngày 1 — Cài đặt môi trường

**Sáng:**
- [ ] Cài **Docker Desktop for Windows** (bật WSL2)
- [ ] Pull và chạy Wazuh stack:
  ```bash
  git clone https://github.com/wazuh/wazuh-docker.git
  cd wazuh-docker/single-node
  docker compose up -d
  ```
- [ ] Truy cập Wazuh Dashboard: https://localhost (admin/SecretPassword)

**Chiều:**
- [ ] Cài **VirtualBox** trên Windows
- [ ] Tạo VM Windows 10 (RAM 2GB, HDD 40GB)
- [ ] Cấu hình network VM: **Host-Only Adapter** (cô lập, không ra Internet)
- [ ] Snapshot VM sạch (đặt tên: `CLEAN_BASELINE`)

**Kết quả ngày 1:** Wazuh chạy được, VM tạo xong, snapshot sạch.

---

### Ngày 2 — Cài công cụ giám sát trong VM

**Trong VM Windows 10:**
- [ ] Cài **Sysmon** với cấu hình SwiftOnSecurity:
  ```powershell
  # Chạy trong VM với quyền Admin
  sysmon64.exe -accepteula -i sysmonconfig.xml
  ```
  Config: https://github.com/SwiftOnSecurity/sysmon-config
- [ ] Cài **Wazuh Agent** (4.x) → cấu hình IP Wazuh Server = IP Host
- [ ] Khởi động Agent, kiểm tra kết nối:
  ```powershell
  NET START WazuhSvc
  ```
- [ ] Trên Wazuh Dashboard → Agents → VM phải hiện **Active**
- [ ] Cài **Python 3.x** trên Host + thư viện:
  ```bash
  pip install pandas matplotlib scikit-learn openpyxl
  ```

**Kết quả ngày 2:** Wazuh Agent kết nối thành công, log Sysmon đổ về dashboard.

---

### Ngày 3 — Thu thập mẫu & tạo baseline (hành vi bình thường)

**Sáng — Tạo baseline benign:**
- [ ] Trong VM: thực hiện các hoạt động bình thường 30–60 phút:
  - Mở Word, Excel, copy nhiều file, duyệt web (localhost)
  - Cài/gỡ phần mềm nhỏ
- [ ] Export log Sysmon từ Wazuh → lưu vào `data/benign_logs/`

**Chiều — Tải mẫu ransomware:**
- [ ] Đăng ký tài khoản tại **MalwareBazaar** (abuse.ch)
- [ ] Tìm và tải 3–5 mẫu ransomware (WannaCry, Ryuk, hoặc tương tự)
  - Lọc theo tag: `ransomware`, OS: `Windows`
  - File tải về: lưu vào Host (KHÔNG giải nén ngoài VM)
- [ ] Chuyển file mẫu vào VM qua Shared Folder (VirtualBox)

> **Lưu ý an toàn:**
> - Tắt Windows Defender trong VM trước khi chạy mẫu
> - Network VM phải là Host-Only
> - Luôn restore snapshot CLEAN_BASELINE trước mỗi lần chạy mẫu mới

**Kết quả ngày 3:** Có baseline log benign + mẫu ransomware sẵn sàng.

---

### Ngày 4 — Chạy thực nghiệm ransomware & thu log

**Quy trình mỗi mẫu:**
1. Restore snapshot `CLEAN_BASELINE`
2. Chụp ảnh màn hình trạng thái VM trước khi chạy
3. Chạy mẫu ransomware trong VM
4. Quan sát 5–10 phút:
   - Wazuh Dashboard → Alerts (tab Security Events)
   - Kiểm tra file bị mã hóa, Shadow Copy bị xóa
5. Export log → lưu vào `data/ransomware_logs/sample_X/`
6. Ghi lại: thời gian phát hiện đầu tiên (TTD), loại alert

**Lần lượt chạy 3–5 mẫu**, mỗi mẫu restore snapshot sạch.

**Viết custom rule Wazuh (nếu chưa có alert tự động):**
```xml
<!-- File: /var/ossec/etc/rules/ransomware_rules.xml (trong Docker container) -->
<group name="ransomware">
  <rule id="100300" level="14">
    <if_sid>61613</if_sid>
    <field name="win.eventdata.commandLine">vssadmin.*delete.*shadows</field>
    <description>Ransomware: Shadow Copy deletion (T1490)</description>
    <mitre><id>T1490</id></mitre>
  </rule>

  <rule id="100301" level="12">
    <if_sid>61613</if_sid>
    <field name="win.eventdata.image">.*\\cmd.exe</field>
    <field name="win.eventdata.commandLine">.*\.exe.*encrypt</field>
    <description>Ransomware: Mass encryption process detected</description>
  </rule>
</group>
```

**Kết quả ngày 4:** Log của 3–5 mẫu ransomware, bảng ghi TTD và alert type.

---

### Ngày 5 — Phân tích kết quả & đo lường chỉ số

**Sáng — Phân tích log với Python:**

Tạo script `analysis/evaluate.py`:
```python
import pandas as pd
import matplotlib.pyplot as plt

# Load log benign và ransomware từ CSV export của Wazuh
benign = pd.read_csv('data/benign_logs/alerts.csv')
ransomware = pd.read_csv('data/ransomware_logs/alerts.csv')

# Đếm alert theo rule_id
print("Top alerts (ransomware):")
print(ransomware['rule.id'].value_counts().head(10))

# Tính chỉ số
TP = ransomware[ransomware['rule.level'] >= 10].shape[0]
FP = benign[benign['rule.level'] >= 10].shape[0]
FN = ransomware[ransomware['rule.level'] < 10].shape[0]

precision = TP / (TP + FP) if (TP + FP) > 0 else 0
recall = TP / (TP + FN) if (TP + FN) > 0 else 0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

print(f"Precision: {precision:.2%}")
print(f"Recall (Detection Rate): {recall:.2%}")
print(f"F1-Score: {f1:.2%}")

# Vẽ biểu đồ
fig, ax = plt.subplots()
ax.bar(['TP', 'FP', 'FN'], [TP, FP, FN])
ax.set_title('Detection Results')
plt.savefig('results/detection_results.png')
```

**Chiều — Điền bảng kết quả:**

| Chỉ số | Kết quả thực nghiệm | Mục tiêu |
|---|---|---|
| Detection Rate (Recall) | __%  | ≥ 90% |
| False Positive Rate | __%  | ≤ 5%  |
| Precision | __%  | ≥ 85% |
| F1-Score | __%  | ≥ 87% |
| Time-to-Detect (TB) | __ giây | ≤ 60s |

**Kịch bản kiểm thử:**

| ID | Kịch bản | Kết quả | Ghi chú |
|---|---|---|---|
| TC-01 | Chạy WannaCry → có alert? | Pass/Fail | |
| TC-02 | Hoạt động bình thường → FP? | Pass/Fail | |
| TC-03 | Xóa Shadow Copy → có rule kích hoạt? | Pass/Fail | |
| TC-04 | Restore snapshot → hệ thống sạch? | Pass/Fail | |

**Kết quả ngày 5:** Bảng số liệu, biểu đồ, kết luận sơ bộ.

---

### Ngày 6 — Ánh xạ framework & hoàn thiện báo cáo

**Sáng — Ánh xạ NIST CSF 2.0:**

| Hàm NIST CSF | Hoạt động trong thực nghiệm |
|---|---|
| **Govern** | Xác định chính sách bảo vệ VM, phân công vai trò Observer/Analyst |
| **Identify** | Liệt kê tài sản: VM, file dữ liệu mẫu, log |
| **Protect** | Tắt Defender (controlled), cô lập mạng Host-Only, snapshot sạch |
| **Detect** | **Wazuh SIEM + Sysmon + Custom Rules** ← Trọng tâm thực nghiệm |
| **Respond** | Quy trình: phát hiện → dừng tiến trình → ghi nhận → cô lập VM |
| **Recover** | Restore snapshot CLEAN_BASELINE, kiểm tra toàn vẹn file |

**Đánh giá Implementation Tier:**
- Tier 1: Không có quy trình → **Không phải**
- **Tier 3 (Repeatable)**: Quy trình chuẩn hóa (snapshot → chạy → giám sát → đo lường) → **Đạt được**
- Tier 4: AI tự động thích nghi → Hướng mở rộng

**Ánh xạ ISO 27001:2022 Annex A:**

| Kiểm soát | Mô tả | Áp dụng trong TN |
|---|---|---|
| A.8.7 | Protection against malware | Wazuh phát hiện ransomware |
| A.8.15 | Logging | Sysmon → Wazuh log pipeline |
| A.8.16 | Monitoring activities | Wazuh Dashboard real-time |
| A.5.24 | IS incident management | Quy trình snapshot + restore |
| A.8.13 | Information backup | Snapshot = backup trước TN |

**Chiều — Hoàn thiện báo cáo:**

Cấu trúc báo cáo cuối:
1. Giới thiệu (ISO 27001, NIST CSF 2.0, Ransomware — lý thuyết)
2. Thiết kế môi trường thực nghiệm (sơ đồ kiến trúc)
3. Quy trình thực nghiệm (ngày 1–5)
4. Kết quả đánh giá (bảng số liệu, biểu đồ)
5. Ánh xạ NIST CSF 2.0 + ISO 27001:2022
6. Kết luận & Hướng mở rộng

---

## Cấu trúc thư mục dự án

```
ATMT/
├── plan.md                    ← File này
├── data/
│   ├── benign_logs/           ← Log hoạt động bình thường
│   └── ransomware_logs/       ← Log từng mẫu ransomware
│       ├── sample_wannacry/
│       ├── sample_ryuk/
│       └── ...
├── analysis/
│   └── evaluate.py            ← Script tính metrics
├── results/
│   ├── detection_results.png  ← Biểu đồ kết quả
│   └── metrics_table.xlsx     ← Bảng số liệu
└── report/
    └── bao_cao_thuc_nghiem.docx
```

---

## Công cụ cần cài (Windows)

| Công cụ | Link tải | Ghi chú |
|---|---|---|
| Docker Desktop | docker.com/products/docker-desktop | Bật WSL2 |
| VirtualBox | virtualbox.org | Tạo VM victim |
| Sysmon | docs.microsoft.com/sysinternals | Cài trong VM |
| Python 3.x | python.org | Cài trên Host |
| VS Code | code.visualstudio.com | Viết script |

---

## Checklist hoàn thành

- [ ] Ngày 1: Wazuh chạy, VM tạo xong
- [ ] Ngày 2: Wazuh Agent kết nối VM thành công
- [ ] Ngày 3: Có log benign, có mẫu ransomware
- [ ] Ngày 4: Chạy 3+ mẫu, có alert Wazuh
- [ ] Ngày 5: Bảng metrics (DR, FPR, TTD) hoàn chỉnh
- [ ] Ngày 6: Báo cáo hoàn thiện, ánh xạ NIST CSF + ISO 27001 xong
