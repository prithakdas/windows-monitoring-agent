# 🛡️ Windows Monitoring Agent

A lightweight Windows-based monitoring agent designed to detect suspicious processes and services using behavioral analysis, rule-based detection, and whitelist filtering.

---

## 🚀 Features

- Real-time monitoring of system processes and services  
- Behavioral-based detection (Temp/AppData execution, anomalies)  
- Rule-based detection (parent-child relationships, suspicious paths)  
- Whitelist filtering to reduce false positives  
- Automated JSON report generation  
- Activity and alert logging system  

---

## 🧠 Detection Techniques

### Behavioral Detection
- Detects execution from suspicious directories like AppData and Temp  
- Identifies abnormal process behavior  
- Flags suspicious naming patterns  

### Rule-Based Detection
- Detects suspicious parent-child relationships  
  - Example: winword.exe → powershell.exe  
- Uses configurable rules from rules.json  

### Whitelist Filtering
- Excludes trusted processes  
- Minimizes false positives  

---

## 📁 Project Structure

windows-monitoring-agent/

├── main.py  
├── config/  
│   ├── rules.json  
│   ├── whitelist.json  
├── core/  
│   ├── detector.py  
│   ├── logger.py  
│   ├── process_monitor.py  
│   ├── service_monitor.py  
│   ├── utils.py  
├── logs/  
├── reports/  
├── requirements.txt  
├── README.md  

---

## ⚙️ Installation

1. Clone the repository:
git clone https://github.com/your-username/windows-monitoring-agent.git  
cd windows-monitoring-agent  

2. Install dependencies:
pip install -r requirements.txt  

---

## ▶️ Usage

Run the monitoring agent:
python main.py  

---

## 📊 Output

Console Output:
- Displays detected alerts and summary  

Logs:
- logs/activity.log → System activity  
- logs/alerts.log → Detected alerts  

Report:
- reports/final_report.json  

Includes:
- Metadata (timestamp, process count, service count)  
- Alert summary  
- High severity alerts  
- Full alert list  

---

## 🎯 Example Detection

- Suspicious execution from Temp/AppData  
- Office applications spawning shell commands  
- Suspicious process behavior  

---

## ⚠️ Note

This tool uses behavioral detection, so some legitimate installers may be flagged.  
Logs and reports are generated at runtime and are excluded from the repository.  

---

## 🧪 Technologies Used

- Python  
- psutil  
- WMI  

---

## 📌 Future Improvements

- Blacklist integration (signature-based detection)  
- Real-time continuous monitoring  
- GUI dashboard  
- Threat intelligence integration  

---

## 👨‍💻 Author

**Prithak Das**  
Master’s in Advanced Networking & Cybersecurity  
Developed as a cybersecurity project demonstrating process monitoring, threat detection, and system analysis techniques.

---

## ⭐ Acknowledgment

Inspired by real-world endpoint detection systems (EDR/SIEM) used in cybersecurity.
