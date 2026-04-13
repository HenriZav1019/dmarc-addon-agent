# DMARC Add-On Agent

A lightweight analysis tool for DMARC, SPF, and DKIM with sender intelligence and aggregate report insights.

## 🔗 Live App

(https://henrizav1019-dmarc-addon-agent-app-mmbumf.streamlit.app/)

---

## ✨ Features

### 🌐 Domain Analyzer

* DMARC, SPF, DKIM validation
* SPF deep analysis (includes, lookups, expansion)
* DKIM selector discovery
* Health scoring and recommendations

### 📧 Header Analyzer

* Authentication results parsing (SPF, DKIM, DMARC)
* Sender identity breakdown
* Alignment analysis
* Suspicious / shadow sender detection
* DNS enrichment

### 🕘 History

* Saved domain scans
* Sender inventory tracking
* Trend visualization

### 📥 DMARC Reports

* Aggregate XML parsing
* Priority issue detection
* Sender correlation
* High-risk source identification

---

## 🧠 Use Cases

* Email security troubleshooting
* DMARC policy deployment
* Identifying unauthorized senders
* SPF optimization
* Vendor / sender validation

---

## ⚙️ Run locally

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python -m streamlit run app.py
```

---

## 🚀 Deployment

This app is deployed using Streamlit Community Cloud and automatically updates from GitHub.

---

## 📌 Author

Henri Zavala


## Run locally
```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m streamlit run app.py
