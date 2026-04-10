# DMARC Add-On Agent MVP

Lightweight visibility and troubleshooting tool for DMARC, DKIM, and SPF.

## Features
- Domain Analyzer
- Header Analyzer
- DMARC Aggregate XML parsing
- SPF lookup and expansion analysis
- DKIM selector and key strength checks
- Sender mapping and suspicious sender signals
- History and sender inventory export

## Run locally
```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m streamlit run app.py