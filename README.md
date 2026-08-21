# VulnScan-Lite
On-Demand Web Vulnerability Scanner
VulnScan Lite is a full‑stack web vulnerability scanner built with:
- *FastAPI* (backend REST API)
- *Celery + Redis* (asynchronous task queue)
- *React + Vite* (frontend UI)

It scans websites for common security headers, SSL certificate validity, and CMS detection, then displays results in a modern dashboard with exportable PDF reports.


# 🚀 Features
- Website vulnerability scanning (headers, SSL, CMS)
- Asynchronous task handling with Celery workers
- Gauge chart for security score visualization
- Export scan results as PDF
- Clean React UI with responsive design


# 📂 Project Structure
<img width="435" height="606" alt="image" src="https://github.com/user-attachments/assets/aa10b5c7-2ee9-4f66-afe6-d962c3e92d0c" />




## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/Kamini2-6/Vulnscan-Lite.git
cd vulnscan-lite

2. Backend Setup (FastAPI + Celery + Redis)

Install dependencies:
pip install -r requirements.txt

Run FastAPI server:
uvicorn src.main:app --reload
or
python -m uvicorn main:app --reload

Start Redis server (or Memurai on Windows):
redis-server

You can install memurai for redis using: https://www.memurai.com/get-memurai

Run Celery worker:
celery -A Scanner.tasks worker --loglevel=info
or
python -m celery -A Scanner.tasks.celery_app worker --loglevel=info --pool=solo

Frontend Setup (React + Vite)
Go to frontend folder: cd vulnscan-lite-frontend
npm install
npm run dev
👉 App will be available at: http://localhost:5173/

Usage / instruction to use this app

Enter a website URL in the input box.

Click Scan to start vulnerability analysis.

View results:
->Security headers status
->SSL certificate validity
->CMS detection
->Security score gauge
->Export results as PDF.

