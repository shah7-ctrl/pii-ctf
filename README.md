# Project Guardian 2.0 – Real-time PII Defense

## Overview
Project Guardian 2.0 is a security-first system designed to **detect, redact, and prevent leakage of Personally Identifiable Information (PII)** in real-time across e-commerce infrastructure.  

The system integrates at multiple layers (client, frontend, backend, and external services) to ensure **low-latency detection**, **scalable deployment**, and **defense-in-depth against data breaches**.  

## 📂 Repository Structure
├── detector_full_candidate_name.py             # PII detection script
├── iscp_pii_dataset_-_Sheet1.csv               # Input dataset
├── redacted_output_candidate_full_name.csv     # Redacted results
├── requirements.txt                            # Python dependencies
├── README.md                                   # Documentation


---

## System Architecture

### 1. Client Layer
- **Security Engineer (Browser)**  
  - Primary interface for monitoring and validating redaction activity.  
  - Interacts via **Analyzer Chat UI** and **Dashboard**.

---

### 2. Frontend Layer (Next.js + Tailwind)
- **Auth Middleware (cookie)**  
  - Handles user authentication and session management.  

- **Admin Panel (Config + SOPs + Users)**  
  - Allows configuration of PII detection/redaction policies.  
  - Manage **Standard Operating Procedures (SOPs)** and user roles.  

- **Analyzer Chat UI**  
  - Interactive interface for analyzing logs and PII detection results.  

- **Dashboard (Bento + Logs + Tools)**  
  - Provides centralized monitoring: logs, analysis, redaction events, and system health.  

- **API Routes Proxy (`/api/*`)**  
  - Acts as the bridge to backend services, securing requests and applying routing logic.  
  - Uses **Server-Sent Events (SSE)** for real-time streaming of logs and alerts.  

---

### 3. Backend Layer (Express + MCP)
- **MCP Server**  
  - Provides core analysis and tooling:
    - `analyze_findings`
    - `redact_pii`
    - `trufflehog_prop`
    - `browse_url`
    - `snyk_token_status`

- **SOP Service**  
  - Handles search, upsert, enable/disable of SOPs.  
  - Ensures compliance workflows are followed.  

- **API Endpoints**
  - `/api/analyze`, `/api/analyze/stream` – Run real-time log analysis & redaction.  
  - `/api/logs` (SSE), `/api/logs/recent` – Stream or fetch recent logs.  
  - `/api/users`, `/api/auth/verify`, `/api/validate` – Authentication and policy enforcement.  
  - `/api/tools` – Access to integrated analysis/redaction tools.  

---

### 4. Database Layer (SQLite)
- **analyses** – Stores detection and redaction results.  
- **sops** – Stores Standard Operating Procedures (security rules/policies).  
- **users** – Authentication and access control.  

---

### 5. External Services & Tools
- **Google Gemini (Gen + Embeddings)** – NLP + Embeddings for smarter detection of unstructured PII.  
- **GitHub/GHE (Octokit + Raw)** – Source scanning for code leaks.  
- **Snyk (token status)** – Vulnerability/token scanning.  
- **Trufflehog CLI** – Secret scanning in code, configs, and logs.  
- **HTTP GET (browse_url)** – Safe browsing and link analysis.  

---

## Data Flow (PII Detection & Redaction)
1. Logs & data enter the **Backend (`/api/analyze`)**.  
2. **MCP Server tools** scan for PII (regex, ML, NER, embeddings).  
3. Detected PII is redacted/masked before being passed downstream.  
4. Results stored in **SQLite (analyses)** for auditing.  
5. Engineers visualize findings via **Dashboard** and **Chat UI**.  
6. Alerts/Logs streamed in **real-time** via SSE.  

---

## Deployment Strategy
- **Frontend:** Deploy as a Next.js app with Tailwind styling.  
- **Backend:** Containerized Express + MCP services, scalable via Kubernetes.  
- **Database:** Lightweight SQLite for POC, can migrate to Postgres/MySQL for production.  
- **PII Detection Daemon:** Deploy as **Sidecar container** or **API Gateway plugin** for in-flight data inspection.  
- **Monitoring:** Integrated into Security Engineer Dashboard with real-time streaming.  
- **Scaling:** Stateless backend services → horizontal scaling possible with Kubernetes or ECS.  

---

## Key Features
- 🔒 Real-time PII detection & redaction (phones, Aadhaar, passport, UPI, names, addresses).  
- ⚡ Low-latency processing (streaming logs via SSE).  
- 🛡️ Defense-in-depth (network + app-layer sanitization).  
- 📊 Centralized Dashboard for security engineers.  
- 🔍 External integrations (Snyk, Trufflehog, Gemini AI) for broader threat coverage.  

---

## Quick Start
```bash
# Install dependencies
npm install   # frontend
pip install -r requirements.txt   # backend PII detector

# Start frontend
npm run dev

# Start backend
python detector_full_candidate_name.py iscp_pii_dataset_-_Sheet1.csv
