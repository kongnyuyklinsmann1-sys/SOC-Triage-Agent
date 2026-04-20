# SOC Triage Agent 🛡️

An AI-powered security log triage pipeline that automatically detects threats, scores risk, and triggers firewall responses — built to combat alert fatigue in modern Security Operations Centers.

---

## 🚨 The Problem
SOC analysts are overwhelmed by thousands of raw logs daily. Manual triage is slow, leading to "breakout times" where attackers move laterally before a human even sees the alert.

## ⚡ The Solution
A Python-based AI agent that ingests raw logs, analyzes them using a custom Security Persona prompt, scores each threat using the MITRE ATT&CK framework, and automatically triggers firewall blocks for critical events.

---

## 🔧 Features
- **Natural Language Analysis** — Converts cryptic log strings into plain-English attack descriptions
- **MITRE ATT&CK Mapping** — Automatically labels each threat with the correct technique ID
- **Risk Scoring** — Assigns a 1-10 priority score to every detected event
- **Automated Response** — Triggers a webhook to block offending IPs when risk score exceeds 8
- **Secure Credentials** — API keys stored in environment variables, never hardcoded

---

## 📁 Project Structure
---

## 🚀 How to Run

### Prerequisites
- Python 3.10+
- OpenAI API key

### Installation
```bash
pip install openai python-dotenv requests
```

### Setup
Create a `.env` file in the root folder:
### Run
```bash
python v4-webhook-response/triage_agent_v4.py
```

---

## ⚠️ Known Limitations
- Static log file (no live ingestion yet)
- Mock firewall only (webhook.site)
- No memory between runs
- AI hallucinations possible on MITRE technique labeling
- No human approval gate for automated blocks

---

## 🗺️ Future Roadmap
- **v5** — Full multi-agent architecture with Perception Engine, Vector Memory, and Human-in-the-Loop
- **AWS Lambda** — Real-time cloud deployment for live log monitoring
- **SIEM Integration** — Direct integration with Splunk and QRadar
- **MITRE API Verification** — Cross-check AI labels against official MITRE database

---

## 🛠️ Tech Stack
Python • OpenAI API • python-dotenv • requests

---

*Built by KONGNYUY KLINSMANN — Cybersecurity student & enthusiast | Building security automation tools in an increasingly AI-driven world.*
