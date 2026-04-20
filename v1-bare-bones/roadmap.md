# SOC Triage Agent - Project Roadmap

## v1 - Bare Bones (COMPLETE)
Date: April 19, 2026
- Python reads sample_logs.txt
- Sends logs to GPT-4o-mini
- Returns full security analysis in terminal
- Security Persona: Expert SOC Analyst + SRE

## v2 - Structured Output (NEXT)
- Make the AI return a consistent JSON format
- Add risk score 1-10 for each event
- Add MITRE ATT&CK technique labels

## v3 - Risk Scoring
- Auto-flag anything scored 8 or above
- Color code output by severity

## v4 - Webhook Response
- Auto-trigger mock firewall block for Critical events

## v5 - Multi-Agent Architecture
- Perception Engine
- The Watchman
- The Researcher
- The Reporter
- Vector Memory
- Human in the Loop
- Mythos-Proofing
## v2 - Structured Output (COMPLETE)
Date: April 19, 2026
- AI now returns clean JSON format
- Each event has severity, risk score, MITRE technique and recommendation
- Python parses and displays each event consistently
## v3 - Risk Scoring (COMPLETE)
Date: April 19, 2026
- Script now detects events with risk score above 8
- High risk events trigger a loud visual alert
- Low risk events print normally
- New concept learned: if/else logic
## v4 - Webhook Response (COMPLETE)
Date: April 19, 2026
- Script now extracts IP address from critical events
- Automatically sends block command to mock firewall
- Firewall confirmed receipt with status 200
- New concepts learned: HTTP requests, webhooks, status codes
## Known Limitations & v5 Fixes

### 1. Exposed API Key
- Current: sk- key sits in plain text inside every Python file
- Risk: Anyone who opens the code can steal it and use your OpenAI credits
- Fix in v5: Environment variables to hide all sensitive credentials

### 2. Static Log File
- Current: Script only reads one manually created text file
- Risk: Useless in a real SOC environment with live streaming logs
- Fix in v5: Perception Engine for real-time multi-source log ingestion

### 3. No Error Handling
- Current: If AI returns imperfect JSON the entire script crashes
- Risk: One bad AI response takes down the whole pipeline
- Fix in v5: Try/catch error handling so script fails gracefully

### 4. AI Hallucinations
- Current: AI can assign wrong MITRE techniques or incorrect risk scores
- Risk: Analysts act on bad data, wrong playbooks get triggered
- Fix in v5: Second AI verification + MITRE ATT&CK API cross-check + confidence scoring

### 5. No Memory
- Current: Every run starts completely fresh
- Risk: Cannot detect patterns or connect related incidents over time
- Fix in v5: Vector Memory layer using Pinecone or ChromaDB

### 6. Mock Firewall Only
- Current: webhook.site just displays the block command, nothing actually blocked
- Risk: No real defensive action taken
- Fix in v5: Real firewall API integration

### 7. Single Log Source
- Current: Only reads one text file
- Risk: Misses threats coming from other systems
- Fix in v5: Multi-source ingestion pulling from Windows Event Logs, Linux syslogs, firewalls, and cloud services

### 8. No Human Approval for Critical Actions
- Current: Script auto-fires block command if risk score exceeds 8
- Risk: Legitimate users could get blocked by a hallucinated score
- Fix in v5: Human-in-the-Loop layer requiring manual confirmation for Critical events

### 9. No Dashboard or Logging
- Current: Results print to terminal and disappear
- Risk: No record of past analyses, blocked IPs, or trends
- Fix in v5: Reporter layer sends structured reports to Slack and stores results permanently

### 10. No Prompt Injection Protection
- Current: Malicious log entries could manipulate the AI analysis
- Risk: Attacker crafts a log line saying "ignore previous instructions"
- Fix in v5: Mythos-Proofing layer with input sanitization and reasoning logs

---
## v5 Build Order
1. Fix API key exposure
2. Add error handling
3. Add real log ingestion
4. Add memory layer
5. Add human approval gate
6. Add dashboard and logging
7. Add hallucination verification
8. Add prompt injection protection

## Security Updates (April 19, 2026)
- API key moved to .env file
- .gitignore created to protect secrets
- All versions updated to read from .env
- Project is now safe to upload to GitHub
## Next Session - To Do
1. Set up GitHub account
2. Create repository for SOC-Triage-Agent
3. Push all files to GitHub
4. Add README.md to the project
5. Begin planning v5 multi-agent architecture
## GitHub Setup (COMPLETE)
Date: April 20, 2026
- GitHub account created: kongnyuyklinsmann1-sys
- Repository published: github.com/kongnyuyklinsmann1-sys/SOC-Triage-Agent
- README.md written and live
- .gitignore protecting .env file
- Old API key rotated and replaced with new key

## Next Session - To Do
1. Start Project 2 - Phishing DNA Analyzer
2. Create new repository for Project 2
3. Continue building toward v5 multi-agent architecture