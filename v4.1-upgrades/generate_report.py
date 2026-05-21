# Import json to read our scan log
import json

# Import os to check if files exist
import os

# Import datetime for report generation timestamp
from datetime import datetime

# Define the path to our scan log
LOG_FILE = "v4.1-upgrades/scan_log.json"

# Define the output path for our HTML report
REPORT_FILE = "v4.1-upgrades/report.html"

# ============================================================
# LOAD SCAN DATA
# ============================================================

# Check if log file exists
if not os.path.exists(LOG_FILE):
    print("❌ No scan log found. Run triage_agent_v4_1.py first.")
    exit()

# Load the scan log
with open(LOG_FILE, "r") as f:
    scans = json.load(f)

# ============================================================
# CALCULATE STATISTICS
# ============================================================

# Total number of scans
total_scans = len(scans)

# Collect all events across all scans
all_events = []
for scan in scans:
    all_events.extend(scan["events"])

# Count total events
total_events = len(all_events)

# Count events by severity
critical_count = sum(1 for e in all_events if e["severity"] == "Critical")
high_count = sum(1 for e in all_events if e["severity"] == "High")
medium_count = sum(1 for e in all_events if e["severity"] == "Medium")
low_count = sum(1 for e in all_events if e["severity"] == "Low")

# Collect all blocked IPs across all scans
all_blocked_ips = []
for scan in scans:
    all_blocked_ips.extend(scan["blocked_ips"])

# Remove duplicates from blocked IPs
unique_blocked_ips = list(set(all_blocked_ips))

# Collect all MITRE techniques used
mitre_techniques = {}
for event in all_events:
    technique = event["mitre_technique"]
    if technique in mitre_techniques:
        mitre_techniques[technique] += 1
    else:
        mitre_techniques[technique] = 1

# Sort MITRE techniques by frequency
sorted_mitre = sorted(mitre_techniques.items(), key=lambda x: x[1], reverse=True)

# ============================================================
# GENERATE HTML REPORT
# ============================================================

html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Triage Agent - Security Report</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #0a0a0a;
            color: #00ff41;
            margin: 0;
            padding: 20px;
        }}
        .header {{
            text-align: center;
            border: 1px solid #00ff41;
            padding: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            font-size: 28px;
            margin: 0;
            text-shadow: 0 0 10px #00ff41;
        }}
        .header p {{
            color: #888;
            margin: 5px 0 0 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            border: 1px solid #00ff41;
            padding: 15px;
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 36px;
            font-weight: bold;
        }}
        .stat-card .label {{
            font-size: 12px;
            color: #888;
            margin-top: 5px;
        }}
        .critical {{ color: #ff0000; border-color: #ff0000; }}
        .high {{ color: #ff8c00; border-color: #ff8c00; }}
        .medium {{ color: #ffd700; border-color: #ffd700; }}
        .low {{ color: #00ff41; }}
        .section {{
            border: 1px solid #333;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .section h2 {{
            color: #00ff41;
            margin-top: 0;
            border-bottom: 1px solid #333;
            padding-bottom: 10px;
        }}
        .event-card {{
            border-left: 3px solid #00ff41;
            padding: 10px 15px;
            margin-bottom: 10px;
            background-color: #0f0f0f;
        }}
        .event-card.critical {{ border-left-color: #ff0000; }}
        .event-card.high {{ border-left-color: #ff8c00; }}
        .event-card.medium {{ border-left-color: #ffd700; }}
        .blocked-ip {{
            display: inline-block;
            background-color: #ff000022;
            border: 1px solid #ff0000;
            color: #ff0000;
            padding: 5px 10px;
            margin: 5px;
            font-size: 14px;
        }}
        .mitre-row {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #1a1a1a;
        }}
        .scan-meta {{
            color: #888;
            font-size: 12px;
            margin-bottom: 5px;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            font-size: 11px;
            margin-left: 10px;
        }}
        .badge.critical {{ background: #ff000033; color: #ff0000; }}
        .badge.high {{ background: #ff8c0033; color: #ff8c00; }}
        .badge.medium {{ background: #ffd70033; color: #ffd700; }}
        .badge.low {{ background: #00ff4133; color: #00ff41; }}
    </style>
</head>
<body>

    <div class="header">
        <h1>🛡️ SOC TRIAGE AGENT — SECURITY REPORT</h1>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Total Scans: {total_scans}</p>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="number">{total_events}</div>
            <div class="label">TOTAL EVENTS</div>
        </div>
        <div class="stat-card critical">
            <div class="number">{critical_count}</div>
            <div class="label">CRITICAL</div>
        </div>
        <div class="stat-card high">
            <div class="number">{high_count}</div>
            <div class="label">HIGH</div>
        </div>
        <div class="stat-card medium">
            <div class="number">{medium_count}</div>
            <div class="label">MEDIUM</div>
        </div>
    </div>

    <div class="section">
        <h2>🚫 BLOCKED IP ADDRESSES ({len(unique_blocked_ips)})</h2>
        {"".join(f'<span class="blocked-ip">{ip}</span>' for ip in unique_blocked_ips) if unique_blocked_ips else '<p style="color:#888">No IPs blocked yet.</p>'}
    </div>

    <div class="section">
        <h2>📊 MITRE ATT&CK TECHNIQUES DETECTED</h2>
        {"".join(f'<div class="mitre-row"><span>{technique}</span><span style="color:#888">{count} occurrence(s)</span></div>' for technique, count in sorted_mitre)}
    </div>

    <div class="section">
        <h2>📋 SCAN HISTORY</h2>
        {"".join(f'''
        <div style="margin-bottom:20px">
            <div class="scan-meta">🕐 Scan at {scan["timestamp"]} | {len(scan["events"])} events | {len(scan["blocked_ips"])} blocked</div>
            {"".join(f'''
            <div class="event-card {event["severity"].lower()}">
                <strong>{event["severity"]}</strong> — Risk Score: {event["risk_score"]}/10
                <span class="badge {event["severity"].lower()}">{event["severity"]}</span><br>
                <span style="color:#ccc">{event["description"]}</span><br>
                <span style="color:#888;font-size:12px">MITRE: {event["mitre_technique"]} | IP: {event["ip_address"]}</span>
            </div>
            ''' for event in scan["events"])}
        </div>
        ''' for scan in scans)}
    </div>

</body>
</html>
"""

# Write the HTML report to file
with open(REPORT_FILE, "w", encoding="utf-8") as f:
    f.write(html)

print(f"✅ Report generated successfully!")
print(f"📊 Open this file in your browser: {REPORT_FILE}")
print(f"   Total scans: {total_scans}")
print(f"   Total events: {total_events}")
print(f"   Critical: {critical_count} | High: {high_count} | Medium: {medium_count} | Low: {low_count}")
print(f"   Blocked IPs: {len(unique_blocked_ips)}")