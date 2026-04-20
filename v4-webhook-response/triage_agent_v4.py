# Import the OpenAI library
from openai import OpenAI

# Import json library to handle JSON data
import json

# Import os to access environment variables
import os

# Import requests library to send webhook to mock firewall
import requests

# Import load_dotenv to read our .env file
from dotenv import load_dotenv

# Load the .env file so Python can read it
load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.env'))

# Connect to OpenAI using the key from .env file
client = OpenAI(api_key=os.getenv("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"))

# Your mock firewall webhook URL from webhook.site
WEBHOOK_URL = "https://webhook.site/03320216-976b-4cc1-abac-b692b77daec5"
# Open and read the log file we created in v1
with open("v1-bare-bones/sample_logs.txt", "r") as file:
    logs = file.read()

# Send the logs to the AI and ask for JSON output
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {
            "role": "system",
            "content": """You are an expert SOC analyst and SRE.
            Your task is to analyze logs and:
            - Detect anomalies and suspicious activity
            - Identify errors and warnings
            - Classify severity (Critical, High, Medium, Low)
            - Correlate related events
            - Suggest possible causes and fixes

            Respond ONLY in this exact JSON format, nothing else:
            {
                "events": [
                    {
                        "description": "what happened",
                        "severity": "Critical/High/Medium/Low",
                        "risk_score": 1-10,
                        "mitre_technique": "technique name and ID",
                        "recommendation": "what to do",
                        "ip_address": "extract IP from log or null"
                    }
                ]
            }"""
        },
        {
            "role": "user",
            "content": logs
        }
    ]
)

# Get the response text
raw_response = response.choices[0].message.content

# Parse the JSON response so Python can work with it
parsed = json.loads(raw_response)

# Print each event and trigger webhook for high risk ones
for event in parsed["events"]:

    # Check if the risk score is higher than 8
    if event["risk_score"] > 8:
        print("🚨" * 10)
        print("HIGH RISK ALERT - IMMEDIATE ACTION REQUIRED")
        print("🚨" * 10)
        print(f"Description : {event['description']}")
        print(f"Severity    : {event['severity']}")
        print(f"Risk Score  : {event['risk_score']}/10")
        print(f"MITRE       : {event['mitre_technique']}")
        print(f"Action      : {event['recommendation']}")
        print(f"IP Address  : {event['ip_address']}")
        print("🚨" * 10)

        # Send webhook to mock firewall to block the IP
        payload = {
            "action": "BLOCK_IP",
            "ip_address": event["ip_address"],
            "reason": event["description"],
            "risk_score": event["risk_score"],
            "mitre_technique": event["mitre_technique"]
        }

        # Send the payload to the mock firewall
        firewall_response = requests.post(WEBHOOK_URL, json=payload)

        # Confirm the block was sent
        print(f"🔥 Firewall block command sent for IP: {event['ip_address']}")
        print(f"🔥 Firewall response status: {firewall_response.status_code}")

    # If risk score is 8 or below print normally
    else:
        print("=" * 50)
        print(f"Description : {event['description']}")
        print(f"Severity    : {event['severity']}")
        print(f"Risk Score  : {event['risk_score']}/10")
        print(f"MITRE       : {event['mitre_technique']}")
        print(f"Action      : {event['recommendation']}")

print("=" * 50)
print("Analysis complete.")