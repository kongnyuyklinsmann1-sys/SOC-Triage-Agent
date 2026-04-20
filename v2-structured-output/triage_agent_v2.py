# Import the OpenAI library
from openai import OpenAI

# Import json library to handle JSON data
import json

# Import os to access environment variables
import os

# Import load_dotenv to read our .env file
from dotenv import load_dotenv

# Load the .env file so Python can read it
load_dotenv()

# Connect to OpenAI using the key from .env file
client = OpenAI(api_key=os.getenv("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"))

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
                        "recommendation": "what to do"
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

# Print each event cleanly
for event in parsed["events"]:
    print("=" * 50)
    print(f"Description : {event['description']}")
    print(f"Severity    : {event['severity']}")
    print(f"Risk Score  : {event['risk_score']}/10")
    print(f"MITRE       : {event['mitre_technique']}")
    print(f"Action      : {event['recommendation']}")

print("=" * 50)
print("Analysis complete.")