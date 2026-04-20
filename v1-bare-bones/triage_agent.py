# Import the OpenAI library we installed earlier
from openai import OpenAI

# Import os to access environment variables
import os

# Import load_dotenv to read our .env file
from dotenv import load_dotenv

# Load the .env file so Python can read it
load_dotenv()

# Connect to OpenAI using the key from .env file
client = OpenAI(api_key=os.getenv("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"))

# Open and read the log file we created
with open("v1-bare-bones/sample_logs.txt", "r") as file:
    logs = file.read()

# Send the logs to the AI with a security analyst instruction
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {
            "role": "system",
            "content": "You are an expert SOC analyst and SRE. Your task is to analyze logs and: Detect anomalies and suspicious activity. Identify errors and warnings. Classify severity (Critical, High, Medium, Low). Correlate related events. Suggest possible causes and fixes."
        },
        {
            "role": "user",
            "content": logs
        }
    ]
)

# Print the AI's response to the terminal
print(response.choices[0].message.content)