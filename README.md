# ThreatLens - Phishing Email Analyser

A Python-based phishing email analysis tool built for Blue Team / SOC Tier-1 workflows.

## What it does
- Extracts email headers, sender info, and metadata
- Detects sender/Reply-To domain mismatches
- Scans subject line for suspicious keywords
- Detects dangerous attachments
- Extracts all URLs from email body
- Checks URLs against VirusTotal (70+ security engines)
- Detects URL shorteners, HTTP links, and suspicious TLDs
- Analyses Received headers to trace email origin
- Generates a Phishing Confidence Score (0-100)

## Usage
```bash
python3 analyser.py samples/email.eml
```

## Scoring System
| Score | Verdict |
|-------|---------|
| 0-20  | Legitimate |
| 21-40 | Suspicious |
| 41-70 | Likely Phishing |
| 71-100 | High Confidence Phishing |

## Tools & APIs Used
- Python 3
- VirusTotal API
- python-dotenv

## Setup
1. Clone the repo
2. Install dependencies: `pip3 install requests python-dotenv`
3. Create a `.env` file with your VirusTotal API key: `VT_API_KEY=yourkey`
4. Run against any `.eml` file
