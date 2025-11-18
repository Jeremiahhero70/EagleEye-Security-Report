# Security Report Generator

Simple monthly security report generator for Wazuh multi-tenant environments.

## Features

1. **Vulnerability Tracking** - Monthly comparison (1st vs 30th)
2. **Security Incident Reporting** - Level 12+ alerts, volume, severity breakdown
3. **Access Auditing** - Login monitoring (USA vs International), VPN access

## Setup

1. Copy `.env.example` to `.env` and configure:
```bash
cp .env .env.example  # Edit with your settings
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run monthly security report:
```bash
python3 security_report.py
```

## Configuration

Edit `.env` file:
- Wazuh dashboard credentials
- Email server settings
- Client configurations (YAML format)

## Output

- Excel reports with multiple sheets (Summary, Alerts by Level, Top Rules)
- Automatic email delivery to configured recipients
- Files saved as: `security_report_{client}_{month}_{timestamp}.xlsx`

## Alert Exclusions

Automatically excludes noise:
- Office 365 phishing/malware events
- Agent queue flooded events  
- CVSS vulnerability classifications
