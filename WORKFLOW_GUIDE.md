# Security Report Generator - Workflow Guide

## How It Works

The security report generator uses a **two-step process** to compare vulnerabilities over time:

### Step 1: Capture Baseline (Beginning of Month)
Run with `--snapshot` flag to save a baseline of current vulnerabilities.

```bash
python3 security_report.py --snapshot
```

**What happens:**
- Queries Wazuh for current vulnerability counts
- Saves snapshot to `reports/{client}/snapshots/snapshot_YYYY-MM-DD.json`
- **No report is generated**, only the baseline is saved
- Takes ~5 seconds per client

**When to run:**
- **1st of the month** (recommended)
- Or anytime you want to establish a new baseline

### Step 2: Generate Report (End of Month or Anytime After)
Run without flags to generate full report with comparison.

```bash
python3 security_report.py
```

**What happens:**
- Loads the baseline snapshot from the 1st
- Queries Wazuh for current vulnerability counts
- **Compares baseline vs current** to show changes
- Fetches security alerts (Level 12+)
- Generates Excel report with 5 sheets
- Emails report to configured recipients

**When to run:**
- **End of month** (last day or 30th/31st)
- Or anytime during the month to see progress

---

## Typical Monthly Workflow

```
Day 1 (Nov 1):
$ python3 security_report.py --snapshot
→ Baseline saved: 620 vulnerabilities

Day 15 (Mid-month check):
$ python3 security_report.py
→ Report generated: 625 vulnerabilities (+5 increase)

Day 30 (End of month):
$ python3 security_report.py
→ Report generated: 633 vulnerabilities (+13 increase)
→ Email sent with full monthly report
```

---

## Command Options

### Capture Baseline Only
```bash
# All enabled clients
python3 security_report.py --snapshot

# Specific client only
python3 security_report.py --snapshot --client homelab
```

### Generate Full Report
```bash
# All enabled clients
python3 security_report.py

# Specific client only
python3 security_report.py --client homelab
```

### Help
```bash
python3 security_report.py --help
```

---

## What If I Forget the Baseline?

**No problem!** The report will automatically:
1. Detect that no baseline exists for the 1st
2. Fetch current data and save it as the baseline
3. Generate the report using today's data as both baseline and current

**Output:**
```
⚠️  No baseline snapshot found for 2025-11-01
   Run 'python3 security_report.py --snapshot' on the 1st to capture baseline
   Using current data as baseline for this report...
```

---

## Automation with Cron

### Recommended Setup

```bash
# Edit crontab
crontab -e
```

Add these entries:

```cron
# Capture baseline on 1st of each month at 12:01 AM
1 0 1 * * cd /home/ai/security_report && python3 security_report.py --snapshot >> /var/log/security_report.log 2>&1

# Generate report on last day of month at 11:00 PM
0 23 28-31 * * [ "$(date +\%d -d tomorrow)" = "01" ] && cd /home/ai/security_report && python3 security_report.py >> /var/log/security_report.log 2>&1
```

Or simpler (generate on 1st using previous month's data):

```cron
# Capture baseline on 1st at 12:01 AM
1 0 1 * * cd /home/ai/security_report && python3 security_report.py --snapshot >> /var/log/security_report.log 2>&1

# Generate report on 2nd at 9:00 AM (compares yesterday's baseline to today)
0 9 2 * * cd /home/ai/security_report && python3 security_report.py >> /var/log/security_report.log 2>&1
```

---

## File Structure

```
/home/ai/security_report/
└── reports/
    └── homelab/
        ├── snapshots/
        │   ├── snapshot_2025-11-01.json    # Baseline (620 vulns)
        │   ├── snapshot_2025-11-15.json    # Mid-month (if captured)
        │   └── snapshot_2025-11-17.json    # Current (633 vulns)
        │
        └── security_report_homelab_November 2025_20251117_234721.xlsx
```

---

## Snapshot File Format

Each snapshot is a JSON file containing:

```json
{
  "date": "2025-11-01",
  "total": 620,
  "by_severity": {
    "Critical": 3,
    "High": 150,
    "Medium": 294,
    "Low": 173
  },
  "by_agent": {
    "AD": {
      "Critical": 2,
      "High": 55,
      "Medium": 29,
      "Low": 4,
      "total": 93
    },
    "Testing": {
      "Critical": 0,
      "High": 50,
      "Medium": 144,
      "Low": 22,
      "total": 216
    }
  },
  "vulnerabilities": [...]
}
```

---

## Excel Report Contents

When you run the full report, you get 5 sheets:

### 1. Summary
Shows the comparison:
```
VULNERABILITY TRACKING
                        Month Start | Current | Change
Total Vulnerabilities:      620    |   633   |  +13
  Critical:                   3    |     3   |    0
  High:                     150    |   159   |   +9
  Medium:                   294    |   298   |   +4
  Low:                      173    |   173   |    0
```

### 2. Alerts by Level
Security incident distribution (Level 12+ alerts)

### 3. Top Rules
Top 10 most triggered security rules

### 4. Vulnerability Comparison
Agent-by-agent breakdown:
```
Agent      | Month Start | Current | Change | Status
AD         |     93      |   98    |   +5   | ⬆ Increased (Red)
Testing    |    216      |  221    |   +5   | ⬆ Increased (Red)
Pi-Hole    |    143      |  143    |    0   | → No Change (Gray)
```

### 5. Vulnerability Details
Complete list of current vulnerabilities with CVE, title, package info

---

## Troubleshooting

### "No baseline snapshot found"
**Solution:** Run `python3 security_report.py --snapshot` to create one

### "No data found for {client}"
**Cause:** No vulnerabilities or alerts found
**Solution:** Check client name matches Wazuh indices

### Email not sending
**Cause:** SMTP server not configured
**Solution:** Update `.env` with valid SMTP settings

### Want to reset and start over?
```bash
# Delete all snapshots for a client
rm -rf reports/homelab/snapshots/

# Run snapshot again to start fresh
python3 security_report.py --snapshot --client homelab
```

---

## Best Practices

1. **Always capture baseline on the 1st** - Most accurate month-to-month comparison
2. **Keep snapshots** - They're only ~100KB each, useful for historical trending
3. **Generate reports at end of month** - Shows complete monthly picture
4. **Review mid-month** - Run anytime to check progress without waiting
5. **Automate it** - Use cron to ensure it runs every month automatically

---

## Summary

✅ **Two-step workflow**: Snapshot first, report later  
✅ **Flexible timing**: Run anytime, not just on specific days  
✅ **Automatic fallback**: Creates baseline if missing  
✅ **Historical tracking**: Keeps all snapshots for trending  
✅ **Per-client isolation**: Each client has own snapshots and reports  

**Quick Reference:**
```bash
# Month start: Save baseline
python3 security_report.py --snapshot

# Month end: Generate report
python3 security_report.py
```

That's it! 🎉
