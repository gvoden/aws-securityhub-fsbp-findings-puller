# AWS Security Hub — FSBP Findings Puller

```
╔══════════════════════════════════════════════════════════════╗
║         AWS Security Hub — FSBP Findings Puller              ║
║         AWS Foundational Security Best Practices v1.0.0      ║
╚══════════════════════════════════════════════════════════════╝
```

Automatically pulls AWS Foundational Security Best Practices (FSBP) v1.0.0
findings across all member accounts in your AWS Organization and generates a
populated Excel remediation tracker and live HTML dashboard — from a single
command.

Built for cloud security engineers managing multi-account AWS environments.
No third-party tools. No dashboards to pay for. Just `boto3` and `openpyxl`.

---

## Features

- **Multi-account support** — pulls findings across all AWS Organizations member accounts via the Security Hub delegated admin account
- **Consolidated controls mode** — compatible with the newer AWS Security Hub consolidated controls format
- **Excel tracker** — 5-sheet workbook with weekly status report, full findings log, by-severity, by-account, and top failing controls
- **HTML dashboard** — KPI cards, progress bars, per-account breakdown, critical/high findings table — open in any browser
- **Auto-populated narrative** — weekly status report pre-filled with real finding counts, outstanding criticals, and go-live risk flags
- **Audit trail** — timestamped outputs build a weekly paper trail automatically
- **Cross-platform** — Mac, Linux, and Windows

---

## Requirements

```bash
pip install boto3 openpyxl
```

Python 3.8+

---

## Usage

```bash
# Default credentials / environment variables
python securityhub_pull.py --region us-east-1

# Named AWS profile
python securityhub_pull.py --region us-east-1 --profile prod-security

# Filter to specific accounts
python securityhub_pull.py --region us-east-1 --accounts 111111111111 222222222222

# Custom output directory
python securityhub_pull.py --region us-east-1 --output-dir /path/to/reports
```

---

## Output

Each run generates two timestamped files:

| File | Description |
|------|-------------|
| `SecurityHub_FSBP_YYYYMMDD_HHMM.xlsx` | Excel workbook — 5 sheets |
| `SecurityHub_Dashboard_YYYYMMDD_HHMM.html` | Visual dashboard — open in browser |

### Excel Sheets

| Sheet | Contents |
|-------|----------|
| Weekly Status Report | KPI summary + narrative fields for reporting |
| Findings | Full findings log with severity, status, resource, remediation |
| By Severity | Critical / High / Medium / Low breakdown with % complete |
| By Account | Per AWS account posture summary |
| By Control | Top failing controls ranked by severity and affected resources |

---

## AWS Setup

Must be run with credentials for the **Security Hub delegated administrator account** to pull findings across all member accounts.

### Verify your admin account

```bash
aws securityhub get-administrator-account --region us-east-1
```

If this returns empty, you are already in the admin account. If it returns an account ID, assume a role into that account first.

### Verify member accounts are enrolled

```bash
aws securityhub list-members --only-associated --region us-east-1
```

### Required IAM permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "securityhub:GetFindings",
        "securityhub:ListMembers",
        "securityhub:GetEnabledStandards",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Automation

### Cron (Mac / Linux) — every Monday at 8am

```bash
crontab -e
```

```
0 8 * * 1 cd /path/to/project && python securityhub_pull.py --region us-east-1 >> securityhub_pull.log 2>&1
```

### Windows Task Scheduler

```
Program: C:\path\to\python.exe
Arguments: C:\path\to\securityhub_pull.py --region us-east-1
```

---

## Tested Against

- AWS Security Hub consolidated controls mode
- AWS Organizations with 45+ member accounts
- Regions: `us-east-1`, `ca-central-1`
- Python 3.8 — 3.14
- Mac, Windows 11, Linux

---

## Contributing

PRs welcome. If you hit API quirks in your environment, open an issue with the
error and the output of:

```bash
aws securityhub get-findings \
  --region YOUR_REGION \
  --filters '{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  --max-results 1 \
  --query 'Findings[0].{GeneratorId:GeneratorId,Types:Types}' \
  --output json
```

---

## License

MIT

---

*Built by a cloud security engineer who needed a weekly paper trail and didn't want to pay for another dashboard.*
