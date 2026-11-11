# Automated Password Policy Auditing and User Account Security Checker

A read-only Python 3 project for Linux. It audits common password-policy settings and local account metadata, then writes timestamped TXT and JSON reports.

## Features
- Checks `/etc/login.defs` for maximum/minimum password age and warning period.
- Checks common `pwquality` configuration locations and PAM integration.
- Checks local accounts for UID 0 duplicates, empty/locked password states, long/unlimited maximum password age, interactive service accounts, and optionally dormant interactive accounts using `lastlog`.
- Produces timestamped text and JSON reports.
- Does not change accounts, passwords, PAM files, or system settings. It never prints or stores password hashes.

## Requirements
- Linux, Python 3.8+
- Optional `lastlog` utility for dormant-account checks
- Run with `sudo` for complete `/etc/shadow` checks. Without it, the report will explicitly say checks are incomplete.

## Run
```bash
chmod +x auditor.py
sudo ./auditor.py
```
Reports are saved in `reports/`. To skip dormant checks:
```bash
sudo ./auditor.py --inactive-days 0
```
To use a different inactivity threshold:
```bash
sudo ./auditor.py --inactive-days 60 --output-dir my_reports
```

## Project structure
```text
linux_account_security_auditor/
├── auditor.py
├── README.md
├── requirements.txt
└── sample_report.txt
```

## Important limitations
- PAM configuration differs across Debian/Ubuntu, RHEL/Fedora, SUSE, and other distributions. The script checks common files only; manually review your distro's active PAM stack.
- `login.defs` values may not control every account-management tool.
- `lastlog` availability and output vary. Treat dormant-account results as leads for manual review, not automatic proof.
- A locked password does not necessarily mean an account cannot authenticate through SSH keys or another mechanism.
- The tool reports findings only. Apply remediation separately with administrator approval.

## Demonstration checklist
1. Run the tool and show the generated TXT report.
2. Open the JSON report to demonstrate machine-readable output.
3. Explain a CRITICAL finding (UID 0 duplicate or empty password field).
4. Explain why locked accounts are not automatically called vulnerable.
5. Explain limitations of PAM paths and lastlog.

## Viva summary
**Aim:** To automate a read-only security audit of Linux password policies and user accounts.

**Method:** Read configuration files and account metadata, compare values with basic security expectations, classify findings by severity, and export timestamped reports.

**Outcome:** Administrators get a quick inventory of possible weak settings and accounts needing review.

**Future enhancement:** Add distro-specific PAM parsing, HTML dashboards, email notifications, and scheduled execution after testing and approval.
