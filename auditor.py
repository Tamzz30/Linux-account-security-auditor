#!/usr/bin/env python3
"""Read-only Linux password-policy and account security auditor."""
import argparse, json, os, re, subprocess
from datetime import datetime, timezone
from pathlib import Path

PASSWD = Path("/etc/passwd")
SHADOW = Path("/etc/shadow")
LOGIN_DEFS = Path("/etc/login.defs")
PWQUALITY = [Path("/etc/security/pwquality.conf"),
             Path("/etc/security/pwquality.conf.d")]
PAM_FILES = [Path("/etc/pam.d/common-password"), Path("/etc/pam.d/system-auth"),
             Path("/etc/pam.d/password-auth")]

def read_text(path):
    try:
        return path.read_text(errors="replace")
    except (OSError, PermissionError):
        return ""

def parse_kv(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            out[parts[0]] = " ".join(parts[1:])
    return out

def finding(items, severity, code, message, recommendation):
    items.append({"severity": severity, "code": code, "message": message,
                  "recommendation": recommendation})

def run_lastlog(username, days):
    try:
        p = subprocess.run(["lastlog", "-b", str(days), "-u", username],
                           capture_output=True, text=True, timeout=5)
        lines = [x for x in p.stdout.splitlines() if x.strip()]
        # lastlog prints a header and then matching users; a matching row means old login.
        return len(lines) > 1 and username in lines[-1]
    except (OSError, subprocess.TimeoutExpired):
        return None

def audit(inactive_days):
    findings, accounts = [], []
    passwd_lines = read_text(PASSWD).splitlines()
    shadow_lines = read_text(SHADOW).splitlines()
    shadow = {}
    for line in shadow_lines:
        fields = line.split(":")
        if len(fields) >= 2:
            shadow[fields[0]] = fields

    for line in passwd_lines:
        fields = line.split(":")
        if len(fields) != 7:
            continue
        name, _, uid, gid, gecos, home, shell = fields
        try:
            uid_num = int(uid)
        except ValueError:
            continue
        sh = shadow.get(name, [])
        pw_field = sh[1] if len(sh) > 1 else None
        account = {"username": name, "uid": uid_num, "gid": gid,
                   "home": home, "shell": shell,
                   "password_state": "unknown"}
        if pw_field is None:
            account["password_state"] = "shadow_entry_unavailable"
        elif pw_field == "":
            account["password_state"] = "empty"
            finding(findings, "CRITICAL", "EMPTY_PASSWORD",
                    f"Account '{name}' has an empty password field.",
                    "Set a strong password or lock/remove the account through approved administration.")
        elif pw_field.startswith(("!", "*")):
            account["password_state"] = "locked"
        else:
            account["password_state"] = "password_hash_present"

        if uid_num == 0 and name != "root":
            finding(findings, "CRITICAL", "EXTRA_UID_ZERO",
                    f"Non-root account '{name}' has UID 0.",
                    "Verify whether this is intentional; normally only root should have UID 0.")
        if uid_num >= 1000 and shell not in ("/usr/sbin/nologin", "/sbin/nologin",
                                              "/bin/false", "/usr/bin/false"):
            account["interactive_shell"] = True
        else:
            account["interactive_shell"] = False

        # Service-like accounts are commonly low-UID accounts other than root.
        if 1 <= uid_num < 1000 and shell not in ("/usr/sbin/nologin", "/sbin/nologin",
                                                  "/bin/false", "/usr/bin/false"):
            finding(findings, "MEDIUM", "SERVICE_ACCOUNT_INTERACTIVE",
                    f"System/service account '{name}' has interactive shell '{shell}'.",
                    "If interactive login is not required, assign /usr/sbin/nologin or /sbin/nologin.")

        if len(sh) > 4:
            max_days = sh[4]
            if max_days.isdigit() and int(max_days) >= 99999:
                finding(findings, "MEDIUM", "PASSWORD_NEVER_EXPIRES",
                        f"Account '{name}' has maximum password age set to {max_days} days.",
                        "Set an appropriate maximum password age based on your organization's policy.")
        accounts.append(account)

    # Password policy values in login.defs
    login = parse_kv(read_text(LOGIN_DEFS))
    for key, code, desc, rec, bad in [
        ("PASS_MAX_DAYS", "MAX_AGE_UNSET", "Maximum password age is missing or effectively unlimited.",
         "Set PASS_MAX_DAYS to your approved policy value.", lambda v: not v.isdigit() or int(v) >= 99999),
        ("PASS_MIN_DAYS", "MIN_AGE_ZERO", "Minimum password age is zero or unset.",
         "Consider setting PASS_MIN_DAYS to prevent rapid password changes.", lambda v: not v.isdigit() or int(v) == 0),
        ("PASS_WARN_AGE", "WARN_AGE_UNSET", "Password expiry warning period is missing or zero.",
         "Set PASS_WARN_AGE to provide users advance notice.", lambda v: not v.isdigit() or int(v) == 0),
    ]:
        value = login.get(key, "")
        if bad(value):
            finding(findings, "MEDIUM", code, desc + f" Current value: {value or 'not configured'}.", rec)

    # pwquality: check common settings without assuming distro-specific defaults.
    pwq_text = ""
    for p in PWQUALITY:
        if p.is_file():
            pwq_text += "\n" + read_text(p)
        elif p.is_dir():
            for child in p.glob("*.conf"):
                pwq_text += "\n" + read_text(child)
    pwq = parse_kv(pwq_text)
    if not pwq:
        finding(findings, "HIGH", "PWQUALITY_NOT_CONFIGURED",
                "No settings were found in the common pwquality configuration locations.",
                "Install/configure libpam-pwquality (package name varies by distribution) and review minlen and credit settings.")
    else:
        minlen = pwq.get("minlen", "")
        if not minlen.isdigit() or int(minlen) < 12:
            finding(findings, "MEDIUM", "PASSWORD_MIN_LENGTH_WEAK",
                    f"pwquality minlen is missing or below 12 (current: {minlen or 'unset'}).",
                    "Consider a minimum length of at least 12, aligned with your policy.")
        if pwq.get("retry", "").isdigit() and int(pwq["retry"]) > 5:
            finding(findings, "LOW", "PWQUALITY_RETRY_HIGH",
                    f"pwquality retry is {pwq['retry']}.",
                    "Review retry limits to reduce repeated weak-password attempts.")

    pam_text = "\n".join(read_text(p) for p in PAM_FILES if p.exists())
    if "pam_pwquality.so" not in pam_text:
        finding(findings, "HIGH", "PAM_PWQUALITY_NOT_ENABLED",
                "pam_pwquality.so was not found in the common PAM password configuration files checked.",
                "Check your distribution's PAM stack and enable the password-quality module if appropriate.")
    if not re.search(r"pam_pwhistory\.so|remember\s*=", pam_text):
        finding(findings, "MEDIUM", "PASSWORD_HISTORY_NOT_FOUND",
                "No PAM password-history configuration was detected in the common files checked.",
                "Configure an approved password-history control (for example pam_pwhistory) if required.")

    if not os.access(SHADOW, os.R_OK):
        finding(findings, "HIGH", "SHADOW_NOT_READABLE",
                "/etc/shadow could not be read; password-state checks are incomplete.",
                "Run the auditor with appropriate administrative privileges. The report never prints password hashes.")

    # Optional dormant login check. Only checks accounts with interactive shells.
    if inactive_days > 0:
        for account in accounts:
            if account["interactive_shell"]:
                result = run_lastlog(account["username"], inactive_days)
                if result is True:
                    finding(findings, "MEDIUM", "DORMANT_ACCOUNT",
                            f"Interactive account '{account['username']}' has a last login older than {inactive_days} days.",
                            "Confirm ownership and business need; disable or remove unused accounts through approved procedures.")
                elif result is None:
                    finding(findings, "LOW", "LASTLOG_UNAVAILABLE",
                            "Could not run lastlog; dormant-account checks may be incomplete.",
                            "Install/use lastlog where supported, or document an alternative login-audit source.")
                    break

    counts = {s: sum(1 for x in findings if x["severity"] == s)
              for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    return {"tool": "Linux Account Security Auditor", "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "host": os.uname().nodename, "accounts_scanned": len(accounts),
            "findings_summary": counts, "findings": findings,
            "scope_note": "Read-only audit. Password hashes and shadow contents are never included."}

def main():
    parser = argparse.ArgumentParser(description="Read-only Linux password policy and account auditor")
    parser.add_argument("--inactive-days", type=int, default=90,
                        help="Flag interactive accounts whose last login is older than this many days (default: 90; use 0 to skip)")
    parser.add_argument("--output-dir", default="reports", help="Directory for timestamped reports")
    args = parser.parse_args()
    if args.inactive_days < 0:
        parser.error("--inactive-days must be 0 or greater")
    report = audit(args.inactive_days)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path, txt_path = out / f"audit_{stamp}.json", out / f"audit_{stamp}.txt"
    json_path.write_text(json.dumps(report, indent=2))
    lines = [report["tool"], "=" * 32, f"Generated: {report['generated_at']}",
             f"Host: {report['host']}", f"Accounts scanned: {report['accounts_scanned']}",
             "", "SUMMARY"]
    lines += [f"{k}: {v}" for k, v in report["findings_summary"].items()]
    lines += ["", "FINDINGS"]
    if not report["findings"]:
        lines.append("No findings detected by the checks performed.")
    for i, f in enumerate(report["findings"], 1):
        lines += [f"{i}. [{f['severity']}] {f['code']}",
                  f"   {f['message']}", f"   Recommendation: {f['recommendation']}"]
    lines += ["", report["scope_note"]]
    txt_path.write_text("\n".join(lines) + "\n")
    print("\n".join(lines[:12]))
    print(f"\nReports saved: {json_path} and {txt_path}")
    print("Note: review findings manually; PAM paths and account UID conventions vary by distribution.")

if __name__ == "__main__":
    main()
