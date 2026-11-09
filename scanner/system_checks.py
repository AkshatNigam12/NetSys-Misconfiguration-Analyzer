"""
System configuration checks for Analyzer2.
Each function returns a dict with the issue details if a problem is found, or None if OK.
"""

import os

from scanner.config import run_command, is_windows, is_macos, ScannerConfig


def check_ssh_config():
    """Check SSH configuration for common security issues."""
    if is_windows():
        try:
            ssh_status = run_command(
                "powershell.exe Get-Service ssh-agent -ErrorAction SilentlyContinue"
            )
            if ssh_status:
                return {"ssh_config": f"SSH service status: {ssh_status}"}
            return None
        except Exception as e:
            return {"ssh_config": f"Error checking SSH: {e}"}
    else:
        try:
            ssh_config = run_command("cat /etc/ssh/sshd_config 2>/dev/null")
            if not ssh_config:
                return None  # SSH server not installed — not an issue

            issues = []
            if "Port 22" in ssh_config:
                issues.append("Default SSH port (22) in use")
            if "PasswordAuthentication yes" in ssh_config:
                issues.append("Password authentication enabled")
            if "PermitRootLogin yes" in ssh_config:
                issues.append("Root login permitted")

            return {"ssh_config": ", ".join(issues)} if issues else None
        except Exception as e:
            return {"ssh_config": f"Error checking SSH: {e}"}


def check_firewall_status():
    """Check firewall status."""
    if is_windows():
        try:
            status = run_command(
                "powershell.exe Get-NetFirewallProfile | Select-Object Name,Enabled"
            )
            if "False" in status:
                return {"firewall": f"Windows Firewall partially disabled: {status}"}
            return None
        except Exception as e:
            return {"firewall": f"Error checking firewall: {e}"}
    elif is_macos():
        try:
            status = run_command(
                "defaults read /Library/Preferences/com.apple.alf globalstate"
            )
            if status.strip() == "0":
                return {"firewall": "macOS Firewall is disabled"}
            return None
        except Exception as e:
            return {"firewall": f"Error checking firewall: {e}"}
    else:
        try:
            status = run_command("ufw status 2>/dev/null")
            if not status or "inactive" in status.lower():
                return {"firewall": "UFW firewall is not active"}
            return None
        except Exception as e:
            return {"firewall": f"Error checking firewall: {e}"}


def check_file_permissions():
    """Check permissions on critical system files."""
    if is_windows():
        try:
            perms = run_command(
                "powershell.exe Get-Acl C:\\Windows\\System32 | Format-List"
            )
            return {"file_permissions": f"System32 permissions: {perms}"} if perms else None
        except Exception as e:
            return {"file_permissions": f"Error checking permissions: {e}"}
    else:
        paths = ScannerConfig.get_system_paths()
        issues = []
        for path in paths:
            try:
                if os.path.exists(path):
                    perms = oct(os.stat(path).st_mode & 0o777)
                    if int(perms, 8) > 0o644:
                        issues.append(f"{path}: {perms}")
            except Exception as e:
                issues.append(f"Error checking {path}: {e}")
        return {"file_permissions": ", ".join(issues)} if issues else None


def check_antivirus():
    """Check antivirus / endpoint protection status."""
    if is_windows():
        try:
            av_status = run_command(
                "powershell.exe Get-MpComputerStatus | "
                "Select-Object AntivirusEnabled,RealTimeProtectionEnabled"
            )
            if "False" in av_status:
                return {"antivirus": "Windows Defender not properly configured"}
            return None
        except Exception as e:
            return {"antivirus": f"Error checking antivirus: {e}"}
    elif is_macos():
        try:
            xprotect_path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle"
            if os.path.exists(xprotect_path):
                return None  # XProtect is present

            applications = run_command("ls /Applications/").split("\n")
            av_names = ["ClamAV", "Sophos", "McAfee", "Symantec", "Norton", "Avast"]
            for av in av_names:
                if any(av.lower() in app.lower() for app in applications):
                    return None
            return {"antivirus": "No recognized antivirus software detected"}
        except Exception as e:
            return {"antivirus": f"Error checking antivirus: {e}"}
    else:
        for av in ["clamav", "clamdscan", "sophos-av", "avast"]:
            try:
                if run_command(f"which {av}"):
                    return None
            except Exception:
                continue
        return {"antivirus": "No antivirus software detected"}


def check_user_accounts():
    """Check user account settings for potential issues."""
    if is_windows():
        try:
            accounts = run_command(
                "powershell.exe Get-LocalUser | Select-Object Name,Enabled,PasswordRequired"
            )
            return {"user_accounts": accounts} if accounts else None
        except Exception as e:
            return {"user_accounts": f"Error checking user accounts: {e}"}
    else:
        try:
            with open("/etc/passwd", "r") as f:
                users = [
                    line.split(":")[0]
                    for line in f
                    if "/home/" in line or "/Users/" in line
                ]
            if users:
                return {"user_accounts": f"User accounts: {', '.join(users)}"}
            return None
        except Exception as e:
            return {"user_accounts": f"Error checking user accounts: {e}"}


def check_system_logs():
    """Check recent system/auth logs for potential issues."""
    if is_windows():
        try:
            logs = run_command(
                "powershell.exe Get-EventLog -LogName Security -Newest 5 2>$null"
            )
            return {"system_logs": f"Recent security events: {logs}"} if logs else None
        except Exception as e:
            return {"system_logs": f"Error checking system logs: {e}"}
    else:
        try:
            # Try auth.log first (Debian/Ubuntu), then secure (RHEL/CentOS)
            logs = run_command("tail -n 5 /var/log/auth.log 2>/dev/null")
            if not logs:
                logs = run_command("tail -n 5 /var/log/secure 2>/dev/null")
            if logs:
                return {"system_logs": f"Recent auth logs: {logs}"}
            return None
        except Exception as e:
            return {"system_logs": f"Error checking system logs: {e}"}
