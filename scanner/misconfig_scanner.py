"""
Network Misconfiguration Scanner for Analyzer2.
Compares system configuration against CIS Benchmarks and NIST Guidelines.
"""

import platform
import socket
import subprocess
import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

# --- Best Practices Database (CIS Benchmarks / NIST Guidelines) ---

BEST_PRACTICES = {
    "Public": [
        {"misconfiguration": "Unsecured Open Ports", "recommended_value": "Minimal required ports open", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "Weak DNS Configuration", "recommended_value": "Use secure DNS servers (e.g., 8.8.8.8, 1.1.1.1)", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "Unrestricted Network Access", "recommended_value": "Restricted access to public networks", "source": "CIS Benchmarks", "risk_level": "Medium"},
        {"misconfiguration": "Weak DHCP Lease Time", "recommended_value": "Lease time should be at least 7200 seconds", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "Weak Default Route Configuration", "recommended_value": "Ensure default route aligns with expected gateway", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "No NTP Configuration", "recommended_value": "Use a secure NTP server", "source": "CIS Benchmarks", "risk_level": "Medium"},
        {"misconfiguration": "Default Credentials on Network Devices", "recommended_value": "Change default admin credentials", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "Exposed SMB Shares", "recommended_value": "Disable unnecessary network shares", "source": "CIS Benchmarks", "risk_level": "Medium"},
        {"misconfiguration": "Disabled Firewall", "recommended_value": "Enable firewall", "source": "NIST Guidelines", "risk_level": "High"},
        {"misconfiguration": "Insecure IPv6 Configuration", "recommended_value": "Ensure IPv6 is secured (e.g., RA Guard)", "source": "NIST Guidelines", "risk_level": "High"},
    ],
    "Private": [
        {"misconfiguration": "Unsecured Open Ports", "recommended_value": "Minimal required ports open", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "Weak DNS Configuration", "recommended_value": "Use secure DNS servers (e.g., 8.8.8.8, 1.1.1.1)", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "Unrestricted Network Access", "recommended_value": "Restricted private network", "source": "CIS Benchmarks", "risk_level": "Medium"},
        {"misconfiguration": "Weak DHCP Lease Time", "recommended_value": "Lease time should be at least 7200 seconds", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "Weak Default Route Configuration", "recommended_value": "Ensure default route aligns with expected gateway", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "No NTP Configuration", "recommended_value": "Use a secure NTP server", "source": "CIS Benchmarks", "risk_level": "Medium"},
        {"misconfiguration": "Default Credentials on Network Devices", "recommended_value": "Change default admin credentials", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "Exposed SMB Shares", "recommended_value": "Disable unnecessary network shares", "source": "CIS Benchmarks", "risk_level": "Medium"},
        {"misconfiguration": "Disabled Firewall", "recommended_value": "Enable firewall", "source": "NIST Guidelines", "risk_level": "High"},
        {"misconfiguration": "Insecure IPv6 Configuration", "recommended_value": "Ensure IPv6 is secured (e.g., RA Guard)", "source": "NIST Guidelines", "risk_level": "High"},
    ],
    "Enterprise": [
        {"misconfiguration": "Unsecured Open Ports", "recommended_value": "Minimal required ports open", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "Weak DNS Configuration", "recommended_value": "Use secure DNS servers (e.g., 8.8.8.8, 1.1.1.1)", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "Unrestricted Network Access", "recommended_value": "Restricted access to internal networks", "source": "CIS Benchmarks", "risk_level": "Medium"},
        {"misconfiguration": "Weak DHCP Lease Time", "recommended_value": "Lease time should be at least 7200 seconds", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "Weak Default Route Configuration", "recommended_value": "Ensure default route aligns with expected gateway", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "No NTP Configuration", "recommended_value": "Use a secure NTP server", "source": "CIS Benchmarks", "risk_level": "Medium"},
        {"misconfiguration": "Default Credentials on Network Devices", "recommended_value": "Change default admin credentials", "source": "CIS Benchmarks", "risk_level": "High"},
        {"misconfiguration": "Exposed SMB Shares", "recommended_value": "Disable unnecessary network shares", "source": "CIS Benchmarks", "risk_level": "Medium"},
        {"misconfiguration": "Disabled Firewall", "recommended_value": "Enable firewall", "source": "NIST Guidelines", "risk_level": "High"},
        {"misconfiguration": "Insecure IPv6 Configuration", "recommended_value": "Ensure IPv6 is secured (e.g., RA Guard)", "source": "NIST Guidelines", "risk_level": "High"},
    ],
}


# --- Detection Helpers ---

def detect_os():
    """Detect the current operating system."""
    return platform.system()


def detect_network_type(ip_address):
    """Determine whether the IP address is on a public or private network."""
    if not ip_address or ip_address == "Unknown":
        return "Unknown"
    try:
        ip = ipaddress.ip_address(ip_address)
        return "Private" if ip.is_private else "Public"
    except ValueError:
        return "Unknown"


# --- System Config Fetchers ---

def fetch_ip_address():
    """Fetch the machine's primary IP address."""
    os_name = platform.system()
    try:
        if os_name == "Windows":
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetIPAddress -AddressFamily IPv4 | Select -ExpandProperty IPAddress"],
                capture_output=True, text=True, timeout=10,
            )
            lines = result.stdout.strip().splitlines()
            if lines:
                return lines[0].strip()
        elif os_name == "Linux":
            result = subprocess.run(
                "hostname -I | awk '{print $1}'",
                shell=True, capture_output=True, text=True, timeout=10,
            )
            return result.stdout.strip()
        elif os_name == "Darwin":
            result = subprocess.run(
                ["ipconfig", "getifaddr", "en0"],
                capture_output=True, text=True, timeout=10,
            )
            return result.stdout.strip()
    except Exception as e:
        logger.error(f"Error retrieving IP address: {e}")
    return "Unknown"


def _run_ps(cmd):
    """Run a PowerShell command and return its output."""
    try:
        result = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout.strip()
    except Exception as e:
        logger.error(f"Error executing PowerShell command: {e}")
        return "Error"


def fetch_linux_config():
    """Fetch current network configuration on Linux."""
    try:
        config = {
            "Unsecured Open Ports": subprocess.getoutput("netstat -tunlp 2>/dev/null | grep -c LISTEN || ss -tunlp | grep -c LISTEN"),
            "Weak DNS Configuration": subprocess.getoutput("grep 'nameserver' /etc/resolv.conf | awk '{print $2}' | head -n 1"),
            "Unrestricted Network Access": subprocess.getoutput("nmcli connection show --active 2>/dev/null | grep -E 'ethernet|wifi' | awk '{print $1}'"),
            "Weak DHCP Lease Time": subprocess.getoutput("cat /var/lib/dhcp/dhclient.leases 2>/dev/null | grep 'lease' | awk '{print $2}'") or "0",
            "Weak Default Route Configuration": subprocess.getoutput("ip route | grep default") or "No default route found",
            "No NTP Configuration": subprocess.getoutput("systemctl is-active ntp 2>/dev/null || systemctl is-active chronyd 2>/dev/null || echo 'NTP service not found'"),
            "Default Credentials on Network Devices": subprocess.getoutput("grep -E 'admin|root' /etc/passwd 2>/dev/null | tr '\\n' '\n'"),
            "Exposed SMB Shares": subprocess.getoutput("smbclient -L localhost -N 2>/dev/null | grep -i 'Disk'") or "No shares found",
            "Disabled Firewall": subprocess.getoutput("ufw status 2>/dev/null | grep -i active") or "Firewall Disabled",
            "Insecure IPv6 Configuration": subprocess.getoutput("sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null") or "IPv6 status unknown",
        }
        # Normalize DHCP lease value
        lease_time = config.get("Weak DHCP Lease Time", "0")
        numeric = "".join(filter(str.isdigit, lease_time))
        config["Weak DHCP Lease Time"] = numeric if numeric else "0"
    except Exception as e:
        logger.error(f"Error fetching Linux config: {e}")
        config = {}
    return config


def fetch_windows_config():
    """Fetch current network configuration on Windows."""
    try:
        config = {
            "Unsecured Open Ports": _run_ps("netstat -ano"),
            "Weak DNS Configuration": _run_ps("Get-DnsClientServerAddress | Format-Table -HideTableHeaders"),
            "Unrestricted Network Access": _run_ps("Get-NetIPConfiguration | Format-Table -HideTableHeaders"),
            "Weak DHCP Lease Time": _run_ps('ipconfig /all | findstr /C:"Lease Duration"'),
            "Weak Default Route Configuration": _run_ps("Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop"),
            "No NTP Configuration": _run_ps("w32tm /query /configuration"),
            "Default Credentials on Network Devices": _run_ps("net user | findstr 'Administrator'"),
            "Exposed SMB Shares": _run_ps("net view \\\\localhost"),
            "Disabled Firewall": _run_ps("netsh advfirewall show allprofiles"),
            "Insecure IPv6 Configuration": _run_ps('ipconfig /all | findstr /C:"IPv6 Address"'),
        }
    except Exception as e:
        logger.error(f"Error fetching Windows config: {e}")
        config = {}
    return config


def fetch_macos_config():
    """Fetch current network configuration on macOS."""
    try:
        config = {
            "Unsecured Open Ports": subprocess.getoutput("netstat -an | grep -c LISTEN"),
            "Weak DNS Configuration": subprocess.getoutput("scutil --dns | awk '/nameserver/ {print $NF; exit}'"),
            "Unrestricted Network Access": subprocess.getoutput("networksetup -getinfo Wi-Fi 2>/dev/null | grep -E 'DHCP|Manually' | awk '{print $NF}'"),
            "Weak DHCP Lease Time": subprocess.getoutput("ipconfig getpacket en0 2>/dev/null | grep 'lease' | awk '{print $2}'") or "0",
            "Weak Default Route Configuration": subprocess.getoutput("netstat -rn | grep default") or "No default route found",
            "No NTP Configuration": subprocess.getoutput("systemsetup -getusingnetworktime 2>/dev/null || echo 'NTP not configured'"),
            "Default Credentials on Network Devices": subprocess.getoutput("dscl . list /Users 2>/dev/null | grep -E 'admin|root'"),
            "Exposed SMB Shares": subprocess.getoutput("smbutil statshares -a 2>/dev/null | grep -i 'Disk'") or "No shares found",
            "Disabled Firewall": subprocess.getoutput("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -i enabled") or "Firewall Disabled",
            "Insecure IPv6 Configuration": subprocess.getoutput("sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null") or "IPv6 status unknown",
        }
        lease_time = config.get("Weak DHCP Lease Time", "0")
        numeric = "".join(filter(str.isdigit, lease_time))
        config["Weak DHCP Lease Time"] = numeric if numeric else "0"
    except Exception as e:
        logger.error(f"Error fetching macOS config: {e}")
        config = {}
    return config


# --- Validators ---

def _validate_open_ports(value):
    """Misconfigured if >= 10 open ports."""
    try:
        if value.isdigit():
            return int(value) < 10
        matches = re.findall(r"\bLISTEN\w*\b", value, re.IGNORECASE)
        return len(matches) < 10
    except Exception:
        return False


def _validate_dns(value):
    """Configured if output includes at least one secure DNS server."""
    secure_dns = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"]
    return any(dns in value for dns in secure_dns)


def _validate_network_access(value):
    """Configured if any network info is returned."""
    return bool(value.strip()) and value.strip().lower() not in ("unknown", "error")


def _validate_dhcp_lease(value):
    """Configured if DHCP lease time >= 7200 seconds."""
    try:
        return int(value) >= 7200
    except (ValueError, TypeError):
        return False


def _validate_default_route(value):
    """Configured if a default route exists."""
    return "default" in value.lower()


def _validate_ntp(value):
    """Configured if NTP is active or enabled."""
    val = value.lower()
    return any(keyword in val for keyword in ("active", "enabled", "on", "yes"))


def _validate_default_credentials(value):
    """Misconfigured if default admin/root accounts found."""
    for username in ("root", "admin", "administrator"):
        if re.search(rf"\b{username}\b", value, re.IGNORECASE):
            return False
    return True


def _validate_smb_shares(value):
    """Misconfigured if network shares are exposed."""
    val = value.strip().lower()
    return "no shares found" in val or val == ""


def _validate_firewall(value):
    """Configured if firewall is active/enabled."""
    val = value.lower()
    return any(keyword in val for keyword in ("active", "enabled", "on", "state = 1"))


def _validate_ipv6(value):
    """Configured if IPv6 is disabled or secured."""
    val = value.lower()
    return any(keyword in val for keyword in (
        "disable_ipv6 = 1", "ra guard", "disabled", "sysctl: unknown oid"
    ))


VALIDATOR_MAP = {
    "Unsecured Open Ports": _validate_open_ports,
    "Weak DNS Configuration": _validate_dns,
    "Unrestricted Network Access": _validate_network_access,
    "Weak DHCP Lease Time": _validate_dhcp_lease,
    "Weak Default Route Configuration": _validate_default_route,
    "No NTP Configuration": _validate_ntp,
    "Default Credentials on Network Devices": _validate_default_credentials,
    "Exposed SMB Shares": _validate_smb_shares,
    "Disabled Firewall": _validate_firewall,
    "Insecure IPv6 Configuration": _validate_ipv6,
}


# --- Comparison and Reporting ---

def compare_configs(user_configs, practices):
    """Compare user config against best practices and return report + flagged items."""
    flagged = []
    report_lines = []

    for practice in practices:
        name = practice["misconfiguration"]
        recommended = practice["recommended_value"]
        source = practice["source"]
        risk = practice["risk_level"]
        current = user_configs.get(name, "Unknown")

        validator = VALIDATOR_MAP.get(name)
        if not validator or current in ("Unknown", "Error"):
            status = "UNKNOWN"
        elif validator(current):
            status = "CONFIGURED"
        else:
            status = "MISCONFIGURED"
            flagged.append({
                "misconfiguration": name,
                "current_value": str(current).strip(),
                "recommended_value": recommended,
                "source": source,
                "risk_level": risk,
            })

        report_lines.append(
            f"\n{name}\n"
            f"   - Recommended: {recommended}\n"
            f"   - Current: {current}\n"
            f"   - Status: {status}\n"
            f"   - Source: {source}\n"
            f"   - Risk Level: {risk}\n"
        )

    return "".join(report_lines), flagged


def display_network_info():
    """Display and return IP address and network type."""
    ip = fetch_ip_address()
    network_type = detect_network_type(ip)
    print("\n=== Network Information ===")
    print(f"  IP Address:   {ip}")
    print(f"  Network Type: {network_type}\n")
    return ip, network_type


def run_network_misconfig_scan():
    """Run the full network misconfiguration scan against best practices.

    Returns:
        tuple: (report_text, flagged_misconfigs, user_configs, network_type)
    """
    detected_os = detect_os()
    ip = fetch_ip_address()
    network_type = detect_network_type(ip)

    if detected_os == "Linux":
        user_configs = fetch_linux_config()
    elif detected_os == "Windows":
        user_configs = fetch_windows_config()
    elif detected_os == "Darwin":
        user_configs = fetch_macos_config()
    else:
        return "Unsupported OS", [], {}, network_type

    practices = BEST_PRACTICES.get(network_type, BEST_PRACTICES["Private"])
    report, flagged = compare_configs(user_configs, practices)
    return report, flagged, user_configs, network_type
