"""
Network configuration checks for Analyzer2.
Each function returns a dict with the issue details if a problem is found, or None if OK.
"""

from scanner.config import run_command, get_os, ScannerConfig


def check_subnet_mask(expected_mask=None):
    """Check if subnet mask matches expected value."""
    if expected_mask is None:
        expected_mask = ScannerConfig.DEFAULT_SUBNET_MASK

    os_type = get_os()
    try:
        if os_type in ("Linux", "Darwin"):
            current_mask = run_command("ifconfig | grep netmask")
        elif os_type == "Windows":
            current_mask = run_command('ipconfig | findstr /i "Subnet"')
        else:
            return None

        if not current_mask or expected_mask not in current_mask:
            return {
                "subnet_mask": f"Mismatch: Expected {expected_mask}, found {current_mask or 'N/A'}"
            }
        return None
    except Exception as e:
        return {"subnet_mask": f"Error checking subnet mask: {e}"}


def check_gateway_configuration(expected_gateway=None):
    """Check if default gateway matches expected value."""
    if expected_gateway is None:
        expected_gateway = ScannerConfig.DEFAULT_GATEWAY

    os_type = get_os()
    try:
        if os_type == "Linux":
            current_gateway = run_command("ip route | grep default | awk '{print $3}'")
        elif os_type == "Darwin":
            current_gateway = run_command("route -n get default | grep gateway")
        elif os_type == "Windows":
            current_gateway = run_command('ipconfig | findstr /i "Gateway"')
        else:
            return None

        if not current_gateway or expected_gateway not in current_gateway:
            return {
                "gateway_configuration": f"Mismatch: Expected {expected_gateway}, found {current_gateway or 'N/A'}"
            }
        return None
    except Exception as e:
        return {"gateway_configuration": f"Error checking gateway: {e}"}


def check_dns_configuration(expected_dns=None):
    """Check if DNS server matches expected value."""
    if expected_dns is None:
        expected_dns = ScannerConfig.DEFAULT_DNS

    os_type = get_os()
    try:
        if os_type == "Linux":
            current_dns = run_command("nmcli dev show | grep DNS")
        elif os_type == "Darwin":
            current_dns = run_command("scutil --dns | grep 'nameserver' | head -1")
        elif os_type == "Windows":
            current_dns = run_command("nslookup google.com")
        else:
            return None

        if not current_dns or expected_dns not in current_dns:
            return {
                "dns_configuration": f"Mismatch: Expected {expected_dns}, found {current_dns or 'N/A'}"
            }
        return None
    except Exception as e:
        return {"dns_configuration": f"Error checking DNS: {e}"}


def check_mtu_size(expected_mtu=None):
    """Check if MTU size matches expected value."""
    if expected_mtu is None:
        expected_mtu = ScannerConfig.DEFAULT_MTU

    os_type = get_os()
    try:
        if os_type in ("Linux", "Darwin"):
            current_mtu = run_command("ifconfig | grep mtu")
        elif os_type == "Windows":
            current_mtu = run_command("netsh interface ipv4 show subinterfaces")
        else:
            return None

        if not current_mtu or str(expected_mtu) not in current_mtu:
            return {
                "mtu_size": f"Mismatch: Expected {expected_mtu}, found {current_mtu or 'N/A'}"
            }
        return None
    except Exception as e:
        return {"mtu_size": f"Error checking MTU size: {e}"}


def check_dhcp_settings():
    """Check if DHCP is configured properly."""
    os_type = get_os()
    try:
        if os_type == "Linux":
            dhcp_status = run_command("cat /etc/resolv.conf | grep 'nameserver'")
        elif os_type == "Darwin":
            dhcp_status = run_command("scutil --dns | grep DHCP")
        elif os_type == "Windows":
            dhcp_status = run_command('ipconfig /all | findstr /i "DHCP"')
        else:
            return None

        if not dhcp_status:
            return {"dhcp_settings": "DHCP is not enabled or not configured properly"}
        return None
    except Exception as e:
        return {"dhcp_settings": f"Error checking DHCP: {e}"}


def check_ntp_configuration(expected_ntp=None):
    """Check if NTP is configured properly."""
    if expected_ntp is None:
        expected_ntp = ScannerConfig.DEFAULT_NTP

    os_type = get_os()
    try:
        if os_type in ("Linux", "Darwin"):
            ntp_status = run_command("ntpq -p 2>/dev/null || timedatectl show-timesync 2>/dev/null || echo 'NTP not found'")
        elif os_type == "Windows":
            ntp_status = run_command("w32tm /query /status")
        else:
            return None

        if not ntp_status or "not found" in ntp_status.lower():
            return {
                "ntp_configuration": f"NTP not properly configured. Expected server: {expected_ntp}"
            }
        return None
    except Exception as e:
        return {"ntp_configuration": f"Error checking NTP: {e}"}


def check_wireless_security():
    """Check wireless network security settings."""
    os_type = get_os()
    try:
        if os_type == "Linux":
            wireless_security = run_command("nmcli -t -f active,ssid,security dev wifi")
        elif os_type == "Darwin":
            wireless_security = run_command(
                "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | grep -i auth"
            )
        elif os_type == "Windows":
            wireless_security = run_command("netsh wlan show networks mode=bssid")
        else:
            return None

        if not wireless_security:
            return {"wireless_security": "Could not determine wireless security status"}

        if "WPA" not in wireless_security.upper() and "WEP" not in wireless_security.upper():
            return {"wireless_security": "Weak or no wireless security detected"}
        return None
    except Exception as e:
        return {"wireless_security": f"Error checking wireless security: {e}"}
