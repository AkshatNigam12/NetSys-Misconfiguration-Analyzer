"""
Scan Runner for Analyzer2.
Orchestrates network checks, system checks, and best-practice comparison.
Generates a unified PDF report.
"""

import os

from scanner.network_checks import (
    check_subnet_mask,
    check_gateway_configuration,
    check_dns_configuration,
    check_mtu_size,
    check_dhcp_settings,
    check_ntp_configuration,
    check_wireless_security,
)
from scanner.system_checks import (
    check_ssh_config,
    check_firewall_status,
    check_file_permissions,
    check_antivirus,
    check_user_accounts,
    check_system_logs,
)
from scanner.misconfig_scanner import run_network_misconfig_scan
from scanner.report_generator import ReportGenerator
from scanner.database import save_scan_data


def _run_checks(check_type, checks):
    """Run a list of checks and collect issues.

    Args:
        check_type: "Network" or "System"
        checks: List of (name, check_function) tuples.

    Returns:
        List of issue dicts.
    """
    issues = []
    for check_name, check_fn in checks:
        print(f"  Checking {check_name}...")
        try:
            result = check_fn()
        except Exception as e:
            result = {check_name: f"Error: {e}"}

        if result:
            key = list(result.keys())[0]
            issues.append({
                "name": check_name,
                "current_status": result.get(key, "N/A"),
                "risk_level": "High",
                "description": f"{check_type} misconfiguration detected.",
                "suggested_fix": "Refer to security best practices.",
                "type": check_type,
            })
            print(f"    [-] Issue detected in {check_name}")
        else:
            print(f"    [+] {check_name} OK")

    return issues


def run_scan(generate_report=True, report_directory="reports"):
    """Run the full scan and optionally generate a PDF report.

    Args:
        generate_report: Whether to generate a PDF report (default True).
        report_directory: Directory to save reports in.

    Returns:
        dict with keys: network_results, system_results, misconfig_results,
                        report_path (if generated), issues (combined).
    """
    print("\n" + "=" * 50)
    print("  Analyzer2 - Security Scan Starting")
    print("=" * 50 + "\n")

    # --- Network Checks ---
    print("[*] NETWORK CONFIGURATION SCAN")
    print("-" * 40)
    network_checks = [
        ("Subnet Mask", check_subnet_mask),
        ("Gateway Configuration", check_gateway_configuration),
        ("DNS Configuration", check_dns_configuration),
        ("MTU Size", check_mtu_size),
        ("DHCP Settings", check_dhcp_settings),
        ("NTP Configuration", check_ntp_configuration),
        ("Wireless Security", check_wireless_security),
    ]
    network_results = _run_checks("Network", network_checks)

    # --- System Checks ---
    print(f"\n[*] SYSTEM CONFIGURATION SCAN")
    print("-" * 40)
    system_checks = [
        ("SSH Configuration", check_ssh_config),
        ("Firewall Status", check_firewall_status),
        ("File Permissions", check_file_permissions),
        ("Antivirus Status", check_antivirus),
        ("User Accounts", check_user_accounts),
        ("System Logs", check_system_logs),
    ]
    system_results = _run_checks("System", system_checks)

    # --- Best-Practice Comparison ---
    print(f"\n[*] CIS/NIST BEST-PRACTICE COMPARISON")
    print("-" * 40)
    misconfig_results = run_network_misconfig_scan()
    _, flagged, _, network_type = misconfig_results
    print(f"  Network type: {network_type}")
    print(f"  Flagged misconfigurations: {len(flagged)}")

    # --- Summary ---
    total = len(network_results) + len(system_results) + len(flagged)
    print(f"\n{'=' * 50}")
    print(f"  SCAN COMPLETE - {total} issue(s) found")
    print(f"{'=' * 50}\n")

    # --- Report Generation ---
    report_path = None
    if generate_report:
        os.makedirs(report_directory, exist_ok=True)
        report_gen = ReportGenerator(report_directory=report_directory)
        report_path = report_gen.generate(
            network_issues=network_results,
            system_issues=system_results,
            misconfig_results=misconfig_results,
        )
        if report_path:
            print(f"[+] Report saved to: {report_path}")

    # --- Persist to DB (best-effort) ---
    scan_data = {
        "network_issues": len(network_results),
        "system_issues": len(system_results),
        "misconfig_flagged": len(flagged),
        "network_type": network_type,
    }
    save_scan_data(scan_data)

    return {
        "network_results": network_results,
        "system_results": system_results,
        "misconfig_results": misconfig_results,
        "report_path": report_path,
        "issues": {
            "Network Issues": network_results,
            "System Issues": system_results,
            "Best-Practice Violations": flagged,
        },
    }
