"""
Configuration for Analyzer2.
Reads sensitive values from environment variables with sensible defaults.
"""

import os
import sys
import platform
import subprocess


# --- MongoDB Configuration ---
# Set these in your environment or a .env file
MONGODB_URI = os.getenv(
    "ANALYZER_MONGODB_URI",
    "mongodb://localhost:27017",  # Default to local MongoDB
)
DB_NAME = os.getenv("ANALYZER_DB_NAME", "Misconfig_tool")
SCANS_COLLECTION = os.getenv("ANALYZER_SCANS_COLLECTION", "Scans")
MISCONFIG_COLLECTION = os.getenv("ANALYZER_MISCONFIG_COLLECTION", "Misconfigurations")

# --- API Configuration ---
API_HOST = os.getenv("ANALYZER_API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("ANALYZER_API_PORT", "8000"))
API_URL = os.getenv("ANALYZER_API_URL", f"http://{API_HOST}:{API_PORT}")


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller."""
    try:
        base_path = sys._MEIPASS  # PyInstaller temp folder
    except AttributeError:
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


class ScannerConfig:
    """Scanner-specific configuration values."""

    # Default expected values for network checks
    DEFAULT_SUBNET_MASK = "255.255.255.0"
    DEFAULT_GATEWAY = "192.168.1.1"
    DEFAULT_DNS = "8.8.8.8"
    DEFAULT_MTU = 1500
    DEFAULT_NTP = "pool.ntp.org"

    # System paths to check
    WINDOWS_SYSTEM32_PATH = "C:\\Windows\\System32"
    MACOS_SYSTEM_PATHS = [
        "/private/etc/passwd",
        "/private/etc/master.passwd",
        "/private/etc/group",
    ]
    LINUX_CRITICAL_PATHS = ["/etc/passwd", "/etc/shadow", "/etc/group"]

    # Report output directory
    REPORT_DIRECTORY = resource_path("reports")

    @staticmethod
    def get_system_paths():
        """Get the appropriate system paths based on OS."""
        system = platform.system()
        if system == "Darwin":
            return ScannerConfig.MACOS_SYSTEM_PATHS
        elif system == "Windows":
            return [ScannerConfig.WINDOWS_SYSTEM32_PATH]
        else:
            return ScannerConfig.LINUX_CRITICAL_PATHS


# --- Utility Functions ---

def get_os():
    """Detect the current operating system."""
    return platform.system()


def is_windows():
    """Check if the system is Windows."""
    return platform.system().lower() == "windows"


def is_macos():
    """Check if the system is macOS."""
    return platform.system().lower() == "darwin"


def is_linux():
    """Check if the system is Linux."""
    return platform.system().lower() == "linux"


def run_command(command):
    """Run a system command and return the output."""
    try:
        if isinstance(command, str):
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=30
            )
        else:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=30
            )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        return ""


def check_command_exists(command):
    """Check if a command exists in the system."""
    try:
        cmd = ["where", command] if is_windows() else ["which", command]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False


def setup_environment():
    """Set up the required directories and check dependencies."""
    try:
        os.makedirs(ScannerConfig.REPORT_DIRECTORY, exist_ok=True)

        if is_windows():
            required_commands = ["powershell.exe", "ipconfig", "netsh"]
        elif is_macos():
            required_commands = ["ifconfig", "networksetup", "scutil", "defaults"]
        else:
            required_commands = ["ifconfig", "ip", "nmcli", "ufw"]

        missing_commands = [
            cmd for cmd in required_commands if not check_command_exists(cmd)
        ]

        if missing_commands:
            print("[!] Warning: The following commands are missing:")
            for cmd in missing_commands:
                print(f"    - {cmd}")
            print("Some functionality may be limited.")

        return True
    except Exception as e:
        print(f"[!] Error setting up environment: {str(e)}")
        return False
