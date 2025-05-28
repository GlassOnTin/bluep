#!/usr/bin/env python3
"""
Script to install bluep as a systemd service.
This script creates and installs a systemd service unit for running
bluep as a background service on Linux systems.
"""

import os
import sys
import pwd
import platform
import subprocess
from pathlib import Path
import argparse


def get_executable_paths() -> tuple[str, str]:
    """Get the paths to python and bluep executable.

    Returns:
        tuple: (python_path, bluep_path)
    """
    # Get path to the virtual environment's Python
    venv_path = Path(__file__).parent / ".venv"
    if platform.system() == "Windows":
        python_path = str(venv_path / "Scripts" / "python.exe")
    else:
        python_path = str(venv_path / "bin" / "python")

    # Get path to bluep module
    bluep_path = str(Path(__file__).parent)

    return python_path, bluep_path


def create_service_file(
    user: str, group: str, python_path: str, bluep_path: str
) -> str:
    """Create the systemd service unit file content.

    Args:
        user: User to run the service as
        group: Group to run the service as
        python_path: Path to Python executable
        bluep_path: Path to bluep installation

    Returns:
        str: Service unit file content
    """
    # Get user's home directory
    import pwd
    user_home = pwd.getpwnam(user).pw_dir
    
    return f"""[Unit]
Description=Bluep Collaborative Text Editor
After=network.target

[Service]
Type=simple
User={user}
Group={group}
WorkingDirectory={bluep_path}
# Use bash login shell to source user environment
ExecStart=/bin/bash -l -c '{python_path} -m bluep.bluep'
Restart=always
RestartSec=3

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths={user_home}/.bluep
# Allow PTY allocation for terminal feature
PrivateDevices=no
CapabilityBoundingSet=
AmbientCapabilities=
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
# Ensure sufficient process limits
TasksMax=100

[Install]
WantedBy=multi-user.target
"""


def install_service(service_content: str) -> None:
    """Install the systemd service unit file.

    Args:
        service_content: Content of the service unit file
    """
    service_path = "/etc/systemd/system/bluep.service"

    try:
        with open(service_path, "w") as f:
            f.write(service_content)

        # Set correct permissions
        os.chmod(service_path, 0o644)

        # Reload systemd daemon
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        print(f"Service installed successfully at {service_path}")

    except PermissionError:
        print("Error: Must run with sudo privileges to install service")
        sys.exit(1)


def check_systemd() -> None:
    """Check if systemd is available on the system."""
    try:
        subprocess.run(["systemctl", "--version"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: systemd is not available on this system")
        sys.exit(1)


def validate_user(username: str) -> tuple[str, str]:
    """Validate user exists and get their primary group.

    Args:
        username: Username to validate

    Returns:
        tuple: (username, group name)
    """
    try:
        user_info = pwd.getpwnam(username)
        group_info = pwd.getpwnam(username)
        return username, group_info.pw_name
    except KeyError:
        print(f"Error: User '{username}' does not exist")
        sys.exit(1)


def main() -> None:
    """Main installation function."""
    # Check if running on Linux
    if sys.platform != "linux":
        print("Error: This script only supports Linux systems")
        sys.exit(1)

    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script must be run with sudo privileges")
        sys.exit(1)

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Install bluep as a systemd service")
    parser.add_argument(
        "--user",
        default=os.environ.get("SUDO_USER", "root"),
        help="User to run the service as (default: current user)",
    )
    args = parser.parse_args()

    # Check systemd availability
    check_systemd()

    # Validate user and get group
    user, group = validate_user(args.user)

    # Get executable paths
    python_path, bluep_path = get_executable_paths()

    # Create and install service
    service_content = create_service_file(user, group, python_path, bluep_path)
    install_service(service_content)

    print("\nTo start the service:")
    print("  sudo systemctl start bluep")
    print("\nTo enable service on boot:")
    print("  sudo systemctl enable bluep")
    print("\nTo check service status:")
    print("  sudo systemctl status bluep")
    print("\nTo view logs:")
    print("  sudo journalctl -u bluep")


if __name__ == "__main__":
    main()
