#!/usr/bin/env python3
"""
Setup and run script for the bluep collaborative text editor.
This script handles initial project setup and configuration.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
import venv
import shutil


def print_step(msg: str) -> None:
    """Print a formatted step message."""
    print("\n" + "=" * 40)
    print(msg)
    print("=" * 40)


def run_command(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command with proper error handling."""
    try:
        return subprocess.run(cmd, check=True, **kwargs)
    except subprocess.CalledProcessError as e:
        print(f"Error running command {' '.join(cmd)}: {e}")
        sys.exit(1)


def check_python_version() -> None:
    """Check if Python version meets requirements."""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)


def setup_venv(venv_path: Path) -> Path:
    """Create and activate a virtual environment."""
    print_step("Setting up virtual environment...")

    if not venv_path.exists():
        venv.create(venv_path, with_pip=True)

    # Determine the path to the virtual environment's Python executable
    if platform.system() == "Windows":
        python_path = venv_path / "Scripts" / "python.exe"
    else:
        python_path = venv_path / "bin" / "python"

    if not python_path.exists():
        print(f"Error: Could not find Python executable at {python_path}")
        sys.exit(1)

    return python_path


def generate_ssl_certs() -> None:
    """Generate SSL certificates if they don't exist."""
    print_step("Checking SSL certificates...")

    if not Path("cert.pem").exists() or not Path("key.pem").exists():
        print("Generating SSL certificates...")
        if platform.system() == "Windows":
            print("Error: Please generate SSL certificates manually on Windows")
            print("Run the following command in Git Bash or similar:")
            print("openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365")
            sys.exit(1)
        else:
            run_command([
                "openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes",
                "-keyout", "key.pem", "-out", "cert.pem", "-days", "365",
                "-subj", "/CN=localhost"
            ])


def install_dependencies(python_path: Path) -> None:
    """Install project dependencies."""
    print_step("Installing dependencies...")
    run_command([str(python_path), "-m", "pip", "install", "-e", "."])


def run_server(python_path: Path) -> None:
    """Start the bluep server."""
    print_step("Starting bluep server...")
    try:
        run_command([str(python_path), "-m", "bluep.bluep"])
    except KeyboardInterrupt:
        print("\nServer stopped")


def main() -> None:
    """Main setup and run function."""
    # Store the project root directory
    project_root = Path(__file__).parent.absolute()
    os.chdir(project_root)

    print_step("Starting bluep setup...")

    # Check Python version
    check_python_version()

    # Setup virtual environment
    venv_path = project_root / ".venv"
    python_path = setup_venv(venv_path)

    # Generate SSL certificates
    generate_ssl_certs()

    # Install dependencies
    install_dependencies(python_path)

    # Start the server
    run_server(python_path)


if __name__ == "__main__":
    main()
