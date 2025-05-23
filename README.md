# bluep

A secure real-time collaborative text editor with TOTP authentication and a blue theme. Multiple users can connect and edit text simultaneously through their browsers.

## Quick Start
```bash
# Clone the repository
git clone https://github.com/glassontin/bluep.git
cd bluep

# Run the setup script
python setup.py
```

## Features
- Two-factor authentication using TOTP
- Real-time text synchronization across clients
- Secure WebSocket communication over HTTPS
- Session management with replay attack prevention
- Machine-specific encryption for TOTP secrets
- Cross-platform configuration storage
- Auto-discovery of local IP address
- Blue minimalist interface

## Requirements
- Python 3.7+
- OpenSSL for certificate generation

## Installation

```bash
git clone https://github.com/glassontin/bluep.git
cd bluep
pip install .
```

## Configuration
1. Generate self-signed SSL certificates:
```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365
```

2. Visit the setup page to configure TOTP:
```
https://<your-local-ip>:8500/setup
```
- Scan the QR code with your authenticator app
- Save the secret key as backup

## Usage
1. Start the server:
```bash
bluep
```

2. Access the editor:
```
https://<your-local-ip>:8500
```

3. Enter your TOTP code to join the editing session

## Security Features
- TOTP-based access control
- Rate limiting for failed authentication attempts
- Secure session management
- HTTPS/WSS encryption
- HTTP-only secure cookies
- Machine-bound configuration encryption

## Dependencies
- FastAPI
- uvicorn
- Pillow
- websockets
- pyotp
- qrcode
- cryptography
- pydantic
- jinja2

## Running as a System Service

### Standard Linux Installation

On Linux systems with systemd, you can install bluep as a system service:

```bash
# Install the service (requires sudo)
sudo python install_service.py

# Start the service
sudo systemctl start bluep

# Enable service to start on boot
sudo systemctl enable bluep

# Check service status
sudo systemctl status bluep

# View logs
sudo journalctl -u bluep
```

The service will run with reduced privileges and several security measures enabled:
- Private /tmp directory
- Read-only access to /home
- Protected system directories
- No new privileges
- No kernel module or tunable access
- No device access

You can customize the user the service runs as:
```bash
sudo python install_service.py --user your_username
```

### Windows Installation

Bluep now supports running natively on Windows 11 without requiring WSL. Use the included PowerShell setup script to configure your Windows environment:

```powershell
# Run as Administrator
# Right-click on windows_setup.ps1 and select "Run with PowerShell as Administrator"
# Or from an elevated PowerShell prompt:
PowerShell.exe -ExecutionPolicy Bypass -File windows_setup.ps1
```

This script will:
1. Configure the Windows Firewall to allow traffic on port 8500
2. Check for and install OpenSSL if needed
3. Set up the Python virtual environment and install dependencies
4. Generate SSL certificates if they don't exist
5. Create a Windows scheduled task to run Bluep as a service

Alternatively, you can run Bluep manually using the batch script:

```cmd
run_bluep_windows.bat
```

You can access Bluep in your browser at `https://localhost:8500` or `https://<your-ip-address>:8500` from other devices on your network.

## License
MIT License

Copyright (c) 2024 glassontin
