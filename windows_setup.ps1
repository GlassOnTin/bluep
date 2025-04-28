# Windows Setup Script for Bluep Collaborative Editor
# This script sets up and configures the Bluep editor on Windows 11

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as Administrator!"
    Write-Host "Exiting..."
    exit
}

# Set working directory to script location
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptPath
$projectPath = $scriptPath

Write-Host "Setting up Bluep Collaborative Editor on Windows 11..." -ForegroundColor Cyan

# Step 1: Configure Windows Firewall
Write-Host "`nStep 1: Configuring Windows Firewall..." -ForegroundColor Green
try {
    $firewallRuleExists = Get-NetFirewallRule -DisplayName "Bluep Collaborative Editor" -ErrorAction SilentlyContinue
    if (-not $firewallRuleExists) {
        New-NetFirewallRule -DisplayName "Bluep Collaborative Editor" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8500
        Write-Host "Firewall rule created successfully for port 8500" -ForegroundColor Green
    } else {
        Write-Host "Firewall rule for Bluep already exists" -ForegroundColor Green
    }
} catch {
    Write-Host "Error configuring firewall: $_" -ForegroundColor Red
}

# Step 2: Check if OpenSSL is installed
Write-Host "`nStep 2: Checking for OpenSSL..." -ForegroundColor Green
$openSSLPath = ""
try {
    $openSSLPath = (Get-Command openssl -ErrorAction SilentlyContinue).Source
    if ($openSSLPath) {
        Write-Host "OpenSSL found at: $openSSLPath" -ForegroundColor Green
    } else {
        Write-Host "OpenSSL not found. Installing via winget..." -ForegroundColor Yellow
        winget install ShiningLight.OpenSSL
        
        # After installation, find OpenSSL again
        $openSSLPath = (Get-Command openssl -ErrorAction SilentlyContinue).Source
        if ($openSSLPath) {
            Write-Host "OpenSSL installed successfully" -ForegroundColor Green
        } else {
            Write-Host "OpenSSL installation may have failed. Please install manually." -ForegroundColor Red
            Write-Host "You can download from: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "Error checking for OpenSSL: $_" -ForegroundColor Red
}

# Step 3: Check for Python and set up virtual environment
Write-Host "`nStep 3: Setting up Python environment..." -ForegroundColor Green
try {
    $pythonCmd = ""
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $pythonCmd = "py"
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        $pythonCmd = "python"
    } else {
        Write-Host "Python not found. Installing Python 3.11..." -ForegroundColor Yellow
        winget install Python.Python.3.11
        $pythonCmd = "py"
    }
    
    Write-Host "Using Python command: $pythonCmd" -ForegroundColor Green
    
    # Create or verify virtual environment
    if (-not (Test-Path ".venv")) {
        Write-Host "Creating virtual environment..." -ForegroundColor Yellow
        & $pythonCmd -m venv .venv
    } else {
        Write-Host "Virtual environment already exists" -ForegroundColor Green
    }
    
    # Activate virtual environment and install dependencies
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    & .\.venv\Scripts\Activate.ps1
    & pip install --upgrade pip
    & pip install -e .
    
    Write-Host "Python environment setup complete" -ForegroundColor Green
} catch {
    Write-Host "Error setting up Python environment: $_" -ForegroundColor Red
}

# Step 4: Generate SSL certificates if they don't exist
Write-Host "`nStep 4: Checking SSL certificates..." -ForegroundColor Green
if (-not ((Test-Path "cert.pem") -and (Test-Path "key.pem"))) {
    Write-Host "Generating SSL certificates..." -ForegroundColor Yellow
    if ($openSSLPath) {
        try {
            & openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"
            Write-Host "SSL certificates generated successfully" -ForegroundColor Green
        } catch {
            Write-Host "Error generating SSL certificates: $_" -ForegroundColor Red
            Write-Host "You may need to generate certificates manually" -ForegroundColor Yellow
        }
    } else {
        Write-Host "OpenSSL not available. Cannot generate certificates automatically." -ForegroundColor Red
    }
} else {
    Write-Host "SSL certificates already exist" -ForegroundColor Green
}

# Step 5: Create Windows Service Equivalent using Task Scheduler
Write-Host "`nStep 5: Setting up Windows Task Scheduler service..." -ForegroundColor Green
$taskName = "BluepCollaborativeEditor"
$taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($taskExists) {
    Write-Host "Removing existing task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

try {
    $pythonExe = Join-Path $projectPath ".venv\Scripts\pythonw.exe"
    $bluepModule = Join-Path $projectPath "bluep\bluep.py"
    
    # Create action to run bluep
    $action = New-ScheduledTaskAction -Execute $pythonExe -Argument "-m bluep.bluep" -WorkingDirectory $projectPath
    
    # Create trigger to run at startup and when user logs in
    $triggerStartup = New-ScheduledTaskTrigger -AtStartup
    $triggerLogon = New-ScheduledTaskTrigger -AtLogOn
    
    # Set principal to run as current user
    $principal = New-ScheduledTaskPrincipal -UserId (Get-CimInstance -ClassName Win32_ComputerSystem).Username -LogonType S4U -RunLevel Highest
    
    # Create task with restart settings
    $settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Hours 0)
    
    # Register the task
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($triggerStartup, $triggerLogon) -Principal $principal -Settings $settings -Description "Bluep Collaborative Text Editor"
    
    Write-Host "Windows Task Scheduler service created successfully" -ForegroundColor Green
} catch {
    Write-Host "Error creating Windows service: $_" -ForegroundColor Red
}

# Step 6: Start the service for the first time
Write-Host "`nStep 6: Starting Bluep service..." -ForegroundColor Green
try {
    Start-ScheduledTask -TaskName $taskName
    Write-Host "Bluep service started successfully" -ForegroundColor Green
} catch {
    Write-Host "Error starting Bluep service: $_" -ForegroundColor Red
}

# Display completion message and instructions
Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "Bluep setup complete!" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "To access Bluep, navigate to: https://localhost:8500" -ForegroundColor Yellow
Write-Host "On first run, access the setup page at: https://localhost:8500/setup" -ForegroundColor Yellow
Write-Host "Scan the QR code with your authenticator app and save the secret key as backup" -ForegroundColor Yellow
Write-Host "`nTo start the service manually:" -ForegroundColor White
Write-Host "Start-ScheduledTask -TaskName '$taskName'" -ForegroundColor White
Write-Host "`nTo stop the service:" -ForegroundColor White
Write-Host "Stop-ScheduledTask -TaskName '$taskName'" -ForegroundColor White
Write-Host "`nTo check service status:" -ForegroundColor White
Write-Host "Get-ScheduledTask -TaskName '$taskName' | Select-Object TaskName, State" -ForegroundColor White
Write-Host "=====================================" -ForegroundColor Cyan
