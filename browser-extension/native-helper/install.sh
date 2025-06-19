#!/bin/bash
# Installation script for Bluep MCP Bridge Native Helper

set -e

echo "Installing Bluep MCP Bridge Native Helper..."

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Install dependencies
echo "Installing Python dependencies..."
pip3 install --user aiohttp

# Copy the native helper script
INSTALL_DIR="/usr/local/bin"
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    MANIFEST_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    MANIFEST_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

# Create directories
mkdir -p "$MANIFEST_DIR"
sudo mkdir -p "$INSTALL_DIR"

# Copy the Python script
sudo cp bluep_mcp_bridge.py "$INSTALL_DIR/bluep_mcp_bridge"
sudo chmod +x "$INSTALL_DIR/bluep_mcp_bridge"

# Update the manifest with the correct path
sed "s|/usr/local/bin/bluep_mcp_bridge|$INSTALL_DIR/bluep_mcp_bridge|g" com.bluep.mcp_bridge.json > "$MANIFEST_DIR/com.bluep.mcp_bridge.json"

echo "Native helper installed successfully!"
echo ""
echo "Next steps:"
echo "1. Install the Bluep MCP Bridge browser extension"
echo "2. Update the extension ID in: $MANIFEST_DIR/com.bluep.mcp_bridge.json"
echo "3. Restart Chrome"
echo ""
echo "The native helper is installed at: $INSTALL_DIR/bluep_mcp_bridge"
echo "The manifest is installed at: $MANIFEST_DIR/com.bluep.mcp_bridge.json"