# Bluep MCP Client

Standalone client for accessing MCP (Model Context Protocol) services hosted on a bluep server.

## Installation

```bash
pip install bluep-mcp-client
```

Or install from source:
```bash
git clone https://github.com/glassontin/bluep.git
cd bluep/bluep-mcp-client
pip install .
```

## Quick Start

1. **Get your session token** from bluep:
   - Log into your bluep server (https://your-server:8500)
   - Open browser developer tools (F12)
   - Go to Application/Storage → Cookies
   - Copy the value of the `session` cookie

2. **Save your authentication**:
   ```bash
   bluep-mcp auth --token YOUR_SESSION_TOKEN
   ```

3. **List available MCP services**:
   ```bash
   bluep-mcp list --server wss://your-server:8500/ws
   ```

4. **Start a local proxy**:
   ```bash
   bluep-mcp proxy azure-devops --port 4000
   ```

## Usage

### Authentication

You can provide your session token in three ways:
1. Command line: `--token YOUR_TOKEN`
2. Environment variable: `export BLUEP_SESSION=YOUR_TOKEN`
3. Save it: `bluep-mcp auth --token YOUR_TOKEN`

### List Services

```bash
# List all available MCP services
bluep-mcp list --server wss://your-server:8500/ws

# With custom server and no SSL verification
bluep-mcp list --server wss://192.168.1.100:8500/ws --no-verify-ssl
```

### Start Proxy

```bash
# HTTP proxy (default)
bluep-mcp proxy azure-devops --port 4000

# WebSocket proxy
bluep-mcp proxy github --port 4001 --websocket

# Custom server
bluep-mcp proxy my-service --server wss://bluep.example.com/ws --port 4002
```

### Configure Claude

Once the proxy is running, configure Claude to use it:

```json
{
  "mcpServers": {
    "azure-devops": {
      "command": "curl",
      "args": ["-X", "POST", "http://localhost:4000"]
    }
  }
}
```

## Security Notes

- Session tokens are stored in `~/.bluep/session` with restricted permissions (0600)
- Use `--no-verify-ssl` only for self-signed certificates in development
- The proxy only listens on localhost by default for security

## Troubleshooting

### Connection Issues
- Ensure your bluep server is running and accessible
- Check that your session token is valid and not expired
- For self-signed certificates, use `--no-verify-ssl`

### Service Not Available
- Verify the service is installed on the bluep server
- Check that another client is hosting the service
- Use `bluep-mcp list` to see available services

## Examples

### Complete Workflow

```bash
# 1. Save your credentials
bluep-mcp auth --token abc123def456

# 2. Check available services
bluep-mcp list --server wss://192.168.1.100:8500/ws --no-verify-ssl

# 3. Start proxy for Azure DevOps
bluep-mcp proxy azure-devops --server wss://192.168.1.100:8500/ws --port 4000 --no-verify-ssl

# 4. In another terminal, use with Claude or test directly
curl -X POST http://localhost:4000 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

## License

MIT License - See the main bluep repository for details.