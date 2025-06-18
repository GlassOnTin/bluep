# MCP Services Directory

This directory contains installed MCP (Model Context Protocol) servers that can be exposed through bluep.

## Structure

Each MCP service is installed in its own subdirectory:
```
mcp-services/
├── azure-devops/
│   ├── package.json
│   ├── node_modules/
│   └── ...
├── github/
│   ├── package.json
│   ├── node_modules/
│   └── ...
└── ...
```

## Installing MCP Services

To install a new MCP service:

```bash
cd mcp-services
git clone https://github.com/Tiberriver256/mcp-server-azure-devops azure-devops
cd azure-devops
npm install
```

## Service Discovery

Bluep automatically discovers MCP services by scanning this directory for:
1. Valid Node.js projects (containing package.json)
2. MCP server configuration files
3. Executable entry points

## Security

- Each MCP service runs in an isolated process
- Services are sandboxed with resource limits
- Authentication is required to access MCP services
- Services cannot access files outside their directory