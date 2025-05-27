# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
Bluep is a secure real-time collaborative text editor with TOTP authentication. It's built with FastAPI and uses WebSockets for real-time text synchronization across multiple clients.

## Build and Test Commands
- Run server: `python -m bluep.bluep`
- Run all tests: `pytest`
- Run single test: `pytest tests/test_file.py::test_function_name`
- Test with coverage: `pytest --cov=bluep tests/`
- Type checking: `mypy bluep/`
- Build package: `python -m build`
- Install development mode: `pip install -e .`
- Setup environment: `python setup.py` (creates venv, installs deps, generates SSL certs)

## Architecture and Key Components

### Core Modules
- **bluep.py**: Main FastAPI application with route handlers and server initialization
- **auth.py**: TOTP authentication system with QR code generation and verification
- **websocket_manager.py**: Manages WebSocket connections and text synchronization
- **secure_config.py**: Machine-specific encryption for storing TOTP secrets
- **middleware.py**: Security middleware for rate limiting and request validation
- **session_manager.py**: Secure session handling with replay attack prevention
- **models.py**: Pydantic models for request/response validation
- **process_manager.py**: Terminal process management for running CLI tools in the browser

### Security Architecture
- TOTP authentication with one-time setup at `/setup`
- Machine-bound encryption for configuration storage
- TLS/SSL encryption for all connections (self-signed certs)
- Rate limiting on authentication attempts
- Session tokens with replay attack prevention
- WebSocket authentication using session tokens

### WebSocket Protocol
Messages use JSON with structure: `{"type": "message_type", "data": {...}}`
- Client → Server: text updates, cursor positions, authentication, process commands
- Server → Client: synchronized text, user list updates, error messages, process output

### Terminal Feature
- Access at `/terminal` route with full terminal emulation
- Supports spawning bash, python, node, and other CLI processes
- Real-time stdio streaming over WebSocket with base64 encoding
- Security: command whitelisting, resource limits, forbidden patterns
- Process management: spawn, input, output, resize, terminate

## Code Style Guidelines
- **Type Annotations**: Use strict typing with explicit return types (including `-> None`)
- **Imports**: Standard lib first, third-party next, local imports last (alphabetized within groups)
- **Naming**: Classes in PascalCase, functions/variables in snake_case, private methods with leading underscore
- **Error Handling**: Use specific exceptions with detailed messages, log errors before raising
- **Documentation**: Every module and function needs docstrings in Google style format
- **Security**: Validate TLS certificates, use TOTP authentication, implement rate limiting
- **Testing**: Create pytest fixtures, mock external dependencies, test security features thoroughly

## Cross-Platform Considerations
- Configuration storage: AppData (Windows), ~/.config (Linux), ~/Library (macOS)
- SSL certificate paths: Handle both relative and absolute paths
- Service installation: systemd (Linux) or Task Scheduler (Windows)
- File operations: Use pathlib.Path for cross-platform compatibility

## Development Workflow
1. Any changes to authentication must include security tests
2. WebSocket changes require testing with multiple concurrent clients
3. Configuration changes must preserve backward compatibility
4. Always run mypy before committing type-related changes
5. Test on both Linux and Windows when modifying platform-specific code