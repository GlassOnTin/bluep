# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
Bluep is a secure real-time collaborative text editor with TOTP authentication. It's built with FastAPI and uses WebSockets for real-time text synchronization across multiple clients.

## Build and Test Commands

### Core Development
- Run server: `python -m bluep.bluep` (default port: 8500)
- Run server (Windows): `run_bluep_windows.bat` or `python -m bluep.bluep_windows`
- Run all tests: `pytest`
- Run single test: `pytest tests/test_file.py::test_function_name`
- Test with coverage: `pytest --cov=bluep tests/`
- Type checking: `mypy bluep/`
- Build package: `python -m build`
- Install development mode: `pip install -e .`

### Setup and Installation
- Initial setup: `python setup.py` (creates `.venv`, installs deps, generates SSL certs)
- Windows setup (Admin PowerShell): `PowerShell.exe -ExecutionPolicy Bypass -File windows_setup.ps1`
- Install as service (Linux): `sudo python install_service.py`
- Install as service (Windows): Run `windows_setup.ps1` as Administrator

### Utility Scripts
- Sync versions: `python version_sync.py` (syncs between `__init__.py` and `pyproject.toml`)
- Debug dump: `python dump_all.py` (creates `all.txt` with all tracked files)
- Set TOTP manually: `python set_totp_key.py` (for development/testing)

## Architecture and Key Components

### Core Modules
- **bluep.py**: Main FastAPI application with route handlers and server initialization
- **bluep_windows.py**: Windows-specific implementation with enhanced compatibility
- **auth.py**: TOTP authentication system with QR code generation and verification
- **websocket_manager.py**: Manages WebSocket connections and text synchronization
- **secure_config.py**: Machine-specific encryption for storing TOTP secrets
- **middleware.py**: Security middleware for rate limiting and request validation
- **session_manager.py**: Secure session handling with replay attack prevention
- **models.py**: Pydantic models for request/response validation
- **process_manager.py**: Terminal process management for running CLI tools in the browser
- **cert_generator.py**: SSL certificate generation with platform-specific handling

### Security Architecture
- TOTP authentication with one-time setup at `/setup` (locks after initial configuration)
- Machine-bound encryption for configuration storage
- TLS/SSL encryption for all connections (self-signed certs, 4096-bit RSA)
- Rate limiting on authentication attempts (10 per minute)
- Session tokens with replay attack prevention
- WebSocket authentication using session tokens
- Service runs with reduced privileges (systemd hardening on Linux, limited user on Windows)

### WebSocket Protocol
Messages use JSON with structure: `{"type": "message_type", "data": {...}}`
- Client → Server: text updates, cursor positions, authentication, process commands
- Server → Client: synchronized text, user list updates, error messages, process output

### Terminal Feature
- Access at `/terminal` route with full terminal emulation (xterm.js)
- Supports spawning bash, python, node, and other CLI processes
- Real-time stdio streaming over WebSocket with base64 encoding
- Security: command whitelisting, resource limits, forbidden patterns
- Process management: spawn, input, output, resize (PTY), terminate
- File transfer support via WebSocket protocol
- Platform-specific shell handling (cmd/PowerShell on Windows, bash on Linux)

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
- Virtual environment: `.venv/Scripts` (Windows) vs `.venv/bin` (Linux)
- SSL generation: OpenSSL command (Linux) vs manual generation (Windows)
- Default shell: bash (Linux/macOS) vs cmd.exe (Windows)

## Development Workflow
1. Any changes to authentication must include security tests
2. WebSocket changes require testing with multiple concurrent clients
3. Configuration changes must preserve backward compatibility
4. Always run mypy before committing type-related changes
5. Test on both Linux and Windows when modifying platform-specific code
6. Run `version_sync.py` before releases to ensure version consistency
7. Use test fixtures from `conftest.py` for consistent test setup
8. Check service logs: `journalctl -u bluep` (Linux) or Event Viewer (Windows)

## Testing Infrastructure
- Test fixtures: `app`, `client`, `auth`, `mock_request`, `mock_response`
- Async test support with auto-configured event loop
- Integration tests use `httpx.AsyncClient` for WebSocket testing
- Security tests verify TOTP, rate limiting, and session management

## Frontend Components
- **static/js/crypto-utils.js**: Client-side encryption utilities
- **static/js/lib/**: Third-party libraries (xterm.js for terminal)
- **templates/**: Jinja2 templates for login, editor, terminal, and setup pages
- WebSocket client code embedded in templates for real-time features