# BLUEP Development Guide

## Build and Test Commands
- Run server: `python -m bluep.bluep`
- Run all tests: `pytest`
- Run single test: `pytest tests/test_file.py::test_function_name`
- Test with coverage: `pytest --cov=bluep tests/`
- Type checking: `mypy bluep/`
- Build package: `python -m build`

## Code Style Guidelines
- **Type Annotations**: Use strict typing with explicit return types (including `-> None`)
- **Imports**: Standard lib first, third-party next, local imports last (alphabetized within groups)
- **Naming**: Classes in PascalCase, functions/variables in snake_case, private methods with leading underscore
- **Error Handling**: Use specific exceptions with detailed messages, log errors before raising
- **Documentation**: Every module and function needs docstrings in Google style format
- **Security**: Validate TLS certificates, use TOTP authentication, implement rate limiting
- **Testing**: Create pytest fixtures, mock external dependencies, test security features thoroughly

This file serves as guidance for agentic coding assistants working in this repository.