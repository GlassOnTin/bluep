import pytest
from fastapi import Response
from fastapi.testclient import TestClient
from bluep.bluep import BlueApp
from bluep.auth import TOTPAuth

@pytest.fixture
def app():
    """Create a test instance of the BlueApp application."""
    blue_app = BlueApp()
    return blue_app.app

@pytest.fixture
def client(app):
    """Create a test client using the test application instance."""
    return TestClient(app)

@pytest.fixture
def auth():
    """Create a test instance of TOTPAuth."""
    return TOTPAuth()

@pytest.fixture(autouse=True)
def configure_asyncio_event_loop_scope(request):
    """Configure event loop scope for async tests."""
    request.config.option.asyncio_default_fixture_loop_scope = "function"

@pytest.fixture
def mock_request():
    """Create a mock request for testing."""
    class MockRequest:
        client = type('Client', (), {'host': '127.0.0.1'})()
        cookies = {}

        def __init__(self):
            self.scope = {
                "type": "http",
                "headers": []
            }
    return MockRequest()

@pytest.fixture
def mock_response():
    """Create a mock response for testing."""
    return Response()
