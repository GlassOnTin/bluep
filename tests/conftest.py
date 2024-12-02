import pytest
from fastapi.testclient import TestClient
from bluep.bluep import create_app
from bluep.auth import TOTPAuth


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def auth():
    return TOTPAuth()
