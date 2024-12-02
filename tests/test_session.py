from bluep.session_manager import SessionManager
from fastapi import Response
import time


def test_session_creation():
    manager = SessionManager()
    response = Response()
    session_id = manager.create_session("test_user", response)
    assert session_id in manager.sessions
    assert manager.sessions[session_id].username == "test_user"


def test_session_expiry():
    manager = SessionManager(cookie_max_age=1)
    response = Response()
    session_id = manager.create_session("test_user", response)
    time.sleep(2)
    assert manager.get_session(session_id) is None
