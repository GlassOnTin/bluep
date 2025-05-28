"""Tests for the process management functionality."""

import asyncio
import os
import signal
import pytest
from unittest.mock import Mock, patch, AsyncMock

from bluep.process_manager import ProcessManager, ProcessInfo


@pytest.fixture
def process_manager():
    """Create a ProcessManager instance for testing."""
    return ProcessManager()


@pytest.mark.asyncio
async def test_spawn_allowed_process(process_manager):
    """Test spawning an allowed process."""
    session_id = "test-session-123"
    
    # Mock the subprocess creation
    with patch('asyncio.create_subprocess_exec') as mock_subprocess:
        mock_process = Mock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_subprocess.return_value = mock_process
        
        # Mock pty.openpty
        with patch('pty.openpty', return_value=(3, 4)):
            with patch('os.close'):
                with patch('fcntl.ioctl'):
                    with patch('fcntl.fcntl'):
                        process_id = await process_manager.spawn_process(
                            "python", session_id
                        )
    
    assert process_id is not None
    assert process_id in process_manager.processes
    assert session_id in process_manager.session_processes
    assert process_id in process_manager.session_processes[session_id]


@pytest.mark.asyncio
async def test_spawn_forbidden_command(process_manager):
    """Test that forbidden commands are rejected."""
    session_id = "test-session-123"
    
    # Test with a command not in allowed list
    process_id = await process_manager.spawn_process(
        "vim", session_id
    )
    assert process_id is None
    
    # Test with forbidden pattern
    process_id = await process_manager.spawn_process(
        "bash -c 'sudo rm -rf /'", session_id
    )
    assert process_id is None


@pytest.mark.asyncio
async def test_spawn_with_suspicious_characters(process_manager):
    """Test that commands with suspicious characters are rejected (except for shells)."""
    session_id = "test-session-123"
    
    # Should reject for non-shell commands
    process_id = await process_manager.spawn_process(
        "python -c 'print($USER)'", session_id
    )
    assert process_id is None
    
    # Should allow for shell commands
    with patch('asyncio.create_subprocess_exec') as mock_subprocess:
        mock_process = Mock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_subprocess.return_value = mock_process
        
        with patch('pty.openpty', return_value=(3, 4)):
            with patch('os.close'):
                with patch('fcntl.ioctl'):
                    with patch('fcntl.fcntl'):
                        process_id = await process_manager.spawn_process(
                            "bash", session_id
                        )
    
    assert process_id is not None


@pytest.mark.asyncio
async def test_process_limit_per_session(process_manager):
    """Test that session process limits are enforced."""
    session_id = "test-session-123"
    
    # Mock successful process creation
    with patch('asyncio.create_subprocess_exec') as mock_subprocess:
        mock_process = Mock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_subprocess.return_value = mock_process
        
        with patch('pty.openpty', return_value=(3, 4)):
            with patch('os.close'):
                with patch('fcntl.ioctl'):
                    with patch('fcntl.fcntl'):
                        # Spawn up to the limit
                        for i in range(process_manager.max_processes_per_session):
                            process_id = await process_manager.spawn_process(
                                "python", session_id
                            )
                            assert process_id is not None
                        
                        # Try to spawn one more - should fail
                        process_id = await process_manager.spawn_process(
                            "python", session_id
                        )
                        assert process_id is None


@pytest.mark.asyncio
async def test_write_to_process(process_manager):
    """Test writing data to a process."""
    session_id = "test-session-123"
    
    # Create a mock process
    with patch('asyncio.create_subprocess_exec') as mock_subprocess:
        mock_process = Mock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_subprocess.return_value = mock_process
        
        with patch('pty.openpty', return_value=(3, 4)):
            with patch('os.close'):
                with patch('fcntl.ioctl'):
                    with patch('fcntl.fcntl'):
                        process_id = await process_manager.spawn_process(
                            "python", session_id
                        )
    
    # Test writing to the process
    with patch('os.write') as mock_write:
        success = await process_manager.write_to_process(process_id, "test input\n")
        assert success
        mock_write.assert_called_once()


@pytest.mark.asyncio
async def test_read_from_process(process_manager):
    """Test reading output from a process."""
    session_id = "test-session-123"
    
    # Create a mock process
    with patch('asyncio.create_subprocess_exec') as mock_subprocess:
        mock_process = Mock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_subprocess.return_value = mock_process
        
        with patch('pty.openpty', return_value=(3, 4)):
            with patch('os.close'):
                with patch('fcntl.ioctl'):
                    with patch('fcntl.fcntl'):
                        process_id = await process_manager.spawn_process(
                            "python", session_id
                        )
    
    # Test reading from the process
    with patch('os.read', return_value=b"test output"):
        output = await process_manager.read_from_process(process_id)
        assert output == b"test output"
    
    # Test reading when no data available
    with patch('os.read', side_effect=BlockingIOError):
        output = await process_manager.read_from_process(process_id)
        assert output is None


@pytest.mark.asyncio
async def test_terminate_process(process_manager):
    """Test terminating a process."""
    session_id = "test-session-123"
    
    # Create a mock process
    mock_process = AsyncMock()
    mock_process.pid = 12345
    mock_process.returncode = None
    mock_process.terminate = Mock()
    mock_process.wait = AsyncMock()
    
    with patch('asyncio.create_subprocess_exec', return_value=mock_process):
        with patch('pty.openpty', return_value=(3, 4)):
            with patch('os.close'):
                with patch('fcntl.ioctl'):
                    with patch('fcntl.fcntl'):
                        process_id = await process_manager.spawn_process(
                            "python", session_id
                        )
    
    # Terminate the process
    success = await process_manager.terminate_process(process_id)
    assert success
    mock_process.terminate.assert_called_once()
    mock_process.wait.assert_called_once()
    
    # Process should be marked as not alive
    process_info = process_manager.get_process_info(process_id)
    assert process_info is not None
    assert not process_info["is_alive"]


@pytest.mark.asyncio
async def test_cleanup_session_processes(process_manager):
    """Test cleaning up all processes for a session."""
    session_id = "test-session-123"
    
    # Mock the entire terminate_process method to avoid file descriptor issues
    terminated_processes = []
    
    async def mock_terminate(process_id, force=False):
        terminated_processes.append(process_id)
        if process_id in process_manager.processes:
            process_manager.processes[process_id].is_alive = False
            if session_id in process_manager.session_processes:
                process_manager.session_processes[session_id].discard(process_id)
        return True
    
    # Create processes manually to avoid file descriptor issues
    process_ids = []
    for i in range(3):
        process_id = f"test-process-{i}"
        process_info = ProcessInfo(
            process_id=process_id,
            command="python",
            created_at=0,
            session_id=session_id,
            is_alive=True
        )
        process_manager.processes[process_id] = process_info
        if session_id not in process_manager.session_processes:
            process_manager.session_processes[session_id] = set()
        process_manager.session_processes[session_id].add(process_id)
        process_ids.append(process_id)
    
    # Mock terminate_process
    with patch.object(process_manager, 'terminate_process', side_effect=mock_terminate):
        await process_manager.cleanup_session_processes(session_id)
    
    # All processes should be terminated
    assert len(terminated_processes) == 3
    for process_id in process_ids:
        assert process_id in terminated_processes
    
    # Session should have no processes
    assert session_id not in process_manager.session_processes or \
           len(process_manager.session_processes[session_id]) == 0


@pytest.mark.asyncio
async def test_resize_terminal(process_manager):
    """Test resizing terminal for a process."""
    session_id = "test-session-123"
    
    # Create a mock process
    with patch('asyncio.create_subprocess_exec') as mock_subprocess:
        mock_process = Mock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_subprocess.return_value = mock_process
        
        with patch('pty.openpty', return_value=(3, 4)):
            with patch('os.close'):
                with patch('fcntl.ioctl') as mock_ioctl:
                    with patch('fcntl.fcntl'):
                        process_id = await process_manager.spawn_process(
                            "python", session_id
                        )
    
    # Test resizing terminal
    with patch('fcntl.ioctl') as mock_ioctl:
        with patch('os.kill') as mock_kill:
            success = await process_manager.resize_terminal(process_id, 120, 40)
            assert success
            mock_ioctl.assert_called_once()
            mock_kill.assert_called_once_with(12345, signal.SIGWINCH)


@pytest.mark.asyncio
async def test_get_process_info(process_manager):
    """Test getting process information."""
    session_id = "test-session-123"
    
    # Create a mock process
    with patch('asyncio.create_subprocess_exec') as mock_subprocess:
        mock_process = Mock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_subprocess.return_value = mock_process
        
        with patch('pty.openpty', return_value=(3, 4)):
            with patch('os.close'):
                with patch('fcntl.ioctl'):
                    with patch('fcntl.fcntl'):
                        process_id = await process_manager.spawn_process(
                            "python", session_id
                        )
    
    # Get process info
    info = process_manager.get_process_info(process_id)
    assert info is not None
    assert info["process_id"] == process_id
    assert info["command"] == "python"
    assert info["session_id"] == session_id
    assert info["is_alive"] is True
    
    # Test non-existent process
    info = process_manager.get_process_info("non-existent")
    assert info is None


@pytest.mark.asyncio
async def test_resource_limits_set(process_manager):
    """Test that resource limits are set when spawning a process."""
    session_id = "test-session-123"
    preexec_fn = None
    
    # Capture the preexec_fn
    async def mock_create_subprocess_exec(*args, **kwargs):
        nonlocal preexec_fn
        preexec_fn = kwargs.get('preexec_fn')
        mock_process = Mock()
        mock_process.pid = 12345
        mock_process.returncode = None
        return mock_process
    
    with patch('asyncio.create_subprocess_exec', side_effect=mock_create_subprocess_exec):
        with patch('pty.openpty', return_value=(3, 4)):
            with patch('os.close'):
                with patch('fcntl.ioctl'):
                    with patch('fcntl.fcntl'):
                        process_id = await process_manager.spawn_process(
                            "python", session_id
                        )
    
    # Verify preexec_fn was set
    assert preexec_fn is not None
    
    # Test that the preexec_fn sets resource limits
    with patch('os.setsid'):
        with patch('resource.setrlimit') as mock_setrlimit:
            preexec_fn()
            
            # Should set 3-4 different resource limits (CPU, memory (optional), file size, nofile)
            # Memory limit is skipped for claude
            assert mock_setrlimit.call_count >= 3
            assert mock_setrlimit.call_count <= 4