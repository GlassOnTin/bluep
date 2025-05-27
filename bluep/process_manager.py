"""Process management module for connecting CLI processes to the browser editor."""

import asyncio
import fcntl
import logging
import os
import pty
import resource
import shlex
import signal
import struct
import subprocess
import sys
import termios
import time
from dataclasses import dataclass
from typing import Dict, Optional, Set, Callable, Any, List
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class ProcessInfo:
    """Information about a managed process."""
    
    process_id: str
    command: str
    process: Optional[asyncio.subprocess.Process] = None
    master_fd: Optional[int] = None
    stdin_reader: Optional[asyncio.StreamReader] = None
    stdout_writer: Optional[asyncio.StreamWriter] = None
    created_at: float = 0
    session_id: Optional[str] = None
    is_alive: bool = True


class ProcessManager:
    """Manages subprocess lifecycle and stdio connections for browser terminal."""
    
    def __init__(self) -> None:
        self.processes: Dict[str, ProcessInfo] = {}
        self.session_processes: Dict[str, Set[str]] = {}  # session_id -> process_ids
        self._lock = asyncio.Lock()
        self.max_processes_per_session = 5
        self.allowed_commands = {
            "bash", "sh", "python", "python3", "node", "claude", 
            "ipython", "irb", "sqlite3", "psql", "mysql"
        }
        # Additional security: forbidden command patterns
        self.forbidden_patterns = [
            "sudo", "su", "chmod", "chown", "rm -rf", "dd", 
            "mkfs", "fdisk", "systemctl", "service", "killall",
            "pkill", "reboot", "shutdown", "halt", "poweroff"
        ]
        
    async def spawn_process(
        self,
        command: str,
        session_id: str,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None
    ) -> Optional[str]:
        """Spawn a new process with PTY support for proper terminal behavior."""
        async with self._lock:
            # Check session process limit
            session_procs = self.session_processes.get(session_id, set())
            if len(session_procs) >= self.max_processes_per_session:
                logger.warning(f"Session {session_id} reached process limit")
                return None
                
            # Validate command
            cmd_parts = shlex.split(command)
            if not cmd_parts:
                return None
                
            base_command = os.path.basename(cmd_parts[0])
            if base_command not in self.allowed_commands:
                logger.warning(f"Command not allowed: {base_command}")
                return None
                
            # Check for forbidden patterns
            command_lower = command.lower()
            for pattern in self.forbidden_patterns:
                if pattern in command_lower:
                    logger.warning(f"Forbidden pattern detected: {pattern}")
                    return None
                    
            # Additional security: limit command arguments
            if len(cmd_parts) > 10:  # Arbitrary limit
                logger.warning("Too many command arguments")
                return None
                
            # Check for suspicious characters that might indicate command injection
            suspicious_chars = ['$', '`', '\\', '&&', '||', ';', '|', '>', '<', '&']
            for char in suspicious_chars:
                if char in command and base_command not in ['bash', 'sh']:
                    logger.warning(f"Suspicious character detected: {char}")
                    return None
                
            process_id = str(uuid4())
            
            try:
                # Create PTY for terminal emulation
                master_fd, slave_fd = pty.openpty()
                
                # Set terminal size (80x24 is standard)
                winsize = struct.pack('HHHH', 24, 80, 0, 0)
                fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)
                
                # Prepare environment with security restrictions
                process_env = {
                    # Only include safe environment variables
                    'PATH': '/usr/local/bin:/usr/bin:/bin',
                    'HOME': os.path.expanduser('~'),
                    'USER': os.environ.get('USER', 'user'),
                    'LANG': os.environ.get('LANG', 'en_US.UTF-8'),
                    'TERM': 'xterm-256color',
                    'COLORTERM': 'truecolor',
                    'PYTHONUNBUFFERED': '1',  # For Python processes
                }
                
                # Add custom env if provided, but sanitize
                if env:
                    for key, value in env.items():
                        # Only allow alphanumeric keys and certain safe values
                        if key.isalnum() and isinstance(value, str) and len(value) < 1000:
                            process_env[key] = value
                
                # Define resource limits
                def set_limits():
                    # Create new session
                    os.setsid()
                    
                    # Set resource limits
                    # CPU time limit (30 minutes)
                    resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))
                    
                    # Memory limit (512MB)
                    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
                    
                    # File size limit (100MB)
                    resource.setrlimit(resource.RLIMIT_FSIZE, (100 * 1024 * 1024, 100 * 1024 * 1024))
                    
                    # Process count limit
                    resource.setrlimit(resource.RLIMIT_NPROC, (50, 50))
                    
                    # Open file descriptors limit
                    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
                
                # Start process with PTY and resource limits
                process = await asyncio.create_subprocess_exec(
                    *cmd_parts,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    env=process_env,
                    cwd=cwd,
                    preexec_fn=set_limits
                )
                
                # Close slave FD in parent
                os.close(slave_fd)
                
                # Make master FD non-blocking
                flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
                fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                
                # Create process info
                info = ProcessInfo(
                    process_id=process_id,
                    command=command,
                    process=process,
                    master_fd=master_fd,
                    created_at=time.time(),
                    session_id=session_id
                )
                
                self.processes[process_id] = info
                
                # Track session processes
                if session_id not in self.session_processes:
                    self.session_processes[session_id] = set()
                self.session_processes[session_id].add(process_id)
                
                # Security audit log
                logger.info(f"Process spawned - ID: {process_id}, Command: {command}, Session: {session_id}, Time: {time.time()}")
                return process_id
                
            except Exception as e:
                logger.error(f"Failed to spawn process: {e}")
                if 'master_fd' in locals() and master_fd is not None:
                    os.close(master_fd)
                return None
                
    async def write_to_process(self, process_id: str, data: str) -> bool:
        """Write data to a process's stdin."""
        async with self._lock:
            info = self.processes.get(process_id)
            if not info or not info.is_alive or info.master_fd is None:
                return False
                
            try:
                # Write to PTY master
                os.write(info.master_fd, data.encode('utf-8'))
                return True
            except Exception as e:
                logger.error(f"Failed to write to process {process_id}: {e}")
                return False
                
    async def read_from_process(self, process_id: str, max_bytes: int = 4096) -> Optional[bytes]:
        """Read available output from a process."""
        async with self._lock:
            info = self.processes.get(process_id)
            if not info or info.master_fd is None:
                return None
                
            try:
                # Non-blocking read from PTY master
                data = os.read(info.master_fd, max_bytes)
                return data if data else None
            except BlockingIOError:
                # No data available
                return None
            except Exception as e:
                logger.error(f"Failed to read from process {process_id}: {e}")
                info.is_alive = False
                return None
                
    async def resize_terminal(self, process_id: str, cols: int, rows: int) -> bool:
        """Resize the terminal for a process."""
        async with self._lock:
            info = self.processes.get(process_id)
            if not info or not info.is_alive or info.master_fd is None:
                return False
                
            try:
                # Pack terminal size
                winsize = struct.pack('HHHH', rows, cols, 0, 0)
                fcntl.ioctl(info.master_fd, termios.TIOCSWINSZ, winsize)
                
                # Send SIGWINCH to notify process of resize
                if info.process and info.process.pid:
                    os.kill(info.process.pid, signal.SIGWINCH)
                    
                return True
            except Exception as e:
                logger.error(f"Failed to resize terminal for {process_id}: {e}")
                return False
                
    async def terminate_process(self, process_id: str, force: bool = False) -> bool:
        """Terminate a process."""
        async with self._lock:
            info = self.processes.get(process_id)
            if not info:
                return False
                
            try:
                if info.process and info.process.returncode is None:
                    if force:
                        info.process.kill()
                    else:
                        info.process.terminate()
                    await info.process.wait()
                    
                if info.master_fd is not None:
                    os.close(info.master_fd)
                    info.master_fd = None
                    
                info.is_alive = False
                
                # Remove from session tracking
                if info.session_id and info.session_id in self.session_processes:
                    self.session_processes[info.session_id].discard(process_id)
                    
                # Security audit log
                logger.info(f"Process terminated - ID: {process_id}, Force: {force}, Session: {info.session_id}, Time: {time.time()}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to terminate process {process_id}: {e}")
                return False
                
    async def cleanup_session_processes(self, session_id: str) -> None:
        """Clean up all processes for a session."""
        async with self._lock:
            process_ids = list(self.session_processes.get(session_id, []))
            
        for process_id in process_ids:
            await self.terminate_process(process_id)
            
    async def monitor_processes(self) -> None:
        """Monitor and clean up dead processes."""
        while True:
            try:
                await asyncio.sleep(5)  # Check every 5 seconds
                
                async with self._lock:
                    dead_processes = []
                    
                    for process_id, info in self.processes.items():
                        if info.process and info.process.returncode is not None:
                            info.is_alive = False
                            dead_processes.append(process_id)
                            
                    # Clean up dead processes
                    for process_id in dead_processes:
                        await self.terminate_process(process_id)
                        del self.processes[process_id]
                        
            except Exception as e:
                logger.error(f"Error in process monitor: {e}")
                
    def get_process_info(self, process_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a process."""
        info = self.processes.get(process_id)
        if not info:
            return None
            
        return {
            "process_id": info.process_id,
            "command": info.command,
            "created_at": info.created_at,
            "is_alive": info.is_alive,
            "session_id": info.session_id
        }
        
    def get_session_processes(self, session_id: str) -> List[Dict[str, Any]]:
        """Get all processes for a session."""
        process_ids = self.session_processes.get(session_id, set())
        result = []
        for pid in process_ids:
            info = self.get_process_info(pid)
            if info:
                result.append(info)
        return result