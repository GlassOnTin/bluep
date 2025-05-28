"""Process management module for connecting CLI processes to the browser editor."""

import asyncio
import errno
import fcntl
import logging
import os
import pty
import queue
import resource
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Set, Any, List
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
    reader_thread: Optional[threading.Thread] = None
    output_queue: Optional[queue.Queue] = None
    is_nodejs: bool = False


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
            "pkill", "reboot", "shutdown", "halt", "poweroff",
            "nc", "netcat", "nmap", "wget", "curl", "ssh",
            "/etc/passwd", "/etc/shadow", "~/.ssh", ".bash_history"
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
                
            # Validate command - CRITICAL: Prevent command injection
            try:
                cmd_parts = shlex.split(command)
            except ValueError as e:
                logger.warning(f"Invalid command syntax: {e}")
                return None
                
            if not cmd_parts:
                return None
                
            # Extract base command and resolve it
            base_command = os.path.basename(cmd_parts[0])
            
            # CRITICAL: Only allow whitelisted commands
            if base_command not in self.allowed_commands:
                logger.warning(f"Command not allowed: {base_command}")
                return None
            
            # CRITICAL: For shell commands, use restricted mode and validate all arguments
            if base_command in ['bash', 'sh']:
                # Force restricted shell mode
                if base_command == 'bash':
                    cmd_parts = ['bash', '--restricted', '--noprofile', '--norc']
                else:
                    cmd_parts = ['sh', '-r']
                    
                # If user provided arguments to shell, reject them
                if len(shlex.split(command)) > 1:
                    logger.warning("Shell commands cannot have arguments")
                    return None
            elif base_command in ['node', 'claude']:
                # Node.js and claude need interactive mode for REPL to work properly with PTY
                if base_command == 'node':
                    cmd_parts = ['node', '-i']
                else:
                    # claude might have its own interactive flag or work without it
                    cmd_parts = ['claude']
                # Don't allow additional arguments
                if len(shlex.split(command)) > 1:
                    logger.warning(f"{base_command} commands cannot have arguments")
                    return None
            else:
                # For non-shell commands, validate each argument
                for arg in cmd_parts[1:]:
                    # Reject arguments that look like command substitution or expansion
                    if any(char in arg for char in ['$', '`', '$(', '${', '\\']):
                        logger.warning(f"Suspicious argument detected: {arg}")
                        return None
                    
                    # Reject arguments that start with - followed by suspicious content
                    if arg.startswith('-') and any(c in arg for c in ['=', ';', '|', '&']):
                        logger.warning(f"Suspicious option detected: {arg}")
                        return None
                
            # Check for forbidden patterns in the original command
            command_lower = command.lower()
            for pattern in self.forbidden_patterns:
                if pattern in command_lower:
                    logger.warning(f"Forbidden pattern detected: {pattern}")
                    return None
                    
            # Limit command arguments
            if len(cmd_parts) > 10:
                logger.warning("Too many command arguments")
                return None
                
            process_id = str(uuid4())
            master_fd = None
            slave_fd = None
            
            try:
                # Create PTY for terminal emulation
                master_fd, slave_fd = pty.openpty()
                
                # Set master_fd to non-blocking mode
                flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
                fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                
                # Set terminal size (80x24 is standard)
                winsize = struct.pack('HHHH', 24, 80, 0, 0)
                fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)
                
                # Prepare environment - start with current environment
                # This ensures we get the same PATH and other vars as the service user
                process_env = os.environ.copy()
                
                # Override/ensure critical terminal variables
                process_env.update({
                    'TERM': 'xterm-256color',
                    'COLORTERM': 'truecolor',
                    'PYTHONUNBUFFERED': '1',  # For Python processes
                    'NODE_NO_READLINE': '1',  # Force Node.js to not use readline (we handle that)
                })
                
                # Remove potentially sensitive or problematic variables
                sensitive_vars = ['SUDO_ASKPASS', 'SSH_AUTH_SOCK', 'GPG_AGENT_INFO']
                for var in sensitive_vars:
                    process_env.pop(var, None)
                    
                # For Node.js, set memory options to prevent OOM
                if base_command == 'node':
                    process_env['NODE_OPTIONS'] = '--max-old-space-size=256'
                elif base_command == 'claude':
                    # claude needs more memory for WebAssembly
                    process_env['NODE_OPTIONS'] = '--max-old-space-size=512'
                else:
                    # Remove NODE_OPTIONS for non-node processes
                    process_env.pop('NODE_OPTIONS', None)
                
                # Add custom env if provided, but sanitize
                if env:
                    for key, value in env.items():
                        # Only allow alphanumeric keys and certain safe values
                        if key.isalnum() and isinstance(value, str) and len(value) < 1000:
                            process_env[key] = value
                
                # Determine memory limit based on command
                memory_limit = 512 * 1024 * 1024  # Default 512MB
                skip_memory_limit = False
                if base_command == 'node':
                    memory_limit = 1024 * 1024 * 1024  # 1GB for Node.js
                elif base_command == 'claude':
                    # Skip memory limit for claude due to WebAssembly requirements
                    skip_memory_limit = True
                
                # Define resource limits
                def set_limits():
                    try:
                        # Create new session
                        os.setsid()
                    except Exception:
                        pass  # May fail in some contexts
                    
                    # Set resource limits with error handling
                    # Some limits may fail due to systemd restrictions
                    try:
                        # CPU time limit (30 minutes)
                        resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))
                    except Exception:
                        pass
                    
                    if not skip_memory_limit:
                        try:
                            # Memory limit - using pre-calculated value
                            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
                        except Exception:
                            pass
                    
                    try:
                        # File size limit (100MB)
                        resource.setrlimit(resource.RLIMIT_FSIZE, (100 * 1024 * 1024, 100 * 1024 * 1024))
                    except Exception:
                        pass
                    
                    # Skip NPROC limit - causes issues with systemd and forking
                    # The systemd service already has appropriate limits
                    
                    try:
                        # Open file descriptors limit
                        _, current_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                        new_limit = min(256, current_hard)  # Don't exceed hard limit
                        resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, new_limit))
                    except Exception:
                        pass
                
                # For Node.js, try to use unbuffer to prevent PTY corruption issues
                if base_command == 'node' and shutil.which('unbuffer'):
                    logger.info("Using unbuffer for Node.js to prevent PTY issues")
                    cmd_parts = ['unbuffer', '-p'] + cmd_parts
                    
                # Start process with PTY and resource limits
                # CRITICAL: Use exec to prevent shell interpretation
                process = await asyncio.create_subprocess_exec(
                    cmd_parts[0],  # Command must be absolute path or in PATH
                    *cmd_parts[1:],  # Arguments passed separately
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    env=process_env,
                    cwd=cwd,
                    preexec_fn=set_limits,
                    # Never use shell=True
                    start_new_session=True
                )
                
                # Close slave FD in parent
                os.close(slave_fd)
                slave_fd = None  # Mark as closed
                
                # Make master FD non-blocking
                flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
                fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                
                # Check if this is a Node.js process
                is_nodejs = base_command == 'node' or 'node' in cmd_parts
                
                # Create process info
                info = ProcessInfo(
                    process_id=process_id,
                    command=command,
                    process=process,
                    master_fd=master_fd,
                    created_at=time.time(),
                    session_id=session_id,
                    is_nodejs=is_nodejs
                )
                
                # For Node.js, use a separate reader thread to isolate PTY handling
                if is_nodejs:
                    info.output_queue = queue.Queue(maxsize=1000)
                    info.reader_thread = threading.Thread(
                        target=self._nodejs_reader_thread,
                        args=(master_fd, info.output_queue, process_id),
                        daemon=True
                    )
                    info.reader_thread.start()
                    logger.info(f"Started isolated reader thread for Node.js process {process_id}")
                
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
                # Clean up file descriptors
                if master_fd is not None:
                    try:
                        os.close(master_fd)
                    except OSError:
                        pass
                if slave_fd is not None:
                    try:
                        os.close(slave_fd)
                    except OSError:
                        pass
                return None
                
    async def write_to_process(self, process_id: str, data: str) -> bool:
        """Write data to a process's stdin."""
        # Get the file descriptor without holding the lock for long
        async with self._lock:
            info = self.processes.get(process_id)
            if not info or not info.is_alive or info.master_fd is None:
                return False
            master_fd = info.master_fd
                
        # Do the actual write outside the lock to prevent blocking other processes
        try:
            # Write to PTY master
            bytes_to_write = data.encode('utf-8')
            logger.debug(f"Writing {len(bytes_to_write)} bytes to process {process_id} (fd={master_fd})")
            bytes_written = os.write(master_fd, bytes_to_write)
            logger.debug(f"Wrote {bytes_written} bytes to process {process_id}")
            return True
        except OSError as e:
            # File descriptor was closed or became invalid
            if e.errno in (errno.EBADF, errno.EIO):  # Bad file descriptor or I/O error
                # Mark process as dead
                async with self._lock:
                    info = self.processes.get(process_id)
                    if info:
                        info.is_alive = False
                logger.debug(f"Process {process_id} file descriptor is invalid")
                return False
            else:
                logger.error(f"Failed to write to process {process_id}: {e}", exc_info=True)
                return False
        except Exception as e:
            logger.error(f"Failed to write to process {process_id}: {e}", exc_info=True)
            return False
                
    async def read_from_process(self, process_id: str, max_bytes: int = 4096) -> Optional[bytes]:
        """Read available output from a process."""
        # Get the process info
        async with self._lock:
            info = self.processes.get(process_id)
            if not info:
                logger.debug(f"No info for process {process_id}")
                return None
            
            # For Node.js processes, read from the queue instead
            if info.is_nodejs and info.output_queue:
                try:
                    # Non-blocking read from queue
                    data = info.output_queue.get_nowait()
                    if data and logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Read {len(data)} bytes from queue for Node.js process {process_id}")
                    return data
                except queue.Empty:
                    return None
            
            # For non-Node.js processes, use the original method
            if not info.master_fd:
                logger.debug(f"No master_fd for process {process_id}")
                return None
            master_fd = info.master_fd
            is_alive = info.is_alive
            
        if not is_alive:
            logger.debug(f"Process {process_id} is not alive, skipping read")
            return None
            
        # Do the actual read outside the lock to prevent blocking other processes
        try:
            # Non-blocking read from PTY master
            data = os.read(master_fd, max_bytes)
            if data and logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Read {len(data)} bytes from fd {master_fd} for process {process_id}")
            return data if data else None
        except BlockingIOError:
            # No data available
            return None
        except OSError as e:
            # File descriptor was closed or became invalid
            if e.errno in (errno.EBADF, errno.EIO):  # Bad file descriptor or I/O error
                # Mark process as dead
                async with self._lock:
                    info = self.processes.get(process_id)
                    if info:
                        info.is_alive = False
                return None
            else:
                logger.error(f"Failed to read from process {process_id}: {e}")
                return None
        except Exception as e:
            logger.error(f"Failed to read from process {process_id}: {e}")
            async with self._lock:
                info = self.processes.get(process_id)
                if info:
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
        # Get process info and mark as not alive immediately
        async with self._lock:
            info = self.processes.get(process_id)
            if not info:
                return False
            
            # Mark as not alive immediately to stop read attempts
            info.is_alive = False
            process = info.process
            master_fd = info.master_fd
            session_id = info.session_id
            reader_thread = info.reader_thread
            
            # Clear the master_fd reference to prevent reads
            info.master_fd = None
                
        # Do the actual termination outside the lock to prevent blocking
        try:
            if process and process.returncode is None:
                if force:
                    process.kill()
                else:
                    process.terminate()
                    
                # Wait for process with timeout
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    logger.warning(f"Process {process_id} did not terminate, killing it")
                    process.kill()
                    await process.wait()
                    
            # Close the file descriptor if it exists
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except OSError as e:
                    # File descriptor might already be closed
                    logger.debug(f"Error closing master_fd for {process_id}: {e}")
                    
            # Wait for reader thread to exit (for Node.js)
            if reader_thread and reader_thread.is_alive():
                logger.debug(f"Waiting for reader thread to exit for process {process_id}")
                reader_thread.join(timeout=2.0)
                if reader_thread.is_alive():
                    logger.warning(f"Reader thread did not exit cleanly for process {process_id}")
                    
            # Remove from session tracking
            async with self._lock:
                if session_id and session_id in self.session_processes:
                    self.session_processes[session_id].discard(process_id)
                    
            # Security audit log
            logger.info(f"Process terminated - ID: {process_id}, Force: {force}, Session: {session_id}, Time: {time.time()}")
            return True
                
        except Exception as e:
            logger.error(f"Failed to terminate process {process_id}: {e}", exc_info=True)
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
        
    def _nodejs_reader_thread(self, master_fd: int, output_queue: queue.Queue, process_id: str) -> None:
        """Dedicated reader thread for Node.js processes to isolate PTY handling."""
        logger.info(f"Node.js reader thread started for process {process_id}")
        
        while True:
            try:
                # Wait for data to be available using select
                readable, _, _ = select.select([master_fd], [], [], 0.1)
                
                if not readable:
                    # No data available yet, continue waiting
                    continue
                    
                # Now read the available data
                data = os.read(master_fd, 4096)
                if not data:
                    logger.info(f"Node.js reader thread: EOF for process {process_id}")
                    break
                    
                # Put data in queue (non-blocking)
                try:
                    output_queue.put_nowait(data)
                except queue.Full:
                    # Drop oldest data if queue is full
                    try:
                        output_queue.get_nowait()
                        output_queue.put_nowait(data)
                    except queue.Empty:
                        pass
                        
            except OSError as e:
                if e.errno == errno.EBADF:
                    logger.info(f"Node.js reader thread: FD closed for process {process_id}")
                elif e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
                    # Non-blocking read would block, continue
                    continue
                else:
                    logger.error(f"Node.js reader thread error for process {process_id}: {e}")
                break
            except Exception as e:
                logger.error(f"Node.js reader thread unexpected error for process {process_id}: {e}")
                break
                
        logger.info(f"Node.js reader thread exiting for process {process_id}")