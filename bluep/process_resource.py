"""Process resource management with guaranteed cleanup."""

import asyncio
import logging
import os
from typing import Optional, Any, Dict
from contextlib import AsyncExitStack
import weakref

from .terminal_state import TerminalState, TerminalStateMachine
from .structured_logging import get_structured_logger, log_event, LogEvent

logger = get_structured_logger(__name__)


class ProcessResource:
    """Context manager for process resources with guaranteed cleanup."""
    
    # Class-level tracking of all active resources for emergency cleanup
    _active_resources: weakref.WeakSet = weakref.WeakSet()
    
    def __init__(self, process_id: str, session_id: str):
        self.process_id = process_id
        self.session_id = session_id
        self.process: Optional[asyncio.subprocess.Process] = None
        self.master_fd: Optional[int] = None
        self.slave_fd: Optional[int] = None
        self.state_machine: Optional[TerminalStateMachine] = None
        self.cleanup_done = False
        self._exit_stack = AsyncExitStack()
        
        # Track this resource
        ProcessResource._active_resources.add(self)
    
    async def __aenter__(self):
        """Enter the context and return self."""
        await self._exit_stack.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit the context and ensure cleanup."""
        try:
            await self.cleanup()
        finally:
            await self._exit_stack.__aexit__(exc_type, exc_val, exc_tb)
            # Remove from active resources
            ProcessResource._active_resources.discard(self)
    
    async def cleanup(self):
        """Perform cleanup of all resources."""
        if self.cleanup_done:
            return
        
        self.cleanup_done = True
        
        # Log cleanup start
        log_event(logger, LogEvent.PROCESS_TERMINATE_START,
                 f"Starting resource cleanup for process {self.process_id}",
                 process_id=self.process_id,
                 session_id=self.session_id)
        
        cleanup_errors = []
        
        # 1. Terminate the process if it exists
        if self.process and self.process.returncode is None:
            try:
                self.process.terminate()
                try:
                    await asyncio.wait_for(self.process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    logger.warning(f"Process {self.process_id} did not terminate, killing it")
                    self.process.kill()
                    await self.process.wait()
            except Exception as e:
                cleanup_errors.append(f"process termination: {e}")
                logger.error(f"Error terminating process {self.process_id}: {e}")
        
        # 2. Close file descriptors
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
                self.master_fd = None
            except OSError as e:
                if e.errno != 9:  # Ignore "Bad file descriptor"
                    cleanup_errors.append(f"master_fd close: {e}")
        
        if self.slave_fd is not None:
            try:
                os.close(self.slave_fd)
                self.slave_fd = None
            except OSError as e:
                if e.errno != 9:  # Ignore "Bad file descriptor"
                    cleanup_errors.append(f"slave_fd close: {e}")
        
        # 3. Update state machine
        if self.state_machine:
            try:
                current_state = self.state_machine.get_state()
                if current_state not in (TerminalState.TERMINATED, TerminalState.ERROR):
                    await self.state_machine.transition_to(TerminalState.TERMINATED, {
                        "reason": "resource_cleanup",
                        "cleanup_errors": cleanup_errors
                    })
            except Exception as e:
                cleanup_errors.append(f"state transition: {e}")
        
        # Log cleanup completion
        if cleanup_errors:
            log_event(logger, LogEvent.PROCESS_TERMINATE_ERROR,
                     f"Resource cleanup completed with errors for process {self.process_id}",
                     level=logging.WARNING,
                     process_id=self.process_id,
                     cleanup_errors=cleanup_errors)
        else:
            log_event(logger, LogEvent.PROCESS_TERMINATE_SUCCESS,
                     f"Resource cleanup completed successfully for process {self.process_id}",
                     process_id=self.process_id)
    
    def add_cleanup_callback(self, callback):
        """Add a cleanup callback to be called on exit."""
        self._exit_stack.callback(callback)
    
    def add_async_cleanup_callback(self, async_callback):
        """Add an async cleanup callback to be called on exit."""
        self._exit_stack.push_async_callback(async_callback)
    
    @classmethod
    async def cleanup_all_resources(cls):
        """Emergency cleanup of all active resources."""
        logger.warning("Performing emergency cleanup of all process resources")
        
        # Copy the set to avoid modification during iteration
        resources = list(cls._active_resources)
        
        cleanup_tasks = []
        for resource in resources:
            if not resource.cleanup_done:
                cleanup_tasks.append(resource.cleanup())
        
        if cleanup_tasks:
            results = await asyncio.gather(*cleanup_tasks, return_exceptions=True)
            
            errors = [r for r in results if isinstance(r, Exception)]
            if errors:
                logger.error(f"Emergency cleanup completed with {len(errors)} errors")
            else:
                logger.info(f"Emergency cleanup completed successfully for {len(cleanup_tasks)} resources")


class ProcessResourceManager:
    """Manager for process resources with lifecycle tracking."""
    
    def __init__(self):
        self.resources: Dict[str, ProcessResource] = {}
        self._lock = asyncio.Lock()
    
    async def create_resource(self, process_id: str, session_id: str) -> ProcessResource:
        """Create a new process resource."""
        async with self._lock:
            if process_id in self.resources:
                raise ValueError(f"Resource already exists for process {process_id}")
            
            resource = ProcessResource(process_id, session_id)
            self.resources[process_id] = resource
            
            # Add cleanup callback to remove from tracking
            resource.add_async_cleanup_callback(
                lambda: self._remove_resource(process_id)
            )
            
            return resource
    
    async def _remove_resource(self, process_id: str):
        """Remove a resource from tracking."""
        async with self._lock:
            self.resources.pop(process_id, None)
    
    async def get_resource(self, process_id: str) -> Optional[ProcessResource]:
        """Get a process resource by ID."""
        async with self._lock:
            return self.resources.get(process_id)
    
    async def cleanup_session_resources(self, session_id: str):
        """Clean up all resources for a session."""
        async with self._lock:
            session_resources = [
                r for r in self.resources.values() 
                if r.session_id == session_id
            ]
        
        cleanup_tasks = []
        for resource in session_resources:
            if not resource.cleanup_done:
                cleanup_tasks.append(resource.cleanup())
        
        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)
    
    async def cleanup_all(self):
        """Clean up all managed resources."""
        async with self._lock:
            all_resources = list(self.resources.values())
        
        cleanup_tasks = []
        for resource in all_resources:
            if not resource.cleanup_done:
                cleanup_tasks.append(resource.cleanup())
        
        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)