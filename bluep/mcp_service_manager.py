"""MCP Service Manager for discovering and managing MCP servers."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from .process_manager import ProcessManager, ProcessInfo

logger = logging.getLogger(__name__)


class MCPServiceStatus(Enum):
    """Status of an MCP service."""
    AVAILABLE = "available"
    RUNNING = "running"
    FAILED = "failed"
    INSTALLING = "installing"


@dataclass
class MCPService:
    """Represents an MCP service."""
    name: str
    path: Path
    package_info: Dict[str, Any]
    status: MCPServiceStatus
    process_id: Optional[str] = None
    port: Optional[int] = None
    
    @property
    def entry_point(self) -> Optional[str]:
        """Get the entry point for the MCP service."""
        if "main" in self.package_info:
            return self.package_info["main"]
        if "bin" in self.package_info:
            bin_info = self.package_info["bin"]
            if isinstance(bin_info, str):
                return bin_info
            elif isinstance(bin_info, dict) and self.name in bin_info:
                return bin_info[self.name]
        return None


class MCPServiceManager:
    """Manages MCP services discovery and lifecycle."""
    
    def __init__(self, services_dir: Path, process_manager: ProcessManager):
        """Initialize MCP Service Manager.
        
        Args:
            services_dir: Directory containing MCP services
            process_manager: Process manager for spawning services
        """
        self.services_dir = services_dir
        self.process_manager = process_manager
        self.services: Dict[str, MCPService] = {}
        self._next_port = 30000  # Starting port for MCP services
        
    async def discover_services(self) -> List[MCPService]:
        """Discover available MCP services in the services directory.
        
        Returns:
            List of discovered MCP services
        """
        services = []
        
        if not self.services_dir.exists():
            logger.warning(f"MCP services directory does not exist: {self.services_dir}")
            return services
            
        for service_path in self.services_dir.iterdir():
            if not service_path.is_dir():
                continue
                
            package_json = service_path / "package.json"
            if not package_json.exists():
                continue
                
            try:
                with open(package_json, 'r') as f:
                    package_info = json.load(f)
                    
                service = MCPService(
                    name=service_path.name,
                    path=service_path,
                    package_info=package_info,
                    status=MCPServiceStatus.AVAILABLE
                )
                
                # Check if node_modules exists
                if not (service_path / "node_modules").exists():
                    service.status = MCPServiceStatus.INSTALLING
                    
                services.append(service)
                self.services[service.name] = service
                
            except Exception as e:
                logger.error(f"Failed to load service {service_path.name}: {e}")
                
        return services
        
    async def start_service(self, service_name: str, session_id: str) -> ProcessInfo:
        """Start an MCP service.
        
        Args:
            service_name: Name of the service to start
            session_id: Session ID for the process
            
        Returns:
            Process information
            
        Raises:
            ValueError: If service not found or already running
        """
        service = self.services.get(service_name)
        if not service:
            raise ValueError(f"Service {service_name} not found")
            
        if service.status == MCPServiceStatus.RUNNING:
            raise ValueError(f"Service {service_name} is already running")
            
        if service.status == MCPServiceStatus.INSTALLING:
            raise ValueError(f"Service {service_name} is still installing")
            
        # Allocate a port for the service
        service.port = self._next_port
        self._next_port += 1
        
        # Determine the command to run
        entry_point = service.entry_point
        if not entry_point:
            # Try common MCP server patterns
            if (service.path / "index.js").exists():
                entry_point = "index.js"
            elif (service.path / "server.js").exists():
                entry_point = "server.js"
            else:
                raise ValueError(f"Could not find entry point for service {service_name}")
                
        # Build the command
        cmd = f"node {entry_point}"
        env = {
            "MCP_PORT": str(service.port),
            "NODE_ENV": "production"
        }
        
        # Spawn the process
        process_info = await self.process_manager.spawn_process(
            session_id=session_id,
            command=cmd,
            cwd=str(service.path),
            env=env
        )
        
        service.process_id = process_info.process_id
        service.status = MCPServiceStatus.RUNNING
        
        return process_info
        
    async def stop_service(self, service_name: str) -> None:
        """Stop an MCP service.
        
        Args:
            service_name: Name of the service to stop
            
        Raises:
            ValueError: If service not found or not running
        """
        service = self.services.get(service_name)
        if not service:
            raise ValueError(f"Service {service_name} not found")
            
        if service.status != MCPServiceStatus.RUNNING or not service.process_id:
            raise ValueError(f"Service {service_name} is not running")
            
        # Terminate the process
        await self.process_manager.terminate_process(service.process_id)
        
        service.process_id = None
        service.port = None
        service.status = MCPServiceStatus.AVAILABLE
        
    async def install_service(self, service_name: str, session_id: str) -> ProcessInfo:
        """Install dependencies for an MCP service.
        
        Args:
            service_name: Name of the service to install
            session_id: Session ID for the install process
            
        Returns:
            Process information for the install command
            
        Raises:
            ValueError: If service not found
        """
        service = self.services.get(service_name)
        if not service:
            raise ValueError(f"Service {service_name} not found")
            
        # Run npm install
        process_info = await self.process_manager.spawn_process(
            session_id=session_id,
            command="npm install",
            cwd=str(service.path)
        )
        
        # Update status
        service.status = MCPServiceStatus.INSTALLING
        
        # TODO: Monitor process completion and update status
        
        return process_info
        
    def get_service_info(self, service_name: str) -> Optional[MCPService]:
        """Get information about a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Service information or None if not found
        """
        return self.services.get(service_name)
        
    def list_services(self) -> List[MCPService]:
        """List all discovered services.
        
        Returns:
            List of all services
        """
        return list(self.services.values())