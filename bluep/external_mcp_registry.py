"""External MCP Service Registry for reverse proxy support."""

import json
import logging
from pathlib import Path
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ExternalMCPService:
    """Represents an external MCP service that bluep will reverse proxy to."""
    name: str
    url: str
    session_id: str
    description: str = ""
    active: bool = True


class ExternalMCPRegistry:
    """Registry for external MCP services that are hosted elsewhere."""
    
    def __init__(self, registry_file: Optional[Path] = None):
        self.registry_file = registry_file or Path("external_mcp_services.json")
        self.services: Dict[str, ExternalMCPService] = {}
        self._load_registry()
    
    def _load_registry(self) -> None:
        """Load registry from file if it exists."""
        if self.registry_file.exists():
            try:
                with open(self.registry_file, 'r') as f:
                    data = json.load(f)
                    for name, service_data in data.items():
                        self.services[name] = ExternalMCPService(**service_data)
                logger.info(f"Loaded {len(self.services)} external MCP services")
            except Exception as e:
                logger.error(f"Error loading external MCP registry: {e}")
    
    def _save_registry(self) -> None:
        """Save registry to file."""
        try:
            data = {name: asdict(service) for name, service in self.services.items()}
            with open(self.registry_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving external MCP registry: {e}")
    
    def register_service(self, name: str, url: str, session_id: str, description: str = "") -> bool:
        """Register an external MCP service."""
        try:
            self.services[name] = ExternalMCPService(
                name=name,
                url=url,
                session_id=session_id,
                description=description,
                active=True
            )
            self._save_registry()
            logger.info(f"Registered external MCP service: {name} at {url}")
            return True
        except Exception as e:
            logger.error(f"Error registering external service {name}: {e}")
            return False
    
    def unregister_service(self, name: str) -> bool:
        """Unregister an external MCP service."""
        if name in self.services:
            del self.services[name]
            self._save_registry()
            logger.info(f"Unregistered external MCP service: {name}")
            return True
        return False
    
    def get_service(self, name: str) -> Optional[ExternalMCPService]:
        """Get an external service by name."""
        return self.services.get(name)
    
    def list_services(self) -> Dict[str, ExternalMCPService]:
        """List all registered external services."""
        return self.services.copy()
    
    def is_external_service(self, name: str) -> bool:
        """Check if a service is registered as external."""
        return name in self.services
    
    def update_service_status(self, name: str, active: bool) -> bool:
        """Update the active status of a service."""
        if name in self.services:
            self.services[name].active = active
            self._save_registry()
            return True
        return False