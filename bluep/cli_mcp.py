"""CLI commands for MCP service management in bluep."""

import asyncio
import sys
import logging
import json
from pathlib import Path
from typing import Optional

import click
import aiohttp

from .mcp_client_proxy import MCPClientProxy

logger = logging.getLogger(__name__)


@click.group()
def mcp():
    """Manage MCP services in bluep."""
    pass


@mcp.command()
@click.option('--bluep-url', default='https://localhost:8500', help='Bluep server URL')
@click.option('--session', envvar='BLUEP_SESSION', help='Session token (or set BLUEP_SESSION env var)')
async def list_services(bluep_url: str, session: Optional[str]):
    """List available MCP services."""
    if not session:
        click.echo("Error: Session token required (use --session or set BLUEP_SESSION)", err=True)
        sys.exit(1)
        
    async with aiohttp.ClientSession() as http_session:
        # TODO: Make HTTP request to list services
        # For now, we'd need to connect via WebSocket
        click.echo("Listing MCP services requires WebSocket connection (not yet implemented)")


@mcp.command()
@click.argument('service_name')
@click.option('--bluep-url', default='wss://localhost:8500/ws', help='Bluep WebSocket URL')
@click.option('--session', envvar='BLUEP_SESSION', help='Session token (or set BLUEP_SESSION env var)')
@click.option('--port', default=4000, help='Local port to expose service on')
@click.option('--websocket', is_flag=True, help='Use WebSocket proxy instead of HTTP')
def proxy(service_name: str, bluep_url: str, session: Optional[str], port: int, websocket: bool):
    """Start local proxy for an MCP service."""
    if not session:
        click.echo("Error: Session token required (use --session or set BLUEP_SESSION)", err=True)
        sys.exit(1)
        
    async def run_proxy():
        proxy = MCPClientProxy(bluep_url, session)
        await proxy.connect()
        
        if websocket:
            await proxy.start_websocket_proxy(service_name, port)
            click.echo(f"MCP WebSocket proxy started on ws://localhost:{port}")
        else:
            await proxy.start_http_proxy(service_name, port)
            click.echo(f"MCP HTTP proxy started on http://localhost:{port}")
            
        click.echo(f"Proxying MCP service '{service_name}'")
        click.echo("Press Ctrl+C to stop")
        
        try:
            await asyncio.Event().wait()
        except KeyboardInterrupt:
            click.echo("\nShutting down proxy...")
            await proxy.stop()
            
    asyncio.run(run_proxy())


@mcp.command()
@click.argument('service_path')
@click.option('--name', help='Service name (defaults to directory name)')
def install(service_path: str, name: Optional[str]):
    """Install an MCP service from a git repository or local path."""
    service_path = Path(service_path)
    
    if not name:
        name = service_path.name
        
    # Determine target directory
    mcp_services_dir = Path(__file__).parent.parent / "mcp-services"
    target_dir = mcp_services_dir / name
    
    if target_dir.exists():
        click.echo(f"Error: Service '{name}' already exists", err=True)
        sys.exit(1)
        
    # Create services directory if needed
    mcp_services_dir.mkdir(exist_ok=True)
    
    if service_path.exists() and service_path.is_dir():
        # Local directory
        import shutil
        shutil.copytree(service_path, target_dir)
        click.echo(f"Copied local service to {target_dir}")
    else:
        # Assume it's a git URL
        import subprocess
        try:
            subprocess.run(['git', 'clone', str(service_path), str(target_dir)], check=True)
            click.echo(f"Cloned repository to {target_dir}")
        except subprocess.CalledProcessError:
            click.echo(f"Error: Failed to clone repository {service_path}", err=True)
            sys.exit(1)
            
    # Check for package.json
    package_json = target_dir / "package.json"
    if not package_json.exists():
        click.echo("Warning: No package.json found in service directory", err=True)
        
    click.echo(f"Service '{name}' installed successfully")
    click.echo(f"Run 'cd {target_dir} && npm install' to install dependencies")


if __name__ == '__main__':
    mcp()