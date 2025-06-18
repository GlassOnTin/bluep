"""CLI for bluep MCP client proxy."""

import asyncio
import sys
import logging
import os
from pathlib import Path

import click

from .proxy import MCPClientProxy

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def get_session_token():
    """Get session token from environment or config file."""
    # Check environment variable
    token = os.environ.get('BLUEP_SESSION')
    if token:
        return token
        
    # Check config file
    config_file = Path.home() / '.bluep' / 'session'
    if config_file.exists():
        return config_file.read_text().strip()
        
    return None


@click.group()
def cli():
    """Bluep MCP Client - Access remote MCP services locally."""
    pass


@cli.command()
@click.option('--server', '-s', default='wss://localhost:8500/ws', 
              help='Bluep WebSocket server URL')
@click.option('--token', '-t', envvar='BLUEP_SESSION',
              help='Session token (or set BLUEP_SESSION env var)')
@click.option('--no-verify-ssl', is_flag=True,
              help='Disable SSL certificate verification')
def list(server, token, no_verify_ssl):
    """List available MCP services."""
    if not token:
        token = get_session_token()
        if not token:
            click.echo("Error: Session token required. Use --token or set BLUEP_SESSION", err=True)
            click.echo("You can get your session token from the browser's cookies after logging into bluep", err=True)
            sys.exit(1)
    
    async def list_services():
        proxy = MCPClientProxy(server, token, verify_ssl=not no_verify_ssl)
        try:
            await proxy.connect()
            result = await proxy.list_services()
            
            services = result.get('mcpServices', [])
            if not services:
                click.echo("No MCP services available")
                return
                
            click.echo("Available MCP services:")
            for service in services:
                status = service.get('status', 'unknown')
                name = service.get('name', 'unknown')
                host = service.get('hostingSession', 'none')
                click.echo(f"  - {name}: {status} (hosted by: {host})")
                
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        finally:
            await proxy.stop()
            
    asyncio.run(list_services())


@cli.command()
@click.argument('service_name')
@click.option('--server', '-s', default='wss://localhost:8500/ws',
              help='Bluep WebSocket server URL')
@click.option('--token', '-t', envvar='BLUEP_SESSION',
              help='Session token (or set BLUEP_SESSION env var)')
@click.option('--port', '-p', default=4000,
              help='Local port to expose service on')
@click.option('--websocket', '-w', is_flag=True,
              help='Use WebSocket proxy instead of HTTP')
@click.option('--no-verify-ssl', is_flag=True,
              help='Disable SSL certificate verification')
def proxy(service_name, server, token, port, websocket, no_verify_ssl):
    """Start local proxy for an MCP service."""
    if not token:
        token = get_session_token()
        if not token:
            click.echo("Error: Session token required. Use --token or set BLUEP_SESSION", err=True)
            click.echo("You can get your session token from the browser's cookies after logging into bluep", err=True)
            sys.exit(1)
    
    async def run_proxy():
        proxy = MCPClientProxy(server, token, verify_ssl=not no_verify_ssl)
        try:
            await proxy.connect()
            
            if websocket:
                await proxy.start_websocket_proxy(service_name, port)
                click.echo(f"MCP WebSocket proxy started on ws://localhost:{port}")
            else:
                await proxy.start_http_proxy(service_name, port)
                click.echo(f"MCP HTTP proxy started on http://localhost:{port}")
                
            click.echo(f"Proxying MCP service '{service_name}'")
            click.echo("Press Ctrl+C to stop")
            
            # Keep running until interrupted
            await asyncio.Event().wait()
            
        except KeyboardInterrupt:
            click.echo("\nShutting down proxy...")
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        finally:
            await proxy.stop()
            
    asyncio.run(run_proxy())


@cli.command()
@click.option('--token', '-t', required=True,
              help='Session token to save')
def auth(token):
    """Save authentication token for future use."""
    config_dir = Path.home() / '.bluep'
    config_dir.mkdir(exist_ok=True)
    
    session_file = config_dir / 'session'
    session_file.write_text(token)
    session_file.chmod(0o600)  # Restrict permissions
    
    click.echo(f"Session token saved to {session_file}")
    click.echo("You can now use bluep-mcp commands without specifying --token")


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()