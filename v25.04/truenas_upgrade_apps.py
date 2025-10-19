"""
truenas_upgrade_apps.py (v25.04.2)

This copy is adapted to use TrueNAS API v25.04.2 and to authenticate using
the `auth.login_ex` method with the `API_KEY_PLAIN` mechanism.

Provide credentials via the inventory `username` and `token` fields, or via
environment variables. The token is passed as the password value to the
API_KEY_PLAIN mechanism.

This file is intended for testing and compatibility with v25.04.2.
"""

import asyncio
import json
import os
import ssl
from argparse import ArgumentParser
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import websockets
import yaml

@dataclass
class TrueNASHost:
    """Data class for TrueNAS host configuration"""
    name: str
    url: str
    token: str
    username: Optional[str] = None
    verify_ssl: bool = False

class TrueNASAppManager:
    """Handles TrueNAS application operations"""
    def __init__(self, host: TrueNASHost, api_version: str = 'v25.04.2'):
        self.host = host
        # Store the API version to use for requests (e.g. 'v25.04.1')
        # This v25.04 compatibility copy defaults to v25.04.2
        self.api_version = api_version.lstrip('/')

        # Create SSL context depending on host.verify_ssl
        self.ssl_context = self._create_ssl_context(host.verify_ssl)

        # Normalize host URL: allow plain host/IP or full URL with scheme
        parsed = urlparse(host.url)
        if parsed.scheme:
            # If a scheme is present, prefer the network location (netloc). Some inputs may put host in path.
            host_netloc = parsed.netloc or parsed.path
        else:
            # No scheme provided, assume the value is host[:port]
            host_netloc = host.url

        host_netloc = host_netloc.rstrip('/')

        # Choose WebSocket scheme: default to secure (wss) unless explicit http scheme provided
        if parsed.scheme == 'http':
            ws_scheme = 'ws'
        else:
            ws_scheme = 'wss'

        self.ws_url = f"{ws_scheme}://{host_netloc}/api/{self.api_version}"

    @staticmethod
    def _create_ssl_context(verify_ssl: bool = False) -> ssl.SSLContext:
        """Create SSL context for WebSocket connection.

        If verify_ssl is True, return a default context that verifies certificates.
        If False, return a context that disables verification (for self-signed certs).
        """
        if verify_ssl:
            return ssl.create_default_context()

        # Default to insecure context when verification is disabled to preserve previous behavior
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    async def process_apps(self) -> Tuple[Dict, List]:
        """Process all app operations for a TrueNAS instance"""
        async with websockets.connect(self.ws_url, ssl=self.ssl_context) as websocket:
            await self._authenticate(websocket)
            apps_response = await self._get_apps_list(websocket)
            upgrade_results = await self._process_upgrades(websocket, apps_response)
            return apps_response, upgrade_results

    async def _authenticate(self, websocket) -> None:
        """Authenticate with TrueNAS using auth.login_ex and API_KEY_PLAIN.

        This sends a single RPC call to `auth.login_ex` with a dict parameter
        containing the mechanism and credentials. The API expects the token to be
        provided in the `password` field when using API_KEY_PLAIN. A username
        should be provided in the inventory or as an environment variable.
        """
        username = getattr(self.host, 'username', None) or os.getenv('TRUENAS_USERNAME')
        token = self.host.token

        # Primary payload shape follows the v25.04 docs: a single object
        # with mechanism and mechanism-specific keys. Send this and raise
        # on any error; we've validated username/token presence earlier.
        payload = {
            'mechanism': 'API_KEY_PLAIN',
            'username': username or '',
            'api_key': token,
        }

        auth_msg = {
            'id': 1,
            'jsonrpc': '2.0',
            'method': 'auth.login_ex',
            'params': [payload],
        }

        await websocket.send(json.dumps(auth_msg))
        auth_result = json.loads(await websocket.recv())
        if 'error' in auth_result:
            raise Exception(f"Authentication failed: {auth_result['error']}")

    async def _get_apps_list(self, websocket) -> Dict:
        """Get list of installed apps"""
        apps_msg = {
            "id": 2,
            "jsonrpc": "2.0",
            "method": "app.query",
            "params": [[], {"select": ["name", "upgrade_available", "version", "latest_version"]}]
        }
        await websocket.send(json.dumps(apps_msg))
        return json.loads(await websocket.recv())

    async def _process_upgrades(self, websocket, apps_response: Dict) -> List:
        """Process necessary upgrades"""
        upgrade_results = []
        if 'result' in apps_response:
            upgrades_needed = [
                app for app in apps_response['result']
                if app.get('upgrade_available', False)
            ]
            for app in upgrades_needed:
                upgrade_msg = {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "app.upgrade",
                    "params": [app['name']]
                }
                await websocket.send(json.dumps(upgrade_msg))
                upgrade_result = json.loads(await websocket.recv())
                upgrade_results.append((app, upgrade_result))
        return upgrade_results

def get_truenas_config() -> List[TrueNASHost]:
    """Load TrueNAS configuration from environment or file"""
    hosts = _get_hosts_from_env()
    if not hosts:
        hosts = _get_hosts_from_file()
    if not hosts:
        raise Exception("No configuration found. Set environment variables or provide inventory file.")
    return hosts

def _get_hosts_from_env() -> List[TrueNASHost]:
    """Get host configurations from environment variables"""
    hosts = []
    instance = 1
    while True:
        url = os.getenv(f'TRUENAS_URL_{instance}')
        if not url:
            break
        hosts.append(TrueNASHost(
            name=os.getenv(f'TRUENAS_NAME_{instance}', f'TrueNAS-{instance}'),
            url=url,
            token=os.getenv(f'TRUENAS_TOKEN_{instance}'),
            username=os.getenv(f'TRUENAS_USERNAME_{instance}'),
            verify_ssl=os.getenv(f'TRUENAS_VERIFY_SSL_{instance}', 'false').lower() == 'true'
        ))
        instance += 1
    return hosts

def _get_hosts_from_file() -> Optional[List[TrueNASHost]]:
    """Get host configurations from inventory file"""
    inventory_path = os.getenv('TRUENAS_INVENTORY', 'inventory.yaml')
    if os.path.exists(inventory_path):
        with open(inventory_path, 'r') as file:
            inventory = yaml.safe_load(file)
            return [TrueNASHost(**host) for host in inventory.get('hosts', [])]
    return None

async def main() -> None:
    """Main application entry point"""
    parser = ArgumentParser(description='TrueNAS Apps Upgrade Tool')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed information about all apps')
    parser.add_argument('--api-version', dest='api_version', default=None,
                       help='Override the TrueNAS API version to use (e.g. v25.04.2)')
    args = parser.parse_args()
    
    try:
        inventory = get_truenas_config()
        # Determine API version: CLI flag takes precedence, then env var, then default
        api_version = args.api_version or os.getenv('TRUENAS_API_VERSION') or 'v25.04.2'
        all_results = {}
        
        # Process all hosts
        for host in inventory:
            if not host.url or not host.token or not getattr(host, 'username', None):
                raise Exception(f"Host '{host.name}' is missing required configuration: url, token, and username are required for API_KEY_PLAIN authentication.")
            manager = TrueNASAppManager(host, api_version=api_version)
            apps_info, upgrades = await manager.process_apps()
            all_results[host.name] = (apps_info, upgrades)
        
        # Display results
        _display_results(all_results, args.verbose)
            
    except Exception as e:
        print(f"\nError: {str(e)}")

def _display_results(all_results: Dict, verbose: bool) -> None:
    """Display processing results"""
    if verbose:
        _display_verbose_info(all_results)
    
    upgrades_found = _display_upgrades(all_results)
    
    if not upgrades_found:
        print("\n✨ All applications are up to date!")

def _display_verbose_info(all_results: Dict) -> None:
    """Display verbose information about all apps"""
    print("\nInstalled Apps Information for TrueNAS instances...")
    for host_name, (info, _) in all_results.items():
        print(f"\n{host_name}:")
        if 'result' in info and info['result']:
            for app in info['result']:
                print(f"- {app.get('name', 'Unknown')}")
                print(f"  Version: {app.get('version', 'Unknown')}")
                print(f"  Latest: {app.get('latest_version', 'Unknown')}")
                print(f"  Update: {'Yes' if app.get('upgrade_available', False) else 'No'}")
        else:
            print("No apps found")
        print()

def _display_upgrades(all_results: Dict) -> bool:
    """Display upgrade information and return whether upgrades were found"""
    upgrades_found = False
    for host_name, (info, upgrades) in all_results.items():
        if 'result' in info:
            updates = [app for app in info['result'] if app.get('upgrade_available', False)]
            if updates:
                if not upgrades_found:
                    print("\nProcessing updates...")
                    upgrades_found = True
                print(f"\n{host_name}")
                for app, result in upgrades:
                    if 'error' in result:
                        print(f"❌ {app['name']}: {app['version']} → {app['latest_version']} - {result['error']}")
                    else:
                        print(f"✅ {app['name']}: {app['version']} → {app['latest_version']} - Update initiated")
    return upgrades_found

if __name__ == "__main__":
    asyncio.run(main())