import asyncio
import json
import os
import ssl
from argparse import ArgumentParser
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import websockets
import yaml

@dataclass
class TrueNASHost:
    """Data class for TrueNAS host configuration"""
    name: str
    url: str
    token: str
    verify_ssl: bool = False

class TrueNASAppManager:
    """Handles TrueNAS application operations"""
    def __init__(self, host: TrueNASHost):
        self.host = host
        self.ssl_context = self._create_ssl_context()
        self.ws_url = f"{host.url.replace('https://', 'wss://')}/api/current"

    @staticmethod
    def _create_ssl_context() -> ssl.SSLContext:
        """Create SSL context for WebSocket connection"""
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
        """Authenticate with TrueNAS"""
        auth_msg = {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "auth.login_with_api_key",
            "params": [self.host.token]
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
    args = parser.parse_args()
    
    try:
        inventory = get_truenas_config()
        all_results = {}
        
        # Process all hosts
        for host in inventory:
            if not host.url or not host.token:
                continue
            manager = TrueNASAppManager(host)
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