import asyncio
import websockets
import json
import ssl
import yaml
import os
import argparse
from typing import Dict, List, Tuple

async def process_truenas_apps(url: str, token: str) -> Tuple[Dict, List]:
    """Handle all TrueNAS API calls for a single instance"""
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    ws_url = url.replace('https://', 'wss://')
    ws_url += '/api/current'
    
    async with websockets.connect(ws_url, ssl=ssl_context) as websocket:
        # 1. Authentication
        auth_msg = {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "auth.login_with_api_key",
            "params": [token]
        }
        await websocket.send(json.dumps(auth_msg))
        auth_result = json.loads(await websocket.recv())
        if 'error' in auth_result:
            raise Exception(f"Authentication failed: {auth_result['error']}")
        
        # 2. Get apps list
        apps_msg = {
            "id": 2,
            "jsonrpc": "2.0",
            "method": "app.query",
            "params": [[], {"select": ["name", "upgrade_available", "version", "latest_version"]}]
        }
        await websocket.send(json.dumps(apps_msg))
        apps_response = json.loads(await websocket.recv())
        
        # 3. Process upgrades if needed
        upgrade_results = []
        if 'result' in apps_response:
            upgrades_needed = [app for app in apps_response['result'] 
                             if app.get('upgrade_available', False)]
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
        
        return apps_response, upgrade_results

def get_truenas_config() -> List[Dict]:
    """Get TrueNAS configuration from environment variables or inventory file"""
    hosts = []
    
    # Check for numbered environment variables (TRUENAS_URL_1, TRUENAS_URL_2, etc.)
    instance = 1
    while True:
        url = os.getenv(f'TRUENAS_URL_{instance}')
        if not url:
            break
            
        hosts.append({
            'name': os.getenv(f'TRUENAS_NAME_{instance}', f'TrueNAS-{instance}'),
            'url': url,
            'token': os.getenv(f'TRUENAS_TOKEN_{instance}'),
            'verify_ssl': os.getenv(f'TRUENAS_VERIFY_SSL_{instance}', 'false').lower() == 'true'
        })
        instance += 1
    
    # If no environment variables found, try inventory file
    if not hosts:
        inventory_path = os.getenv('TRUENAS_INVENTORY', 'inventory.yaml')
        if os.path.exists(inventory_path):
            with open(inventory_path, 'r') as file:
                inventory = yaml.safe_load(file)
                return inventory.get('hosts', [])
        raise Exception("No configuration found. Set environment variables or provide inventory file.")
    
    return hosts

async def main():
    # Add argument parsing
    parser = argparse.ArgumentParser(description='TrueNAS Apps Upgrade Tool')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Show detailed information about all apps')
    args = parser.parse_args()
    
    inventory = get_truenas_config()
    all_results = {}
    
    try:
        # Collect all data first
        for host in inventory:
            if not host.get('url') or not host.get('token'):
                continue
            apps_info, upgrades = await process_truenas_apps(host['url'], host['token'])
            all_results[host['name']] = (apps_info, upgrades)
        
        if args.verbose:
            # Verbose output - show all apps
            print("\nInstalled Apps for all TrueNAS instances:")
            for host_name, (info, _) in all_results.items():
                print(f"\n\n{host_name}")
                if 'result' in info and info['result']:
                    for app in info['result']:
                        print(f"\n- {app.get('name', 'Unknown')}")
                        print(f"  - Current Version: {app.get('version', 'Unknown')}")
                        print(f"  - Latest Version: {app.get('latest_version', 'Unknown')}")
                        print(f"  - Upgrade Available: {app.get('upgrade_available', False)}")
                else:
                    print("  No apps found or error retrieving apps")
        
        # Always show upgrade results (simplified if not verbose)
        upgrade_initiated = False
        for host_name, (_, upgrades) in all_results.items():
            if upgrades:
                if not upgrade_initiated:
                    print("\nInitiating upgrades...")
                    upgrade_initiated = True
                
                for app, result in upgrades:
                    if 'error' in result:
                        print(f"❌ {host_name}: Error upgrading {app['name']}: {result['error']}")
                    else:
                        if args.verbose:
                            print(f"\n✅ {host_name}: Upgrading {app['name']}")
                            print(f"   From: {app['version']}")
                            print(f"   To: {app['latest_version']}")
                        else:
                            print(f"✅ {host_name}: {app['name']} ({app['version']} → {app['latest_version']})")
        
        if not upgrade_initiated:
            print("\n✨ All applications are up to date!")

    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())