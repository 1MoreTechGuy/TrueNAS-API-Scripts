import asyncio
import websockets
import json
import ssl
import yaml
from typing import Dict, List

async def upgrade_app(websocket, app_name: str) -> Dict:
    upgrade_msg = {
        "id": 3,
        "jsonrpc": "2.0",
        "method": "app.upgrade",
        "params": [app_name]
    }
    await websocket.send(json.dumps(upgrade_msg))
    return json.loads(await websocket.recv())

async def get_installed_apps(url: str, token: str) -> Dict:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    ws_url = url.replace('https://', 'wss://')
    ws_url += '/api/current'
    
    async with websockets.connect(ws_url, ssl=ssl_context) as websocket:
        # Authentication
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
        
        # Get apps list
        apps_msg = {
            "id": 2,
            "jsonrpc": "2.0",
            "method": "app.query",
            "params": [[], {"select": ["name", "upgrade_available", "version", "latest_version"]}]
        }
        
        await websocket.send(json.dumps(apps_msg))
        apps_response = json.loads(await websocket.recv())
        
        # Upgrade apps that need updates
        if 'result' in apps_response:
            for app in apps_response['result']:
                if app.get('upgrade_available', False):
                    print(f"\nUpgrading {app['name']} from version {app['version']} to {app['latest_version']}...")
                    upgrade_result = await upgrade_app(websocket, app['name'])
                    if 'error' in upgrade_result:
                        print(f"Error upgrading {app['name']}: {upgrade_result['error']}")
                    else:
                        print(f"Successfully initiated upgrade for {app['name']}")
        
        return apps_response

async def process_hosts(hosts: List[Dict]) -> Dict[str, Dict]:
    tasks = []
    for host in hosts:
        if not host.get('url') or not host.get('token'):
            continue
        tasks.append(get_installed_apps(host['url'], host['token']))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return {hosts[i]['name']: result for i, result in enumerate(results) 
            if not isinstance(result, Exception)}

async def main():
    with open('inventory.yaml', 'r') as file:
        inventory = yaml.safe_load(file)
    
    try:
        results = await process_hosts(inventory['hosts'])
        print("\nInstalled Apps for all TrueNAS instances:")
        for host_name, info in results.items():
            print(f"\n\n{host_name}")
            if 'result' in info and info['result']:
                for app in info['result']:
                    print(f"\n- {app.get('name', 'Unknown')}")
                    print(f"  - Current Version: {app.get('version', 'Unknown')}")
                    print(f"  - Latest Version: {app.get('latest_version', 'Unknown')}")
                    print(f"  - Upgrade Available: {app.get('upgrade_available', False)}")
            else:
                print("  No apps found or error retrieving apps")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())