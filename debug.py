"""debug.py

Debug script to troubleshoot issues on semaphore or possibly other script
automation platforms and runners

Acknowledgement:
This file was created with the assistance of GitHub Copilot. Review and
testing were performed by the author.

"""

import asyncio
import os
import ssl
from urllib.parse import urlparse

import websockets
from websockets.exceptions import WebSocketException
import yaml

print("\n==  ENVIRONMENT VARIABLES  ==")
print("=============================")

for key, value in os.environ.items():
    print(f"{key}={value}")

print("\n==  CHECK INVENTORY FILE  ==")
print("============================")

# Get host configurations from inventory file
inventory_path = os.getenv('TRUENAS_INVENTORY', 'inventory.yaml')
if os.path.exists(inventory_path):
    # Explicitly specify encoding for portability
    with open(inventory_path, 'r', encoding='utf-8') as file:
        inventory = yaml.safe_load(file) or {}
        print(f'FILENAME: {inventory_path}')
        print(f'CONTENTS: {inventory}')
else:
    print('No Inventory File Found \n')


def _get_hosts_from_env():
    host_configs = []
    instance = 1
    while True:
        url = os.getenv(f'TRUENAS_URL_{instance}')
        if not url:
            break
        api_version = os.getenv(f'TRUENAS_API_VERSION_{instance}')
        if api_version is None:
            api_version = os.getenv('TRUENAS_API_VERSION', 'v25.10.0')

        host_configs.append({
            'name': os.getenv(f'TRUENAS_NAME_{instance}', f'TrueNAS-{instance}'),
            'url': url,
            'token': os.getenv(f'TRUENAS_TOKEN_{instance}'),
            'verify_ssl': os.getenv(f'TRUENAS_VERIFY_SSL_{instance}', 'false').lower() == 'true',
            'api_version': api_version,
        })
        instance += 1
    return host_configs


def _get_hosts_from_inventory(inventory_data):
    host_configs = []
    if not isinstance(inventory_data, dict):
        return host_configs
    for inventory_host in inventory_data.get('hosts', []):
        if not isinstance(inventory_host, dict) or not inventory_host.get('url'):
            continue
        api_version = inventory_host.get('api_version')
        if api_version is None:
            api_version = os.getenv('TRUENAS_API_VERSION', 'v25.10.0')
        host_configs.append({
            'name': inventory_host.get('name', inventory_host['url']),
            'url': inventory_host['url'],
            'token': inventory_host.get('token'),
            'verify_ssl': bool(inventory_host.get('verify_ssl', False)),
            'api_version': api_version,
        })
    return host_configs


def _build_ws_url(url, api_version=None):
    parsed = urlparse(url)
    if parsed.scheme in ('ws', 'wss'):
        scheme = parsed.scheme
    elif parsed.scheme == 'http':
        scheme = 'ws'
    else:
        scheme = 'wss'
    host_netloc = parsed.netloc or parsed.path
    host_netloc = host_netloc.rstrip('/')
    api_version = api_version or os.getenv('TRUENAS_API_VERSION', 'v25.10.0')
    return f"{scheme}://{host_netloc}/api/{api_version}"


def _create_ssl_context(verify_ssl):
    if verify_ssl:
        return ssl.create_default_context()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def _check_one_ws(host):
    ws_url = _build_ws_url(host['url'], host.get('api_version'))
    ssl_context = _create_ssl_context(host.get('verify_ssl', False))
    try:
        async with websockets.connect(ws_url, ssl=ssl_context):  # pylint: disable=no-member
            return True, ws_url, None
    except (OSError, WebSocketException) as exc:
        return False, ws_url, exc


async def _check_websockets(hosts):
    print("\n==  WEBSOCKET CONNECTION CHECK  ==")
    print("==================================")
    if not hosts:
        print('No TrueNAS hosts found for websocket connectivity checks.\n')
        return
    
    for host in hosts:
        success, ws_url, exc = await _check_one_ws(host)
        if success:
            print(f"[OK]   {host['name']} → {ws_url}")
        else:
            print(f"[FAIL] {host['name']} → {ws_url}: {exc}")
    print()


print("\n==  PARSING HOSTS FROM INVENTORY  ==")
print("==================================")
all_hosts = []
try:
    all_hosts.extend(_get_hosts_from_env())
except Exception as exc:
    print(f"Error parsing hosts from environment variables: {exc}")
try:
    all_hosts.extend(_get_hosts_from_inventory(inventory))
except Exception as exc:
    print(f"Error parsing hosts from inventory file: {exc}")

# Deduplicate hosts by URL while preserving order
seen_urls = set()
deduped_hosts = []
for host_entry in all_hosts:
    if host_entry['url'] in seen_urls:
        continue
    seen_urls.add(host_entry['url'])
    deduped_hosts.append(host_entry)
print(f'RESULT: {all_hosts.__len__()} Total Host Found, {deduped_hosts.__len__()} Unique Hosts.')
print(f'CONTENTS: {all_hosts}')

asyncio.run(_check_websockets(deduped_hosts))

print("===      END OUTPUT      ===\n")
