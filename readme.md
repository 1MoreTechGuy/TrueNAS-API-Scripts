Dependencies: python3-websockets

Quick Start: `python3 truenas_upgrade_apps.py` or `TRUENAS_INVENTORY=/path/to/inventory.yaml python3 truenas_upgrade_apps.py`


```
Usage: truenas_upgrade_apps.py [-h] [-v]

TrueNAS Apps Upgrade Tool

Options:
  -h, --help     show this help message and exit
  -v, --verbose  Show detailed information about all apps
 ```

Environmental Variables:

```
export TRUENAS_INVENTORY=/path/to/your/inventory.yaml
```

```
export TRUENAS_URL_1="https://<IP OR HOSTNAME>"
export TRUENAS_TOKEN_1="TRUENAS_API_TOKEN"
export TRUENAS_NAME_1="TrueNAS-Alpha"
export TRUENAS_VERIFY_SSL_1="false"
export TRUENAS_URL_2="https://<IP OR HOSTNAME>"
export TRUENAS_TOKEN_2="TRUENAS_API_TOKEN"
export TRUENAS_NAME_2="TrueNAS-Omega"
export TRUENAS_VERIFY_SSL_2="false"
```

```
{
  "TRUENAS_URL_1": "https://<IP OR HOSTNAME>",
  "TRUENAS_TOKEN_1": "TRUENAS_API_TOKEN",
  "TRUENAS_NAME_1": "TrueNAS-Alpha",
  "TRUENAS_VERIFY_SSL_1": "false",
  
  "TRUENAS_URL_2": "https://<IP OR HOSTNAME>",
  "TRUENAS_TOKEN_2": "TRUENAS_API_TOKEN",
  "TRUENAS_NAME_2": "TrueNAS-Omega",
  "TRUENAS_VERIFY_SSL_2": "false"
}
```