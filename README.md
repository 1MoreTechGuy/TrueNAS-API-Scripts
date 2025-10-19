# TrueNAS API Scripts

Scripts to connect to one or more TrueNAS instances and perform actions via the TrueNAS API. Check out https://api.truenas.com/v25.10/ for more information.

## Dependencies

- Python 3.8+
- websockets
- pyyaml

Install dependencies:

```bash
python3 -m pip install websockets pyyaml
```

## Quick Start

Run the script against an `inventory.yaml` file in the current directory (default):

```bash
python3 truenas_upgrade_apps.py
```

Or point to a custom inventory file using the `TRUENAS_INVENTORY` environment variable:

```bash
TRUENAS_INVENTORY=/path/to/inventory.yaml python3 truenas_upgrade_apps.py
```

Use `-v` / `--verbose` to display detailed app info:

```bash
python3 truenas_upgrade_apps.py -v
```

## Usage

```
Usage: truenas_upgrade_apps.py [-h] [-v]

TrueNAS Apps Upgrade Tool

Options:
  -h, --help     show this help message and exit
  -v, --verbose  Show detailed information about all apps
```

## Configuration

You can provide hosts via an inventory YAML file or using environment variables.

### Inventory (default `inventory.yaml`)

Example `inventory.yaml`:

```yaml
hosts:
  - name: TrueNAS-Alpha
    url: "https://<IP OR HOSTNAME>"
    token: "TRUENAS_API_TOKEN"
    verify_ssl: false
  - name: TrueNAS-Omega
    url: "https://<IP OR HOSTNAME>"
    token: "TRUENAS_API_TOKEN"
    verify_ssl: false
```

### Environment variables

You can supply hosts using numbered environment variables. Example:

```bash
export TRUENAS_URL_1="https://<IP OR HOSTNAME>"
export TRUENAS_TOKEN_1="TRUENAS_API_TOKEN"
export TRUENAS_NAME_1="TrueNAS-Alpha"
export TRUENAS_VERIFY_SSL_1="false"

export TRUENAS_URL_2="https://<IP OR HOSTNAME>"
export TRUENAS_TOKEN_2="TRUENAS_API_TOKEN"
export TRUENAS_NAME_2="TrueNAS-Omega"
export TRUENAS_VERIFY_SSL_2="false"
```

## Notes

- The script defaults to `inventory.yaml` in the working directory. Use `TRUENAS_INVENTORY` to override.
- Inventory files and environment variables contain API tokens and should not be committed to version control. This repo ignores `inventory.yaml` and `inventory.yml`.

## Troubleshooting

- Authentication failed: verify the API tokens and that the user has necessary permissions.
- Connection errors: ensure the TrueNAS URL is reachable and WebSocket (wss) access is allowed.
- SSL verification: set `verify_ssl: false` in your inventory for self-signed certs or set the `TRUENAS_VERIFY_SSL_<n>` env var to `false`.

## Help

Run `python3 truenas_upgrade_apps.py -h` to display command-line help.


## SemaphoreUI

This script can be automated via platforms such as SemaphoreUI.

A variable group can be used to define the environment variables. SemaphoreUI acceptes JSON as way to mass upload the variables and values.

```json
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
