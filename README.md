# TrueNAS API Scripts

Scripts to connect to one or more TrueNAS instances and perform actions via the TrueNAS API.

Notes on versions:
- The main script (`truenas_upgrade_apps.py` in the repository root) was developed and tested
  against the TrueNAS API version v25.10.0. Refer to https://api.truenas.com/v25.10/ for
  that API's details.
- A compatibility copy targeting older TrueNAS API versions is provided under the
  `v25.04/` directory (`v25.04/truenas_upgrade_apps.py`) and defaults to `v25.04.2`.

## Dependencies

- Python 3.8+
- websockets
- pyyaml

Install dependencies:

```bash
python3 -m pip install websockets pyyaml
```
Or
```bash
sudo apt install python3-webscockets pyyaml-env-tag
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

Specify the API version to use with `--api-version` or the `TRUENAS_API_VERSION` environment variable. Example:

```bash
python3 truenas_upgrade_apps.py --api-version v25.10.0
# or via env var
TRUENAS_API_VERSION=v25.10.0 python3 truenas_upgrade_apps.py
```

## Usage

```
python3 truenas_upgrade_apps.py [-h] [-v] [--api-version API_VERSION]

Options:

- -h, --help: show help and exit
- -v, --verbose: show detailed information about all apps
- --api-version: override API version used by the script (e.g. v25.10.0)
```

Examples:

- Run the script (defaults to v25.10.0):

```bash
python3 truenas_upgrade_apps.py
```

- Run the script but force a different API version (advanced use):

```bash
python3 truenas_upgrade_apps.py --api-version v26.04
```
## Configuration

You can provide hosts via an inventory YAML file or using environment variables.

### Inventory (default `inventory.yaml`)

Example `inventory.yaml`:

```yaml
hosts:
  - name: TrueNAS-Alpha
    # URL may be a bare hostname or IP (scheme optional). e.g. "truenas.local" or "192.168.1.5"
    url: "<IP OR HOSTNAME>"
    token: "<TRUENAS_API_TOKEN>"
    verify_ssl: false
  - name: TrueNAS-Omega
    url: "<IP OR HOSTNAME>"
    token: "<TRUENAS_API_TOKEN>"
    verify_ssl: false
```

### Environment variables

You can supply hosts using numbered environment variables. Example:

```bash
export TRUENAS_URL_1="<IP OR HOSTNAME>"
export TRUENAS_TOKEN_1="<TRUENAS_API_TOKEN>"
export TRUENAS_NAME_1="TrueNAS-Alpha"
export TRUENAS_VERIFY_SSL_1="false"

export TRUENAS_URL_2="<IP OR HOSTNAME>"
export TRUENAS_TOKEN_2="<TRUENAS_API_TOKEN>"
export TRUENAS_NAME_2="TrueNAS-Omega"
export TRUENAS_VERIFY_SSL_2="false"
```

## Notes

- The script defaults to `inventory.yaml` in the working directory. Use `TRUENAS_INVENTORY` to override.
- Inventory files and environment variables contain API tokens and should not be committed to version control. This repo ignores `inventory.yaml` and `inventory.yml`.

API version override

You can override the API version the script uses by setting the `TRUENAS_API_VERSION` environment variable or passing `--api-version` on the command line. The default for the root script is `v25.10.0`. The compatibility copy in `v25.04/` defaults to `v25.04.2`.

## Troubleshooting

- Authentication failed: verify the API tokens and that the user has necessary permissions.
- Connection errors: ensure the TrueNAS URL is reachable and WebSocket (wss) access is allowed.
- SSL verification: set `verify_ssl: false` in your inventory for self-signed certs or set the `TRUENAS_VERIFY_SSL_<n>` env var to `false`.

Input formats accepted for the `url`/`TRUENAS_URL_<n>` fields:

- Bare hostname or IP: `truenas.local` or `192.168.1.5`
- Hostname/IP with port: `truenas.local:8443` or `192.168.1.5:8443`
- Full URL (scheme allowed): `https://truenas.local` or `http://192.168.1.5:80`

When a scheme is not provided the script defaults to secure WebSockets (`wss://`). If you explicitly provide `http://`, the script will use `ws://`.

## Help

Run `python3 truenas_upgrade_apps.py -h` to display command-line help.


## SemaphoreUI

This script can be automated via platforms such as SemaphoreUI. 

REMINDER: You need to install the dependencies on your semaphore host system or instance before running this script.

A variable group can be used to define the environment variables. SemaphoreUI accepts JSON as way to mass upload the variables and values.

```json
{
  "TRUENAS_URL_1": "<IP OR HOSTNAME>",
  "TRUENAS_TOKEN_1": "<TRUENAS_API_TOKEN>",
  "TRUENAS_NAME_1": "TrueNAS-Alpha",
  "TRUENAS_VERIFY_SSL_1": "false",
  "TRUENAS_URL_2": "<IP OR HOSTNAME>",
  "TRUENAS_TOKEN_2": "<TRUENAS_API_TOKEN>",
  "TRUENAS_NAME_2": "TrueNAS-Omega",
  "TRUENAS_VERIFY_SSL_2": "false"
}
```

## Acknowledgements

This project was developed with assistance from GitHub Copilot. The tool suggested code and documentation snippets which were reviewed, edited, and tested by the author.
