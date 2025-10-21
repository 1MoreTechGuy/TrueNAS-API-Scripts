# TrueNAS API Scripts

Command line utilities to connect to one or more TrueNAS instances and perform actions via the TrueNAS API.

Current Scripts:

- `truenas_upgrade_apps.py` — query installed apps and trigger upgrades when
  `upgrade_available` is reported.
- `truenas_prune_boot_environments.py` — inspect boot environments and
  suggest deletions; optionally perform deletions after confirmation.

Notes:

- Targeted API version: `v25.10.0` by default. Refer to https://api.truenas.com/v25.10/ for
  that API's details.
- A compatibility copy targeting older TrueNAS API versions is provided under the
  `v25.04/` directory and defaults to `v25.04.2`.

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
sudo apt install python3-webscockets python3-yaml
```

## Quick Start

Run any of these scripts against an `inventory.yaml` file in the current directory (default).


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

Use `-h` / `--help` to display helpful documentation:

```bash
python3 truenas_upgrade_apps.py -h
```

## Hosts Configuration

You can provide the list of TrueNAS hosts to operate on in two ways. This
single section describes both methods, the precedence used by the scripts,
global environment variables that affect behavior, URL formats accepted, and
security notes.

### 1) Inventory YAML file (default)

The scripts will read a YAML file containing a top-level `hosts:` list by
default from `inventory.yaml` in the working directory. You can override the
path with the `TRUENAS_INVENTORY` environment variable.

```bash
export TRUENAS_INVENTORY="/path/to/inventory.yaml"
```

Example `inventory.yaml`:

```yaml
hosts:
  - name: TrueNAS-Alpha
    url: "truenas.alpha.local"   # hostname, host:port, or full URL
    token: "<TRUENAS_API_TOKEN>"
    verify_ssl: false
  - name: TrueNAS-Omega
    url: "truenas.omega.local:8443"
    token: "<TRUENAS_API_TOKEN>"
    verify_ssl: false
```

Schema notes:

- `name` (string): human-friendly identifier shown in output.
- `url` (string): host, host:port, or full URL. See "URL formats" below.
- `token` (string): API key/token (keep secret).
- `verify_ssl` (boolean): when false the script disables certificate verification.


### 2) Environment variables (per-host)

For CI or quick runs you can export numbered environment variables. The
loader inspects `TRUENAS_URL_1`, `TRUENAS_URL_2`, ... and stops when the next
URL variable is missing.

Example:

```bash
export TRUENAS_URL_1="truenas.alpha.local"
export TRUENAS_TOKEN_1="<api-token>"
export TRUENAS_NAME_1="TrueNAS-Alpha"
export TRUENAS_VERIFY_SSL_1="false"

export TRUENAS_URL_2="truenas.omega.local"
export TRUENAS_TOKEN_2="<api-token>"
export TRUENAS_NAME_2="TrueNAS-Omega"
export TRUENAS_VERIFY_SSL_2="false"
```

Precedence:

- If any `TRUENAS_URL_<n>` environment variables are present the scripts will
  use the hosts defined via environment variables and will not load the
  inventory YAML.
- If no environment hosts are found the scripts will look for the inventory
  YAML at the path provided by `TRUENAS_INVENTORY` (if set) or `inventory.yaml`.

URL Formatting:

- Bare host or IP: `truenas.local` or `192.168.1.5` (defaults to `wss://`).
- Host with port: `truenas.local:8443` (defaults to `wss://` unless `http://`)
- Full URL with scheme: `https://truenas.local` or `http://192.168.1.5:80`.

When a scheme is not provided the script defaults to secure WebSockets
(`wss://`). If you explicitly provide `http://` the script will use `ws://`.

Security Notes:

- Inventory files and environment variables contain API tokens — do not commit
  them to version control. Use secret stores, CI variable groups, or vault
  solutions for automated runs.
- Setting `verify_ssl: false` or `TRUENAS_VERIFY_SSL_<n>` to `false` disables
  certificate verification and is insecure; only use on trusted networks.


## Script: `truenas_upgrade_apps.py`

Purpose:

Check installed applications on each configured TrueNAS host and initiate
upgrades where `upgrade_available` is reported.

Usage:

```bash
python3 truenas_upgrade_apps.py [options]
```

Options:

- -v, --verbose : show detailed information about installed apps
- --api-version : override the middleware API version (or set
  `TRUENAS_API_VERSION`)

Examples:

```bash
python3 truenas_upgrade_apps.py
python3 truenas_upgrade_apps.py -v
python3 truenas_upgrade_apps.py --api-version v26.04
```

## Script: `truenas_prune_boot_environments.py`

Purpose:

Inspect boot environments and suggest deletions of older, non-protected
environments. Optionally perform deletions after explicit confirmation.

Usage:

```bash
python3 truenas_prune_boot_environments.py [options]
```

Options:

- -v, --verbose : show detailed pool and environment information
- --api-version : override the middleware API version (or set
  `TRUENAS_API_VERSION`)
- --override-warnings : allow proposing deletions when pool reports warning
- --keep-minimum : minimum number of newest environments to keep (default 8)
- --keep-maximum : soft maximum number to keep (protected entries always kept)
- --free-space-minimum : free-percent threshold for emergency deletions (default 20.0)
- --auto-approve : perform deletions without interactive confirmation

Examples:

```bash
python3 truenas_prune_boot_environments.py
python3 truenas_prune_boot_environments.py -v
python3 truenas_prune_boot_environments.py --auto-approve
```

Environment variables (script specific):

- `TRUENAS_OVERRIDE_WARNINGS` — set to `1`/`true` to allow proposing deletions when pool reports warning
- `TRUENAS_KEEP_MINIMUM` - defaults to 8 if not supplied
- `TRUENAS_KEEP_MAXIMUM` - defaults to no limit if not supplied
- `TRUENAS_FREE_SPACE_MINIMUM` — defaults to 20% if not supplied
- `TRUENAS_AUTO_APPROVE` — set to `1`/`true` to skip interactive confirmation

### Decision logic:

This script follows a conservative, safety-first decision flow when deciding
which boot environments to keep and which to propose for deletion. High-level
rules summarized here mirror the actual logic implemented in
`truenas_prune_boot_environments.py` and help operators understand why an
environment was chosen to be kept or deleted.

- Health-first: if the boot pool reports an unhealthy state the script will
  suppress per-environment deletion suggestions for that host and mark the
  host as "pool unhealthy". No deletions are proposed or performed for that
  host until the pool's health is resolved.

- Warning suppression: if the pool reports a warning state (but not
  unhealthy) the script will, by default, suppress deletion proposals for
  that host. This can be overridden with `--override-warnings` or
  `TRUENAS_OVERRIDE_WARNINGS=1` when you understand the risk.

- Protected entries: any environment with `active==True`, `activated==True`,
  or explicitly `keep==True` is always preserved and never proposed for
  deletion. These entries form the "always keep" set and have top priority.

- Operator-specified minimum/maximum:
  - `--keep-minimum` / `TRUENAS_KEEP_MINIMUM` (default 8) is the highest-
    precedence operator control. The script will never propose deletions that
    reduce the total kept environments below this minimum.
  - `--keep-maximum` / `TRUENAS_KEEP_MAXIMUM` is a soft cap: the script will
    try to keep at most this many newest environments (excluding protected
    entries which may exceed the cap). The `keep-minimum` overrides this if
    set to a larger value.

- Free-space consideration (conservative default): when the pool reports
  sufficient free space (computed from `free` and `size` values) and no
  `--keep-maximum` was supplied, the script takes a conservative approach and
  will not propose deletions. This avoids unnecessary churn on healthy
  systems.

- Emergency free-space deletions: if the pool free-percent falls below the
  configured threshold (`--free-space-minimum` / `TRUENAS_FREE_SPACE_MINIMUM`,
  default 20.0%), the script will compute an emergency deletion set. It
  selects the oldest non-protected environments (smallest created timestamp)
  until the free-percent would exceed the threshold or until deleting any
  more would violate the `--keep-minimum` constraint. The oldest entries
  receive delete reasons like "oldest (free-space-minimum<=X%)".

- Selection tie-breaker and presentation: when choosing non-protected
  environments to keep, the script selects the newest ones first (newest
  chronological order), annotates why each environment is kept (for example
  `keep-minimum`, `keep-maximum`, or `active or flagged keep`), and presents
  both a compact summary (default) and a verbose listing (`-v`) so operators
  can inspect the exact rationale.

- Safety before action: the script never performs destructive actions without
  explicit operator approval. By default it prints a planned-changes summary
  and prompts for confirmation. Use `--auto-approve` or `TRUENAS_AUTO_APPROVE`
  to skip the prompt for automated runs.


## API Version Override:

You can override the API version the script uses by setting the `TRUENAS_API_VERSION` environment variable or passing `--api-version` on the command line. The default for the root script is `v25.10.0`. The compatibility copy in `v25.04/` defaults to `v25.04.2`.

## Troubleshooting:

This section lists common problems you might encounter when running the
scripts, likely causes, and suggested fixes.

- Problem: Authentication failed ("Authentication failed" or permission errors)
  - Likely cause: incorrect API token or insufficient permissions for the
    API key used.
  - Fix: verify the token value and that the user/extension has the
    required privileges. Rotate or re-create the API key if needed.

- Problem: Connection errors or timeouts
  - Likely cause: host unreachable, DNS failure, firewall blocking WebSocket,
    or wrong port.
  - Fix:
    1. Verify DNS / IP (ping or dig):

       ```bash
       ping -c 1 truenas.alpha.local
       ```

    2. Check port connectivity (replace host and port as appropriate):

       ```bash
       nc -vz truenas.alpha.local 443
       ```

    3. Ensure the TrueNAS Web UI/API is reachable and that the WebSocket
       endpoint is allowed through any firewalls.

- Problem: SSL verification or certificate errors
  - Likely cause: self-signed certificate or corporate TLS interception.
  - Fix: for environments where you control the network and accept the risk,
    set `verify_ssl: false` in your `inventory.yaml` or `TRUENAS_VERIFY_SSL_<n>=false`.
    For production, prefer installing the correct CA or using a valid cert.

Input formats accepted for the `url`/`TRUENAS_URL_<n>` fields:

- Bare hostname or IP: `truenas.local` or `192.168.1.5`
- Hostname/IP with port: `truenas.local:8443` or `192.168.1.5:8443`
- Full URL (scheme allowed): `https://truenas.local` or `http://192.168.1.5:80`

When a scheme is not provided the scripts default to secure WebSockets
(`wss://`). If you explicitly provide `http://` the script will use `ws://`.

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

## Disclaimer

Use these scripts at your own risk. They may perform destructive actions (for
example, `truenas_prune_boot_environments.py` can delete boot environments when
explicitly approved). Verify your configuration, ensure you have appropriate
backups, and test in a non-production environment before running these scripts
against production systems. No warranty is provided; the author and contributors
are not liable for any data loss or system damage resulting from use of these
utilities.

## Acknowledgements

This project was developed with assistance from GitHub Copilot. The tool suggested code and documentation snippets which were reviewed, edited, and tested by the author.