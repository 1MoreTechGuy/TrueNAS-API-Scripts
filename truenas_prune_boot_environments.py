"""
truenas_prune_boot_environments.py

Prune (suggest deletions for) TrueNAS boot environments.

Connect to one or more TrueNAS instances and query boot environment state using
`boot.get_state` via the JSON-RPC WebSocket API.

This script reuses the same inventory and environment variable patterns as the
existing TrueNAS API scripts in this repository and provides the same CLI
flags: -v/--verbose and --api-version.

Acknowledgement:
This file was created to match the project's existing scripts and conventions.

Edit-tracking: this file was edited to demonstrate the workflow that records
each edit in the repository todo list (see dev/ or the central task manager).
"""

# pylint: disable=too-few-public-methods

import asyncio
import json
import os
import ssl
from datetime import datetime, timezone
import re
from argparse import ArgumentParser
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlparse

import websockets  # pylint: disable=no-member
import yaml


@dataclass
class TrueNASHost:  # pylint: disable=too-few-public-methods
    """Dataclass representing a TrueNAS host configuration."""
    name: str
    url: str
    token: str
    verify_ssl: bool = False


class TrueNASBootInspector:
    """Inspector that connects to a TrueNAS host and queries boot state."""

    def __init__(self, host: TrueNASHost, api_version: str = 'v25.10.0'):
        self.host = host
        self.api_version = api_version.lstrip('/')
        self.ssl_context = self._create_ssl_context(host.verify_ssl)

        parsed = urlparse(host.url)
        if parsed.scheme:
            host_netloc = parsed.netloc or parsed.path
        else:
            host_netloc = host.url
        host_netloc = host_netloc.rstrip('/')

        ws_scheme = 'ws' if parsed.scheme == 'http' else 'wss'
        self.ws_url = f"{ws_scheme}://{host_netloc}/api/{self.api_version}"

    @staticmethod
    def _create_ssl_context(verify_ssl: bool = False) -> ssl.SSLContext:
        """Create an SSLContext based on verify_ssl flag.

        When verify_ssl is False the context will not verify certificates
        which is useful for local or self-signed TrueNAS instances.
        """
        if verify_ssl:
            return ssl.create_default_context()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def inspect_boot(self) -> Dict:
        """Open a websocket, authenticate, and fetch boot state and envs.

        Returns a dict with keys 'state' and 'environments'.
        """
        # websockets.connect is dynamically provided by the websockets package
        # pylint: disable=no-member
        async with websockets.connect(self.ws_url, ssl=self.ssl_context) as websocket:
            await self._authenticate(websocket)
            state = await self._get_boot_state(websocket)
            envs = await self._get_boot_environments(websocket)
            return {"state": state, "environments": envs}

    async def _authenticate(self, websocket) -> None:
        """Authenticate using the API key token for this host."""
        auth_msg = {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "auth.login_with_api_key",
            "params": [self.host.token]
        }
        await websocket.send(json.dumps(auth_msg))
        auth_result = json.loads(await websocket.recv())
        if 'error' in auth_result:
            raise RuntimeError(f"Authentication failed: {auth_result['error']}")

    async def _get_boot_state(self, websocket) -> Dict:
        """Call boot.get_state and return the result."""
        msg = {
            "id": 2,
            "jsonrpc": "2.0",
            "method": "boot.get_state",
            "params": []
        }
        await websocket.send(json.dumps(msg))
        return json.loads(await websocket.recv())

    async def _get_boot_environments(self, websocket) -> Dict:
        """Query boot.environment.query and request a small set of fields."""
        # Query boot environments and select only the fields requested by the user
        msg = {
            "id": 3,
            "jsonrpc": "2.0",
            "method": "boot.environment.query",
            "params": [[], {
                "select": ["id", "active", "activated", "created", "used_bytes", "keep"]
            }]
        }
        await websocket.send(json.dumps(msg))
        return json.loads(await websocket.recv())

    async def destroy_environments(self, env_ids: List[str]) -> Dict[str, dict]:
        """Destroy the given boot environment ids on this host.

        Returns a mapping of env_id -> response dict from the JSON-RPC call.
        This opens a fresh websocket, authenticates, then issues one
        boot.environment.destroy call per id, collecting results.
        """
        results = {}
        # Open a new websocket for destruction operations
        # websockets.connect is dynamically provided by the websockets package
        # and static analysis may not see it. Keep the pylint disable here.
        # pylint: disable=no-member
        async with websockets.connect(self.ws_url, ssl=self.ssl_context) as websocket:
            await self._authenticate(websocket)
            msg_id = 1000
            for eid in env_ids:
                # The middleware expects a dict/BootEnvironmentDestroyArgs rather
                # than a bare string. Pass the env id wrapped in the expected
                # parameter structure so the API's validator accepts it.
                call = {
                    "id": msg_id,
                    "jsonrpc": "2.0",
                    "method": "boot.environment.destroy",
                    # Pass a simple dict containing the id; the server will
                    # associate it with the 'boot_environment_destroy' arg name
                    # when validating against BootEnvironmentDestroyArgs.
                    "params": [{"id": eid}]
                }
                await websocket.send(json.dumps(call))
                try:
                    resp = json.loads(await websocket.recv())
                except (json.JSONDecodeError, ValueError, OSError) as err:  # network/recv errors
                    resp = {"error": str(err)}
                results[eid] = resp
                msg_id += 1
        return results


@dataclass
class KeepConfig:
    """Configuration for keep minimum and maximum values."""

    minimum: int
    maximum: Optional[int] = None


# Reuse inventory parsing from existing scripts

def get_truenas_config() -> List[TrueNASHost]:
    """Return a list of configured TrueNAS hosts from env or inventory file.

    Tries environment variables first, then the inventory file. Raises
    RuntimeError if no hosts are configured.
    """
    hosts = _get_hosts_from_env()
    if not hosts:
        hosts = _get_hosts_from_file()
    if not hosts:
        raise RuntimeError(
            "No configuration found. Set environment variables or provide an inventory file."
        )
    return hosts


def _get_hosts_from_env() -> List[TrueNASHost]:
    """Read TrueNAS host configuration from environment variables.

    Supports TRUENAS_URL_<n>, TRUENAS_TOKEN_<n>, TRUENAS_NAME_<n>, and
    TRUENAS_VERIFY_SSL_<n> for multiple instances.
    """
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
    """Load hosts from an inventory YAML file if present.

    The inventory file is expected to contain a top-level `hosts` list of
    mappings compatible with the TrueNASHost dataclass.
    """
    inventory_path = os.getenv('TRUENAS_INVENTORY', 'inventory.yaml')
    if os.path.exists(inventory_path):
        with open(inventory_path, 'r', encoding='utf-8') as f:
            inventory = yaml.safe_load(f)
            return [TrueNASHost(**host) for host in inventory.get('hosts', [])]
    return None


def _format_timestamp(val):
    """Format a Mongo-style or epoch-ms timestamp into ISO8601 in UTC.

    Always returns an ISO8601 timestamp with UTC timezone.
    """
    if isinstance(val, dict) and '$date' in val:
        try:
            ms = int(val['$date'])
            dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
            return dt.isoformat()
        except (ValueError, TypeError):
            return str(val)
    if isinstance(val, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(val) / 1000.0, tz=timezone.utc)
            return dt.isoformat()
        except (ValueError, TypeError):
            return str(val)
    return str(val)


def _created_ms(val):
    """Return created timestamp in epoch-ms or None.

    Accepts Mongo-style {'$date': ms}, numeric epoch-ms, or ISO string.
    """
    if isinstance(val, dict) and '$date' in val:
        try:
            return int(val['$date'])
        except (ValueError, TypeError):
            return None
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val)
            return int(dt.timestamp() * 1000)
        except (ValueError, TypeError):
            return None
    return None


def _parse_bytes(v):
    """Parse a bytes value which may be int, numeric string, or human-readable like '10G'."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str):
        try:
            return int(v)
        except (ValueError, TypeError):
            pass
        m = re.match(r'^([\d\.]+)\s*([KMGTPE]?)(i?B)?$', v.strip(), re.I)
        if m:
            num = float(m.group(1))
            unit = m.group(2).upper()
            mul = 1
            if unit == 'K':
                mul = 1024
            elif unit == 'M':
                mul = 1024 ** 2
            elif unit == 'G':
                mul = 1024 ** 3
            elif unit == 'T':
                mul = 1024 ** 4
            elif unit == 'P':
                mul = 1024 ** 5
            return int(num * mul)
    return None


def _parse_size_to_bytes(v):
    """Parse free/size values into bytes (returns float) or None.

    Accepts numeric types, numeric strings, or human-readable sizes.
    """
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except (ValueError, TypeError):
            pass
        m = re.match(r'^([\d\.]+)\s*([KMGTPE]?)(i?B)?$', v.strip(), re.I)
        if m:
            num = float(m.group(1))
            unit = m.group(2).upper()
            mul = 1
            if unit == 'K':
                mul = 1024
            elif unit == 'M':
                mul = 1024 ** 2
            elif unit == 'G':
                mul = 1024 ** 3
            elif unit == 'T':
                mul = 1024 ** 4
            elif unit == 'P':
                mul = 1024 ** 5
            return num * mul
    return None


def _sort_env_items_newest_first(env_items: List[dict]) -> List[dict]:
    """Return env_items sorted by created timestamp (newest first).

    This helper is small and reduces complexity in the main flow.
    """
    try:
        return sorted(env_items, key=lambda x: _created_ms(x.get('created')) or 0, reverse=True)
    except (TypeError, ValueError):
        return env_items


def _build_env_meta(env_items: List[dict]) -> List[dict]:
    """Build metadata list for each environment entry.

    Each entry includes id, active, activated, keep, created_ms and used_bytes.
    """
    meta = []
    for e in env_items:
        if not isinstance(e, dict):
            continue
        ub = e.get('used_bytes')
        meta.append({
            'id': e.get('id'),
            'active': bool(e.get('active')),
            'activated': bool(e.get('activated')),
            'keep': bool(e.get('keep')),
            'created_ms': _created_ms(e.get('created')),
            'used_bytes': _parse_bytes(ub)
        })
    return meta


def _compute_pool_free_pct(items: List[dict]) -> Optional[float]:
    """Compute pool free percentage from the first item if possible."""
    try:
        pool_picked = _pick_fields(items[0] if items else {})
        free_val = pool_picked.get('free')
        size_val = pool_picked.get('size')
        free_num = _parse_size_to_bytes(free_val)
        size_num = _parse_size_to_bytes(size_val)
        if free_num is not None and size_num:
            if size_num > 0:
                return (float(free_num) / float(size_num)) * 100.0
    except (ValueError, TypeError):
        return None
    return None


def _is_unhealthy(h) -> bool:
    """Return True if the healthy field indicates the pool is unhealthy."""
    if h is None:
        return False
    if isinstance(h, bool):
        return h is False
    if isinstance(h, str):
        return h.strip().lower() in ('false', '0', 'no')
    if isinstance(h, (int, float)):
        return int(h) == 0
    return False


def _is_warning(w) -> bool:
    """Return True if the warning field indicates a warning state."""
    if w is None:
        return False
    if isinstance(w, bool):
        return w is True
    if isinstance(w, str):
        return w.strip().lower() in ('true', '1', 'yes')
    if isinstance(w, (int, float)):
        return int(w) != 0
    return False


def _sort_newest_first_ids(ids: List[str], env_meta: List[dict]) -> List[str]:
    """Sort ids by created_ms using env_meta (newest first)."""
    id_to_meta = {x['id']: x for x in env_meta if x.get('id') is not None}

    def keyfn(i):
        m = id_to_meta.get(i, {})
        return -(m.get('created_ms') or 0)

    return sorted(ids, key=keyfn)


def _compute_suggestions(env_meta: List[dict], items: List[dict], keep_minimum: int,
                         keep_maximum: Optional[int], _override_warnings: bool, args) -> tuple:
    """Compute proposed keep/delete sets for a given host.

    Returns a tuple (proposed_keep, proposed_delete, keep_reasons).
    This function implements conservative defaults: free-space only
    short-circuits (keeping everything) when the operator did not request
    a keep_maximum. Emergency free-space deletions are handled in
    _check_health_and_emergency.
    """
    all_ids = [x['id'] for x in env_meta if x.get('id') is not None]

    pool_free_pct = _compute_pool_free_pct(items)
    pool_picked = _get_pool_picked(items)

    # Centralize health and emergency free-space checks into a small helper
    # Health/emergency check must be aware of the operator-requested
    # keep_minimum so emergency deletions never reduce kept envs below
    # the explicit minimum the operator requested (highest precedence).
    health_result = _check_health_and_emergency(pool_picked, pool_free_pct, args,
                                                env_meta, keep_minimum)
    if health_result is not None:
        # health_result is (keep_set, delete_set, keep_reasons, delete_reasons)
        return health_result

    # Compute whether the pool appears to have sufficient free space; this
    # flag is only used to avoid proposing deletions when the operator did
    # not request a maximum (conservative behavior).
    free_space_minimum = _determine_free_space_minimum(args)
    try:
        free_space_ok = (
            pool_free_pct is not None
            and float(pool_free_pct) >= float(free_space_minimum)
        )
    except (TypeError, ValueError):
        free_space_ok = False

    # If the pool has sufficient free space and the operator didn't request
    # a maximum, keep everything (no deletions). This keeps the behavior
    # conservative by default.
    if keep_maximum is None and free_space_ok:
        return set(all_ids), set(), {}, {}

    # Normal selection logic: always preserve protected entries and then
    # pick newest non-protected entries up to the desired target. To keep
    # the function small and linter-friendly we delegate the desired-count
    # selection and the keep-reason construction to small helpers below.
    always_keep = _compute_always_keep(env_meta)

    proposed_keep, selected_from_candidates, rule = _compute_desired_and_selected(
        env_meta, always_keep, keep_minimum, keep_maximum
    )

    keep_reasons = _build_keep_reasons(always_keep, selected_from_candidates, rule)

    # Normal path: no specific delete_reasons computed
    delete_reasons = {}
    return proposed_keep, set(all_ids) - proposed_keep, keep_reasons, delete_reasons


def _get_pool_picked(items: List[dict]) -> dict:
    """Safely pick pool-level fields from items[0] or return empty dict."""
    try:
        return _pick_fields(items[0] if items else {})
    except (TypeError, ValueError, KeyError):
        return {}


def _check_health_and_emergency(pool_picked: dict, pool_free_pct: Optional[float],
                                args, env_meta: List[dict], keep_minimum: int) -> Optional[tuple]:
    """Return (proposed_keep, proposed_delete) or None to continue.

    If the pool is unhealthy or free-percent info is missing, return a keep-all
    result. If free-percent is below threshold, return an emergency selection.
    Otherwise return None to indicate normal processing should continue.
    """
    if _is_unhealthy(pool_picked.get('healthy')):
        all_ids = [x['id'] for x in env_meta if x.get('id') is not None]
        return set(all_ids), set(), {}, {}

    free_space_minimum = _determine_free_space_minimum(args)
    if pool_free_pct is None:
        all_ids = [x['id'] for x in env_meta if x.get('id') is not None]
        return set(all_ids), set(), {}, {}

    if pool_free_pct < float(free_space_minimum):
        free_num = _parse_size_to_bytes(pool_picked.get('free'))
        size_num = _parse_size_to_bytes(pool_picked.get('size'))
        if free_num is None or size_num is None:
            all_ids = [x['id'] for x in env_meta if x.get('id') is not None]
            return set(all_ids), set(), {}, {}
        ek_keep, ek_delete, ek_delete_reasons = _select_emergency_deletions(
            env_meta, float(free_num), float(size_num), float(free_space_minimum), keep_minimum
        )
        # Build keep reasons for anything forced kept (active/keep)
        kr = {x: 'active or marked keep' for x in _compute_always_keep(env_meta)}
        return ek_keep, ek_delete, kr, ek_delete_reasons
    return None


def _select_newest_non_protected_ids(newest: List[dict], always_keep: set) -> List[str]:
    """Return list of ids for newest non-protected envs (newest first)."""
    ids = []
    for x in newest:
        if x.get('id') is None:
            continue
        if x.get('id') in always_keep:
            continue
        ids.append(x.get('id'))
    return ids


def _compute_desired_and_selected(env_meta: List[dict], always_keep: set,
                                  keep_minimum: int, keep_maximum: Optional[int]):
    """Compute desired_total and return (proposed_keep, selected_ids, rule).

    proposed_keep is the set of ids that should be kept. selected_ids are the
    non-protected ids chosen to meet the desired_total (newest-first). rule is
    a string 'keep-minimum' or 'keep-maximum' indicating which constraint was
    effective.
    """
    newest = sorted(env_meta, key=lambda x: x.get('created_ms') or 0, reverse=True)
    total_envs = len(newest)
    if keep_maximum is None:
        desired_total = max(keep_minimum, len(always_keep))
    else:
        desired_total = max(keep_minimum, min(keep_maximum, total_envs))

    candidate_ids = _select_newest_non_protected_ids(newest, always_keep)
    num_needed = max(0, desired_total - len(always_keep))
    selected_from_candidates = list(candidate_ids[:num_needed])

    proposed_keep = always_keep | set(selected_from_candidates)
    if keep_maximum is None:
        rule = 'keep-minimum'
    else:
        rule = 'keep-maximum' if desired_total != keep_minimum else 'keep-minimum'
    return proposed_keep, selected_from_candidates, rule


def _build_keep_reasons(always_keep: set, selected_from_candidates: List[str], rule: str) -> dict:
    """Construct keep_reasons mapping for protected and selected ids."""
    keep_reasons = {x: 'active or marked keep' for x in always_keep}
    min_not_met = (rule == 'keep-minimum') and (len(selected_from_candidates) > 0)
    for sid in selected_from_candidates:
        reason = rule
        if min_not_met:
            reason = f"{rule}"
        keep_reasons[sid] = reason
    return keep_reasons


def _determine_free_space_minimum(args) -> float:
    """Determine free space minimum from CLI args or env var (default 20.0)."""
    ft_env = os.getenv('TRUENAS_FREE_SPACE_MINIMUM')
    free_space_minimum = 20.0
    if getattr(args, 'free_space_minimum', None) is not None:
        try:
            free_space_minimum = float(args.free_space_minimum)
        except (TypeError, ValueError):
            free_space_minimum = 20.0
    elif ft_env:
        try:
            free_space_minimum = float(ft_env)
        except (TypeError, ValueError):
            free_space_minimum = 20.0
    return free_space_minimum


def determine_keep_minimum(args) -> int:
    """Determine keep minimum from CLI args or env var (default 8).

    The keep-minimum must be at least 1.
    """
    keep_env = os.getenv('TRUENAS_KEEP_MINIMUM')
    keep_min = 8
    if getattr(args, 'keep_minimum', None) is not None:
        try:
            keep_min = int(args.keep_minimum)
        except (ValueError, TypeError):
            keep_min = 8
    elif keep_env:
        try:
            keep_min = int(keep_env)
        except (TypeError, ValueError):
            keep_min = 8
    keep_min = max(keep_min, 1)
    return keep_min


def determine_keep_maximum(args) -> Optional[int]:
    """Determine keep maximum from CLI args or env var (default None).

    If set, must be >= 1. If unspecified, returns None (no maximum).
    """
    keep_env = os.getenv('TRUENAS_KEEP_MAXIMUM')
    if getattr(args, 'keep_maximum', None) is not None:
        try:
            km = int(args.keep_maximum)
        except (ValueError, TypeError):
            km = None
    elif keep_env:
        try:
            km = int(keep_env)
        except (TypeError, ValueError):
            km = None
    else:
        km = None
    if km is not None and km < 1:
        km = 1
    return km


async def inspect_all_hosts(inventory: List[TrueNASHost], api_version: str):
    """Inspect all hosts and return (results, inspectors).

    results: mapping host_name -> state. inspectors: mapping host_name -> inspector.
    """
    results = {}
    inspectors = {}
    for host in inventory:
        if not host.url or not host.token:
            continue
        inspector = TrueNASBootInspector(host, api_version=api_version)
        inspectors[host.name] = inspector
        state = await inspector.inspect_boot()
        results[host.name] = state
    return results, inspectors


def _print_delete_plan(delete_plan: Dict) -> None:
    """Print a concise summary of planned deletions for confirmation."""
    print('\n\nPlanned Changes Summary:')
    for hn, plan in delete_plan.items():
        host_state = plan.get('state')
        override = plan.get('override_warnings')
        env_meta, to_keep, to_delete = _extract_plan_lists(plan)
        keep_count = len(to_keep) if to_keep is not None else 0
        delete_count = len(to_delete) if to_delete is not None else 0
        # add a visible space before DELETE for readability
        # Always show counts even when the pool reports unhealthy or
        # warning states so operators can quickly see the proposed change
        # sizes. Individual env listings will be suppressed for unhealthy
        # pools but we'll still show a small sample of kept IDs.
        # show totals as: Host (KEEP=X DELETE=Y):
        print(f"\n{hn} (KEEP={keep_count} DELETE={delete_count}):")
        host_reasons = _host_reasons_from_state(host_state, override)

        # If the pool is unhealthy, show the counts and a concise ERROR
        # message with status_code/status_detail on separate lines, then
        # continue without listing env-level actions.
        if host_reasons and any(r == 'pool unhealthy' for r in host_reasons):
            picked = _pick_fields(host_state if isinstance(host_state, dict) else {})
            status_code = picked.get('status_code')
            status_detail = picked.get('status_detail')
            # show any warning/notes alongside the error
            if host_reasons:
                print(f"  Host notes: {', '.join(host_reasons)}")
            print(
                '  ERROR: Boot Pool Unhealthy — No actions will be performed '
                'against this host. Resolve pool health issues to proceed.'
            )
            if status_code is not None:
                print(f'  status_code: {status_code}')
            if status_detail:
                print(f'  status_detail: {status_detail}')

            # show a small sample of kept IDs so operators see what's preserved
            sample_kept = _sort_newest_first_ids(list(to_keep), env_meta)[:3]
            if sample_kept:
                sample_str = ', '.join(sample_kept)
                suffix = ', ...' if len(to_keep) > 3 else ''
                print(
                    f"  { _emoji('keep') } KEEP (sample): " + sample_str + suffix
                )
            continue

        # For non-unhealthy hosts, show any host notes (including warnings)
        if host_reasons:
            print(f"  Host notes: {', '.join(host_reasons)}")

        keep_reasons = plan.get('keep_reasons') or {}
        delete_reasons = plan.get('delete_reasons') or {}
        _print_keep_items(env_meta, to_keep, keep_reasons)
        _print_delete_section(env_meta, to_delete, delete_reasons)


def _emoji(kind: str) -> str:
    """Return a small emoji for the given kind (keep, delete, note)."""
    return {
        'keep': '✅',
        'delete': '🗑️',
        'note': '⚠️',
    }.get(kind, '')


def _relative_age(created_ms: Optional[int]) -> str:
    """Return a short relative age like '2d', '3h', '5m' or 'now'."""
    if not created_ms:
        return ''
    try:
        now_ms = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
        delta_ms = max(0, now_ms - int(created_ms))
        secs = delta_ms // 1000
        if secs < 60:
            return 'now'
        mins = secs // 60
        if mins < 60:
            return f"{mins}m"
        hours = mins // 60
        if hours < 24:
            return f"{hours}h"
        days = hours // 24
        return f"{days}d"
    except (OverflowError, ValueError):
        # If timestamp math fails return an empty age string. Allow
        # KeyboardInterrupt/SystemExit to propagate.
        return ''


def _print_summary_plan(delete_plan: Dict) -> None:
    """Print a concise, human-first summary.

    For each host show a short header, any host notes, a small sample of kept
    IDs to indicate what's preserved, and concise delete lines with relative
    age and reason. This keeps the output readable for humans while still
    providing the key actions.
    """
    print('\nPlanned changes summary:')
    for hn, plan in delete_plan.items():
        host_state = plan.get('state')
        override = plan.get('override_warnings')
        env_meta, to_keep, to_delete = _extract_plan_lists(plan)
        keep_count = len(to_keep) if to_keep is not None else 0
        delete_count = len(to_delete) if to_delete is not None else 0
        notes = _host_reasons_from_state(host_state, override)

        # If the pool is unhealthy, show counts and the error details but do
        # not attempt to list per-environment deletions or samples. Print a
        # clear single-line message that no action will be taken for this
        # host to avoid any accidental destructive guidance.
        if notes and any(r == 'pool unhealthy' for r in notes):
            picked = _pick_fields(host_state if isinstance(host_state, dict) else {})
            status_code = picked.get('status_code')
            status_detail = picked.get('status_detail')
            # show totals as: Host (KEEP=X DELETE=Y): and note it's unhealthy
            print(f"\n  {hn} (KEEP={keep_count} DELETE={delete_count}):")
            print(f"  {_emoji('note')} Boot Pool Unhealthy")
            if status_code is not None:
                print(f'  status_code: {status_code}')
            if status_detail:
                print(f'  status_detail: {status_detail}')
            # Explicitly state that no action will be taken for this host
            print(
                '    No actions will be performed against this host due to boot pool '
                'health; investigate and retry.'
            )
            continue

        # Short header for healthy or warning hosts
        note_part = f" { _emoji('note') } {' '.join(notes)}" if notes else ''
        # add an extra space before DELETE for consistent visual separation
        # show totals as: Host (KEEP=X DELETE=Y):
        print(f"\n  {hn} (KEEP={keep_count} DELETE={delete_count}):{note_part}")

        # Small sample of kept IDs (up to 3) to show what's preserved
        sample_kept = _sort_newest_first_ids(list(to_keep), env_meta)[:3]
        if sample_kept:
            sample_str = ', '.join(sample_kept)
            suffix = ', ...' if len(to_keep) > 5 else ''
            print(f"    { _emoji('keep') } KEEP: " + sample_str + suffix)

        # Concise delete lines: id — age — reason
        if not to_delete:
            print('    🚫 No deletions proposed')
        else:
            for did in _sort_newest_first_ids(list(to_delete), env_meta):
                m = next((x for x in env_meta if x.get('id') == did), {})
                dreason = plan.get('delete_reasons', {}).get(did) or 'oldest'
                age = _relative_age(m.get('created_ms'))
                print(f"    { _emoji('delete') } \u0020DELETE {did} — {age} — {dreason}")


def _extract_plan_lists(plan: Dict) -> tuple:
    """Return (env_meta, to_keep_set, to_delete_set) from a plan dict."""
    env_meta = plan.get('env_meta') or []
    to_keep = set(plan.get('to_keep') or [])
    to_delete = set(plan.get('to_delete') or [])
    return env_meta, to_keep, to_delete


def _determine_keep_reason(m: dict) -> str:
    """Return a short reason string for keeping an env entry."""
    if not m:
        return 'no metadata'
    if m.get('active') or m.get('activated') or m.get('keep'):
        return 'active or flagged keep'
    # Annotate newest with 'non-protected' when the entry lacks protective flags
    return 'newest (non-protected)'


def _print_keep_items(
    env_meta: List[dict],
    to_keep: set,
    keep_reasons: Optional[dict] = None,
) -> None:
    """Print KEEP items with reasons and metadata."""
    print("\n  KEEP: (id - reason - created - used_bytes)")
    for kid in _sort_newest_first_ids(list(to_keep), env_meta):
        m = next((x for x in env_meta if x.get('id') == kid), {})
        # Prefer explicitly computed reasons, fall back to attribute-based reason
        reason = None
        if keep_reasons and kid in keep_reasons:
            reason = keep_reasons.get(kid)
        if not reason:
            reason = _determine_keep_reason(m)
        created = _format_timestamp(m.get('created_ms')) if m.get('created_ms') else ''
        used = m.get('used_bytes')
        print(f"    - {kid} - {reason} - {created} - {used}")


def _print_delete_items(
    env_meta: List[dict],
    to_delete: set,
    delete_reasons: Optional[dict] = None,
) -> None:
    """Print DELETE items with reasons and metadata."""
    # This function prints just the delete items (without header). Use
    # _print_delete_section() when you want the header printed as well.
    for did in _sort_newest_first_ids(list(to_delete), env_meta):
        m = next((x for x in env_meta if x.get('id') == did), {})
        reason = None
        if delete_reasons and did in delete_reasons:
            reason = delete_reasons.get(did)
        if not reason:
            reason = 'oldest (non-protected)'
        created = _format_timestamp(m.get('created_ms')) if m.get('created_ms') else ''
        used = m.get('used_bytes')
        print(f"    - {did} - {reason} - {created} - {used}")


def _print_delete_section(
    env_meta: List[dict],
    to_delete: set,
    delete_reasons: Optional[dict] = None,
) -> None:
    """Print the DELETE header and either the items or a no-action message."""
    print("\n  DELETE: (id - reason - created - used_bytes)")
    if not to_delete:
        print("      🚫 no deletions proposed")
        return
    _print_delete_items(env_meta, to_delete, delete_reasons)


def _host_reasons_from_state(host_state: object, override: bool) -> List[str]:
    """Return a list of host-level reason strings from a state object.

    Keeps logic small to avoid inflating locals in callers.
    """
    picked = _pick_fields(host_state if isinstance(host_state, dict) else {})
    reasons = []
    healthy = picked.get('healthy')
    warning = picked.get('warning')
    status_detail = picked.get('status_detail')
    if _is_unhealthy(healthy):
        reasons.append('pool unhealthy')
    if _is_warning(warning) and not override:
        reasons.append('pool reported warning (deletions suppressed)')
    if status_detail:
        reasons.append(f"detail: {status_detail}")
    return reasons


def _compute_always_keep(env_meta: List[dict]) -> set:
    """Return set of ids that must always be kept (active/activated/keep)."""
    return {
        x['id'] for x in env_meta
        if x.get('id') is not None and (x.get('active') or x.get('activated') or x.get('keep'))
    }


def _select_emergency_deletions(env_meta: List[dict], free_num: float, size_num: float,
                                free_space_minimum: float, keep_minimum: int) -> (set, set, dict):
    """Select oldest non-protected envs until free% > free_space_minimum.

    Returns (proposed_keep, proposed_delete).
    """
    remaining_free = float(free_num)
    total_size = float(size_num)
    deletable = [
        x for x in env_meta
        if not (x.get('active') or x.get('activated') or x.get('keep'))
        and x.get('id') is not None
    ]
    deletable_sorted = sorted(deletable, key=lambda x: x.get('created_ms') or 0)
    to_delete = []
    total_envs = len([x for x in env_meta if x.get('id') is not None])
    # Compute the maximum number of deletable envs while preserving
    # the operator-requested keep_minimum (do not delete below this).
    max_deletable = max(0, total_envs - max(keep_minimum, len(_compute_always_keep(env_meta))))
    deleted_count = 0
    for cand in deletable_sorted:
        used = cand.get('used_bytes') or 0
        remaining_free += used
        current_pct = ((remaining_free / total_size) * 100.0 if total_size > 0 else 0.0)
        # Stop if deleting this candidate would exceed the maximum allowed
        # deletions (to preserve keep_minimum), otherwise record it.
        if deleted_count >= max_deletable:
            break
        to_delete.append(cand['id'])
        deleted_count += 1
        if current_pct > float(free_space_minimum):
            break

    proposed_delete = set(to_delete)
    all_ids = [x['id'] for x in env_meta if x.get('id') is not None]
    proposed_keep = set(all_ids) - proposed_delete

    # Annotate delete reasons: oldest deletions are due to free-space emergency
    delete_reasons = {
        did: f"oldest (free-space-minimum<={free_space_minimum}%)"
        for did in proposed_delete
    }
    return proposed_keep, proposed_delete, delete_reasons


# Fields to extract from boot.get_state wrapper results
DESIRED_FIELDS = [
    'name', 'status', 'healthy', 'warning',
    # prefer 'status_code' (accept older 'statu_code' as fallback)
    'status_code', 'status_detail', 'size', 'allocated', 'free',
]


def _extract_items(result):
    """Normalize different possible API shapes into a list of items."""
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        # common wrapper patterns
        if 'items' in result and isinstance(result['items'], list):
            return result['items']
        # find first value that's a list of dicts
        for v in result.values():
            if isinstance(v, list) and v and all(isinstance(i, dict) for i in v):
                return v
        # treat as single dict representing one item
        return [result]
    # otherwise return a single-item list with the raw result
    return [result]


def _print_items(items: List[dict]) -> None:
    """Print picked DESIRED_FIELDS for a list of items."""
    for item in items:
        picked = _pick_fields(item if isinstance(item, dict) else {})
        for k in DESIRED_FIELDS:
            print(f"  {k}: {picked.get(k)}")
        print()


def _get_env_items_from_state(state) -> List[dict]:
    """Extract environment items payload from state/environments polymorphic shapes."""
    envs = state.get('environments') if isinstance(state, dict) else None
    if envs is None and isinstance(state, dict):
        envs = state.get('environments')
    if not envs:
        return []
    if isinstance(envs, dict) and 'result' in envs:
        return envs['result']
    if isinstance(envs, list):
        return envs
    return []


def _print_envs(host_name: str, env_items: List[dict]) -> None:
    """Print boot environment entries in a human friendly format."""
    if not env_items:
        return
    print(f"{host_name} Boot Environments:")
    env_items_sorted = _sort_env_items_newest_first(env_items)
    for e in env_items_sorted:
        if not isinstance(e, dict):
            continue
        eid = e.get('id')
        active = e.get('active')
        activated = e.get('activated')
        created = e.get('created')
        used_bytes = e.get('used_bytes')
        keep = e.get('keep')
        created_str = _format_timestamp(created)
        print(f"  - id: {eid}")
        print(f"    active: {active}")
        print(f"    activated: {activated}")
        print(f"    created: {created_str}")
        print(f"    used_bytes: {used_bytes}")
        print(f"    keep: {keep}")


def _find_key(d, key):
    """Recursively find a key in nested dicts/lists and return its value."""
    if not isinstance(d, dict):
        return None
    if key in d:
        return d[key]
    for v in d.values():
        if isinstance(v, dict):
            res = _find_key(v, key)
            if res is not None:
                return res
        elif isinstance(v, list):
            for el in v:
                if isinstance(el, dict):
                    res = _find_key(el, key)
                    if res is not None:
                        return res
    return None


def _pick_fields(item: dict):
    """Pick a small set of fields from an API item using DESIRED_FIELDS."""
    out = {}
    for f in DESIRED_FIELDS:
        if f == 'status_code':
            out['status_code'] = _find_key(item, 'status_code') or _find_key(item, 'statu_code')
        else:
            out[f] = _find_key(item, f)
    return out


def _process_host(host_name: str, state, args, keep_cfg: KeepConfig, override_warnings: bool):
    """Process a single host and return computed suggestion sets.

    Printing of detailed boot-pool and environment information is limited to
    verbose mode (`args.verbose == True`). The compact summary/printer will
    surface only the changes by default.
    """
    if isinstance(state, dict) and 'error' in state:
        if getattr(args, 'verbose', False):
            print(f"\n\n{host_name}:")
            print(f"  Error: {state['error']}")
        return None

    if isinstance(state, dict) and 'result' in state:
        items = _extract_items(state['result'])
    else:
        items = _extract_items(state)

    if not items:
        if getattr(args, 'verbose', False):
            print(f"\n\n{host_name}:")
            print("  (no boot entries returned)")
        return None

    # Only print pool/item details in verbose mode
    if getattr(args, 'verbose', False):
        print(f"\n\n{host_name}:")
        _print_items(items)

    # Also extract boot environments (if returned)
    envs = state.get('environments') if isinstance(state, dict) else None
    if envs is None and isinstance(state, dict):
        envs = state.get('environments')

    if envs:
        env_items = _get_env_items_from_state(state)
        if getattr(args, 'verbose', False):
            _print_envs(host_name, env_items)

        # Prepare env metadata and compute suggestions
        env_meta = _build_env_meta(env_items)
        proposed_keep, proposed_delete, keep_reasons, delete_reasons = _compute_suggestions(
            env_meta, items, keep_cfg.minimum, keep_cfg.maximum, override_warnings, args
        )
        return env_meta, proposed_keep, proposed_delete, keep_reasons, delete_reasons

    return None


async def main() -> None:
    """Entry point: parse CLI and inspect configured TrueNAS hosts."""
    parser = ArgumentParser(description='TrueNAS Boot Inspector')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose output')
    parser.add_argument('--api-version', dest='api_version', default=None,
                        help='Override the TrueNAS API version to use (e.g. v25.10.0)')
    parser.add_argument(
        '--override-warnings', dest='override_warnings', action='store_true',
        help=(
            'Allow proposing deletions even if the boot pool reports warning==True. '
            'Can also set TRUENAS_OVERRIDE_WARNINGS=1'
        ),
    )
    parser.add_argument(
        '--keep-minimum', dest='keep_minimum', type=int, default=None,
        help=(
            'Minimum number of newest boot environments to keep (default 8). '
            'Must be >=1. Can also set TRUENAS_KEEP_MINIMUM env var'
        ),
    )
    parser.add_argument(
        '--keep-maximum', dest='keep_maximum', type=int, default=None,
        help=(
            'Maximum number of newest boot environments to keep. This is a soft '
            'limit: entries with active/activated/keep flags will always be preserved '
            'even if they exceed the maximum. Can also set TRUENAS_KEEP_MAXIMUM env var'
        ),
    )
    parser.add_argument(
        '--free-space-minimum', dest='free_space_minimum', type=float, default=None,
        help=(
            'Minimum free percent on boot pool before emergency deletions are considered '
            '(default 20.0). Can also set TRUENAS_FREE_SPACE_MINIMUM env var'
        ),
    )
    parser.add_argument(
        '--auto-approve', dest='auto_approve', action='store_true',
        help='Automatically approve and perform deletions without prompting.'
    )

    args = parser.parse_args()

    try:
        inventory = get_truenas_config()
        api_version = (
            args.api_version or os.getenv('TRUENAS_API_VERSION') or 'v25.10.0'
        )
        override_warnings = (
            args.override_warnings
            or os.getenv('TRUENAS_OVERRIDE_WARNINGS') in ('1', 'true', 'yes')
        )
        # Auto-approve can be supplied via CLI flag or TRUENAS_AUTO_APPROVE env var
        auto_approve_env = os.getenv('TRUENAS_AUTO_APPROVE')
        auto_approve = (
            args.auto_approve or (auto_approve_env is not None and
                                  str(auto_approve_env).lower() in ('1', 'true', 'yes'))
        )

        # Determine keep minimum/maximum and inspect hosts
        keep_minimum = determine_keep_minimum(args)
        keep_maximum = determine_keep_maximum(args)
        keep_cfg = KeepConfig(minimum=keep_minimum, maximum=keep_maximum)
        results, inspectors = await inspect_all_hosts(inventory, api_version)

        # Build the combined plan (deletions + notes-only) and prompt the user
        combined_plan = _build_combined_plan(
            results, inspectors, args, keep_cfg, override_warnings
        )
        if combined_plan:
            # Determine whether to use verbose (detailed) output or the
            # compact changes-only summary. The compact view is the default
            # because it helps operators quickly see what will change;
            # use -v/--verbose for the previous detailed output.
            any_deletions = any(bool(p.get('to_delete')) for p in combined_plan.values())
            if not any_deletions:
                if args.verbose:
                    _print_delete_plan(combined_plan)
                else:
                    _print_summary_plan(combined_plan)
                print('\nNo deletion actions proposed for any hosts; exiting.')
                return

            # Print the selected view before confirming/executing deletions
            if args.verbose:
                _print_delete_plan(combined_plan)
            else:
                _print_summary_plan(combined_plan)

            await _confirm_and_execute_deletions(combined_plan, auto_approve)

    except Exception as e:  # pylint: disable=broad-except
        # Non-fatal runtime errors are reported to the user; allow system
        # exceptions like KeyboardInterrupt to propagate.
        print(f"\nError: {str(e)}")


def _build_combined_plan(results: Dict, inspectors: Dict, args, keep_cfg: KeepConfig,
                         override_warnings: bool) -> Dict:
    """Build combined plan of deletions and notes-only hosts.

    Extracted from main to reduce local variable count in the main function
    (addresses pylint R0914). Returns a dict mapping host_name -> plan.
    """
    combined_plan = {}
    for host_name, state in results.items():
        proc = _process_host(host_name, state, args, keep_cfg, override_warnings)
        if not proc:
            continue
        env_meta, proposed_keep, proposed_delete, keep_reasons, delete_reasons = proc
        if not env_meta:
            continue
        # Always include the host in the combined plan so the summary can
        # explicitly state when no deletion actions are proposed.
        combined_plan[host_name] = {
            'inspector': inspectors.get(host_name),
            'env_meta': env_meta,
            'to_delete': proposed_delete or set(),
            'to_keep': proposed_keep,
            'keep_reasons': keep_reasons,
            'delete_reasons': delete_reasons,
            'state': state,
            'override_warnings': override_warnings,
        }

    return combined_plan


async def _confirm_and_execute_deletions(delete_plan: Dict, auto_approve: bool) -> None:
    """Prompt for confirmation (unless auto_approve) and execute deletions.

    delete_plan is a mapping of host_name -> {inspector, env_meta, to_delete, to_keep}.
    """
    # The plan should already have been printed by the caller (either the
    # compact or verbose view). Do not re-print it here to avoid duplicated
    # 'Planned changes summary' sections.
    proceed = auto_approve
    if not proceed:
        ans = input('\nProceed with deletions? [y/N]: ').strip().lower()
        proceed = ans in ('y', 'yes')

    if not proceed:
        print('\nDeletion cancelled by user.')
        return
    # Execute deletions per-host and collect results to present an actions
    # summary after all operations complete.
    actions_performed = {}
    for hn, plan in delete_plan.items():
        inspector = plan['inspector']
        to_delete = list(plan['to_delete'])
        if not to_delete:
            actions_performed[hn] = {'deleted': [], 'errors': {}}
            continue

        print(f"\nDeleting on host {hn}: {len(to_delete)} environments")
        try:
            results = await inspector.destroy_environments(to_delete)
        except RuntimeError as err:
            print(f"  Error performing deletions on {hn}: {err}")
            actions_performed[hn] = {'deleted': [], 'errors': {'__host__': str(err)}}
            continue
        except OSError as err:
            print(f"  Network error performing deletions on {hn}: {err}")
            actions_performed[hn] = {'deleted': [], 'errors': {'__host__': str(err)}}
            continue

        deleted = []
        errors = {}
        for eid, resp in results.items():
            if isinstance(resp, dict) and 'error' in resp:
                print(f"  {eid}: ERROR: {resp['error']}")
                errors[eid] = resp['error']
            else:
                print(f"  {eid}: deleted (response id={resp.get('id')})")
                deleted.append(eid)

        actions_performed[hn] = {'deleted': deleted, 'errors': errors}

    # Print concise actions-performed summary
    print('\nActions performed:')
    for hn, act in actions_performed.items():
        dels = act.get('deleted', [])
        errs = act.get('errors', {})
        print(f"\n  {hn}: deleted={len(dels)} errors={len(errs)}")
        if not dels:
            print("    🚫 No deletions")
        for d in dels:
            print(f"    { _emoji('delete') } \u0020{d}")
        for eid, err in errs.items():
            if eid == '__host__':
                print(f"    { _emoji('note') } \u0020HOST ERROR: {err}")
            else:
                print(f"    { eid }: ERROR: {err}")


if __name__ == '__main__':
    asyncio.run(main())
