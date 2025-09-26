# backend/flask_app/data_aggregator/apigee_loaders.py
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import os
import time
import requests

from .utils.apigee_constants import ENV_OBJ_DICT, SPLUNK_API_BY_ENV
from .utils.apigee_utils import (
    initialize_apigee_obj,
    fetch_apigee_xml_data,
    get_policy_analysis_dict,
    get_virtual_host_analysis_dict,
)

# ----------------------- Small helpers -----------------------

def _security_mechanism(policy_summary: Dict[str, Any], ssl_flags: Dict[str, Any]) -> str:
    if policy_summary.get("oauthv2"):
        return "oauth2"
    if policy_summary.get("verify_api_key"):
        return "apikey"
    if policy_summary.get("hmac"):
        return "hmac"
    if any(ssl_flags.get(k) for k in ("clientAuthRequired", "twoWaySSL", "mtls")):
        return "mtls"
    return "unknown" if any([policy_summary.get("oauthv2"), policy_summary.get("verify_api_key"), policy_summary.get("hmac")]) else "none"

def _first_target_host(targets: Optional[List[Dict[str, Any]]]) -> str:
    for t in targets or []:
        u = t.get("url")
        if u:
            try:
                return urlparse(u).hostname or "N/A"
            except Exception:
                return "N/A"
    return "N/A"

def _phoenix_month(val: str) -> str:
    from datetime import datetime as _dt
    try:
        dt = _dt.strptime(val, "%Y-%m-%d")
    except Exception:
        try:
            dt = _dt.fromtimestamp(float(val), tz=timezone.utc)
        except Exception:
            dt = datetime.now(timezone.utc)
    phx = dt.astimezone(ZoneInfo("America/Phoenix"))
    return f"{phx.year:04d}-{phx.month:02d}-01"

# ----------------------- Splunk plumbing -----------------------

def _resolve_splunk_host(env_key: str, explicit_host: str) -> str:
    """
    Returns full base like 'https://host:443' or 'https://host:8089'
    Priority: explicit .env SPLUNK_HOST -> constants SPLUNK_API_BY_ENV
    """
    host = (explicit_host or "").strip()
    if host:
        return host
    cfg = SPLUNK_API_BY_ENV.get(env_key.upper())
    if not cfg:
        raise RuntimeError(f"No SPLUNK_HOST and no SPLUNK_API_BY_ENV for env '{env_key}'")
    scheme = cfg.get("scheme", "https")
    hostname = cfg["host"]
    port = cfg.get("port", 443)  # default to 443 for corp deployments
    return f"{scheme}://{hostname}:{port}"

def _splunk_base(host: str) -> str:
    """
    Mgmt port 8089 uses /services
    Web port 443 proxies REST under /splunkd/__raw/services
    """
    if host.endswith(":443"):
        return f"{host}/splunkd/__raw/services"
    return f"{host}/services"

def _run_splunk(host: str, user: str, pwd: str, query: str, verify_tls: bool = True) -> List[Dict[str, Any]]:
    base = _splunk_base(host)
    # Create job
    try:
        r = requests.post(
            f"{base}/search/jobs",
            data={"search": f"search {query}", "output_mode": "json"},
            auth=(user, pwd),
            timeout=30,
            verify=verify_tls,
        )
        r.raise_for_status()
    except Exception as e:
        print(f"[splunk] connect/create FAILED base={base} verify={verify_tls} user={user} err={e}")
        return []
    sid = (r.json() or {}).get("sid")
    if not sid:
        print(f"[splunk] no SID returned from {base}")
        return []

    # Poll until done
    for _ in range(300):
        try:
            j = requests.get(
                f"{base}/search/jobs/{sid}",
                params={"output_mode": "json"},
                auth=(user, pwd),
                timeout=30,
                verify=verify_tls,
            )
            j.raise_for_status()
            jj = j.json() or {}
            entry = (jj.get("entry") or [{}])[0]
            if entry.get("content", {}).get("isDone"):
                break
        except Exception as e:
            print(f"[splunk] poll failed: {e}")
            return []
        time.sleep(1)

    # Fetch results
    try:
        res = requests.get(
            f"{base}/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": 50000},
            auth=(user, pwd),
            timeout=60,
            verify=verify_tls,
        )
        res.raise_for_status()
        jj = res.json() or {}
        return jj.get("results", []) or []
    except Exception as e:
        print(f"[splunk] results fetch failed: {e}")
        return []

def _spl_active_proxies_query(index: str) -> str:
    return f"""
    index={index} sourcetype=api_proxy earliest=-30d
    | eval apiproxy=coalesce(apiproxy, apiProxy_proxyName)
    | stats count as requests by apiproxy
    | where requests>0
    | fields apiproxy
    """

SPL_ONBOARDED_TMPL = """
index={index} sourcetype=api_proxy earliest=-13mon
| eval apiproxy=coalesce(apiproxy, apiProxy_proxyName)
| stats earliest(_time) as first_seen by apiproxy
| eval month=strftime(first_seen,"%Y-%m-01")
| stats count as onboarded_apis by month
| sort 0 month
"""
SPL_TPS_TMPL = """
index={index} sourcetype=api_proxy earliest=-13mon
| bin _time span=1s
| stats count as rps by _time
| eval month=strftime(_time,"%Y-%m-01")
| stats max(rps) as peak_tps avg(rps) as avg_tps by month
| sort 0 month
"""
SPL_CONS_TMPL = """
index={index} sourcetype=api_proxy earliest=-13mon
| eval month=strftime(_time,"%Y-%m-01")
| eval consumer=coalesce('apigee.developer.app.name','apigee.client_id')
| eventstats earliest(_time) as first_seen by consumer
| eval is_new=if(strftime(first_seen,"%Y-%m-01")==month,1,0)
| stats sum(is_new) as new_consumers dc(consumer) as active_consumers by month
| sort 0 month
"""
SPL_TRAFFIC_TMPL = """
index={index} sourcetype=api_proxy earliest=-13mon
| eval bytes_in=tonumber('request.header.contentLength'), bytes_out=tonumber('target.received.content.length')
| timechart span=1mon count as requests sum(bytes_in) as bytes_in sum(bytes_out) as bytes_out
"""

def _list_active_proxies_from_splunk(env_key: str, splunk_host: str, user: str, pwd: str, verify_tls: bool) -> List[str]:
    index = os.getenv("APIGEE_SPLUNK_INDEX", f"2000004162_api_{env_key}_idx1")
    q = _spl_active_proxies_query(index)
    rows = _run_splunk(splunk_host, user, pwd, q, verify_tls)
    return sorted({r.get("apiproxy") for r in rows if r.get("apiproxy")})

def _latest_revision_from_sdk(apigee, proxy_name: str) -> Optional[str]:
    proxy_api = getattr(apigee, "proxy", None)
    if not proxy_api:
        return None
    # common revision list methods
    for name in ("get_revisions", "list_revisions", "revisions"):
        if hasattr(proxy_api, name):
            try:
                revs = getattr(proxy_api, name)(proxy_name)
                if isinstance(revs, (list, tuple)) and revs:
                    return str(sorted(map(int, map(str, revs)))[-1])
            except Exception:
                pass
    # sometimes SDKs expose a direct latest
    for name in ("get_latest_revision", "latest"):
        if hasattr(proxy_api, name):
            try:
                rev = getattr(proxy_api, name)(proxy_name)
                return str(rev)
            except Exception:
                pass
    return None

# ----------------------- Catalog (config/metadata) -----------------------

def load_apigee_catalog(planet: str, org: str, env_key: str) -> List[Dict[str, Any]]:
    env_obj = ENV_OBJ_DICT.get(env_key)
    if env_obj is None:
        raise ValueError(f"[catalog] Unknown APIGEE_ENV '{env_key}'. Available: {list(ENV_OBJ_DICT.keys())}")

    # Initialize Apigee SDK
    try:
        apigee = initialize_apigee_obj(planet, org, env_obj)
    except Exception as e:
        print(f"[catalog] Apigee init FAILED planet={planet} org={org} env={env_key} err={type(e).__name__}: {e}")
        return []

    # Resolve Splunk base & creds via config
    from .config import load_settings
    s = load_settings()
    splunk_host = _resolve_splunk_host(env_key, s.splunk_host)

    # choose discovery mode
    force_splunk = os.getenv("APIGEE_FORCE_SPLUNK_DISCOVERY", "").strip().lower() in ("1", "true", "t", "yes", "y")
    pairs: List[Any] = []

    if force_splunk:
        print(f"[catalog] Forcing Splunk-derived discovery for env '{env_key}'")
        proxies = _list_active_proxies_from_splunk(env_key, splunk_host, s.splunk_user, s.splunk_password, s.splunk_verify_tls)
        for p in proxies:
            rev = _latest_revision_from_sdk(apigee, p)
            if rev:
                pairs.append((p, rev))
    else:
        # Try SDK-first using deployment env name; if empty, fall back to Splunk
        deploy_env = os.getenv("APIGEE_DEPLOY_ENV", env_key)
        try:
            from .utils.apigee_utils import get_all_active_proxies_by_deployment_env
            all_info = getattr(apigee, "get_all_info", lambda: None)() or {}
            pairs = get_all_active_proxies_by_deployment_env(all_info, deploy_env)
        except Exception:
            pairs = []

        if not pairs:
            print(f"[catalog] SDK discovery empty for deploy env '{deploy_env}'. Falling back to Splunk…")
            proxies = _list_active_proxies_from_splunk(env_key, splunk_host, s.splunk_user, s.splunk_password, s.splunk_verify_tls)
            for p in proxies:
                rev = _latest_revision_from_sdk(apigee, p)
                if rev:
                    pairs.append((p, rev))

    if not pairs:
        print(f"[catalog] No active proxies resolved for env '{env_key}'.")
        return []

    # Build rows
    rows: List[Dict[str, Any]] = []
    for proxy, rev in pairs:
        parsed, _xml = fetch_apigee_xml_data(apigee, proxy, rev)
        pol = get_policy_analysis_dict(parsed["policies"])
        ssl = get_virtual_host_analysis_dict(parsed["virtual_hosts"])
        rows.append({
            "apiproxy": proxy,
            "base_path": parsed.get("base_path") or parsed.get("BasePath") or parsed.get("proxy_base_path"),
            "target_host": _first_target_host(parsed.get("targets")),
            "security_mechanism": _security_mechanism(pol, ssl),
            "virtual_hosts": list(parsed.get("virtual_hosts") or []),
            "ssl_profile_flags": ssl,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
    return rows

# ----------------------- Metrics (monthly aggregations) -----------------------

def _index_by_month(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for r in rows or []:
        m = r.get("month")
        if m:
            out[_phoenix_month(m)] = {k: r[k] for k in r if k != "month"}
    return out

def fetch_apigee_monthlies(splunk_host: str, splunk_user: str, splunk_password: str, verify_tls: bool = True) -> List[Dict[str, Any]]:
    index = os.getenv("APIGEE_SPLUNK_INDEX", "2000004162_api_e3_idx1")

    def _safe(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        try:
            return _index_by_month(results or [])
        except Exception:
            return {}

    try:
        onboarded = _safe(_run_splunk(splunk_host, splunk_user, splunk_password, SPL_ONBOARDED_TMPL.format(index=index), verify_tls))
        tps       = _safe(_run_splunk(splunk_host, splunk_user, splunk_password, SPL_TPS_TMPL.format(index=index),       verify_tls))
        cons      = _safe(_run_splunk(splunk_host, splunk_user, splunk_password, SPL_CONS_TMPL.format(index=index),      verify_tls))
        traffic   = _safe(_run_splunk(splunk_host, splunk_user, splunk_password, SPL_TRAFFIC_TMPL.format(index=index),   verify_tls))
    except Exception as e:
        print(f"[metrics] Splunk query failed: {e}")
        return []

    months = sorted(
        set((onboarded or {}).keys())
        | set((tps or {}).keys())
        | set((cons or {}).keys())
        | set((traffic or {}).keys())
    )

    out: List[Dict[str, Any]] = []
    for m in months:
        row: Dict[str, Any] = {"month": m}
        row.update(onboarded.get(m, {}))
        row.update(tps.get(m, {}))
        row.update(cons.get(m, {}))
        row.update(traffic.get(m, {}))

        # normalize numeric types
        for k in ("onboarded_apis", "peak_tps", "new_consumers", "active_consumers", "requests", "bytes_in", "bytes_out"):
            v = row.get(k)
            if v not in (None, ""):
                try:
                    row[k] = int(float(v))
                except Exception:
                    pass
        v = row.get("avg_tps")
        if v not in (None, ""):
            try:
                row["avg_tps"] = float(v)
            except Exception:
                pass

        out.append(row)
    return out
