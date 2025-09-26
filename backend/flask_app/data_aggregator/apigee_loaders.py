from urllib.parse import urlparse
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import os, time, requests

from .utils.apigee_constants import ENV_OBJ_DICT, SPLUNK_API_BY_ENV
from .utils.apigee_utils import (
    initialize_apigee_obj,
    fetch_apigee_xml_data,
    get_policy_analysis_dict,
    get_virtual_host_analysis_dict,
)

# ----------------------- helpers -----------------------

def _security_mechanism(policy_summary: dict, ssl_flags: dict) -> str:
    if policy_summary.get("oauthv2"): return "oauth2"
    if policy_summary.get("verify_api_key"): return "apikey"
    if policy_summary.get("hmac"): return "hmac"
    if any(ssl_flags.get(k) for k in ("clientAuthRequired","twoWaySSL","mtls")): return "mtls"
    return "unknown" if any([policy_summary.get("oauthv2"), policy_summary.get("verify_api_key"), policy_summary.get("hmac")]) else "none"

def _first_target_host(targets):
    for t in targets or []:
        u = t.get("url")
        if u:
            try: return urlparse(u).hostname or "N/A"
            except Exception: return "N/A"
    return "N/A"

def _phoenix_month(val: str) -> str:
    from datetime import datetime as _dt
    try: dt = _dt.strptime(val, "%Y-%m-%d")
    except Exception: dt = _dt.fromtimestamp(float(val), tz=timezone.utc)
    phx = dt.astimezone(ZoneInfo("America/Phoenix"))
    return f"{phx.year:04d}-{phx.month:02d}-01"

# ----------------------- Splunk helpers -----------------------

def _resolve_splunk_host(env_key: str, explicit_host: str, cfg_map=SPLUNK_API_BY_ENV) -> str:
    host = (explicit_host or "").strip()
    if host:
        return host
    cfg = cfg_map.get(env_key)
    if isinstance(cfg, str):
        return cfg
    if not cfg: raise RuntimeError(f"No SPLUNK_HOST and no SPLUNK_API_BY_ENV for env '{env_key}'")
    scheme = cfg.get("scheme", "https"); hostname = cfg["host"]; port = cfg.get("port", 8089)
    return f"{scheme}://{hostname}:{port}"

def _run_splunk(host, user, pwd, query: str, verify_tls: bool = True):
    base = f"{host}/services"
    r = requests.post(f"{base}/search/jobs",
        data={"search": f"search {query}", "output_mode":"json"},
        auth=(user, pwd), timeout=30, verify=verify_tls)
    r.raise_for_status(); sid = r.json()["sid"]
    for _ in range(300):
        j = requests.get(f"{base}/search/jobs/{sid}",
            params={"output_mode":"json"},
            auth=(user, pwd), timeout=30, verify=verify_tls)
        j.raise_for_status()
        if j.json()["entry"][0]["content"].get("isDone"): break
        time.sleep(1)
    res = requests.get(f"{base}/search/jobs/{sid}/results",
        params={"output_mode":"json","count":50000},
        auth=(user, pwd), timeout=60, verify=verify_tls)
    res.raise_for_status(); return res.json().get("results", [])

# SPL index is now overridable via APIGEE_SPLUNK_INDEX
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

# ----------------------- Catalog: force Splunk-first if toggled -----------------------

def _list_active_proxies_from_splunk(env_key: str, splunk_host: str, user: str, pwd: str, verify_tls: bool) -> list[str]:
    index = os.getenv("APIGEE_SPLUNK_INDEX", f"2000004162_api_{env_key}_idx1")
    q = _spl_active_proxies_query(index)
    rows = _run_splunk(splunk_host, user, pwd, q, verify_tls)
    return sorted({r.get("apiproxy") for r in rows if r.get("apiproxy")})

def _latest_revision_from_sdk(apigee, proxy_name: str) -> str | None:
    proxy_api = getattr(apigee, "proxy", None)
    if not proxy_api: return None
    for name in ("get_revisions","list_revisions","revisions"):
        if hasattr(proxy_api, name):
            try:
                revs = getattr(proxy_api, name)(proxy_name)
                if isinstance(revs, (list, tuple)) and revs:
                    return str(sorted(map(int, map(str, revs)))[-1])
            except Exception:
                pass
    # other SDKs expose get_latest_revision / latest
    for name in ("get_latest_revision","latest"):
        if hasattr(proxy_api, name):
            try:
                rev = getattr(proxy_api, name)(proxy_name)
                return str(rev)
            except Exception:
                pass
    return None

def load_apigee_catalog(planet: str, org: str, env_key: str) -> list[dict]:
    env_obj = ENV_OBJ_DICT.get(env_key)
    if env_obj is None:
        raise ValueError(f"[catalog] Unknown APIGEE_ENV '{env_key}'. Available: {list(ENV_OBJ_DICT.keys())}")

    # Initialize SDK
    apigee = initialize_apigee_obj(planet, org, env_obj)

    # Resolve Splunk host (we will need it either way)
    from .config import load_settings
    s = load_settings()
    spl_host = _resolve_splunk_host(env_key, s.splunk_host)

    # Decide discovery mode
    force_splunk = os.getenv("APIGEE_FORCE_SPLUNK_DISCOVERY","").strip().lower() in ("1","true","t","yes","y")

    pairs = []

    if force_splunk:
        print(f"[catalog] Forcing Splunk-derived discovery for env '{env_key}'")
        proxies = _list_active_proxies_from_splunk(env_key, spl_host, s.splunk_user, s.splunk_password, s.splunk_verify_tls)
        for p in proxies:
            rev = _latest_revision_from_sdk(apigee, p)
            if rev: pairs.append((p, rev))
    else:
        # try SDK-first (using deployment env name), then fall back to Splunk
        deploy_env = os.getenv("APIGEE_DEPLOY_ENV", env_key)
        try:
            # if your utils expose get_all_active_proxies_by_deployment_env via apigee, call it;
            # otherwise import it if you have it as a pure function (commented out earlier).
            from .utils.apigee_utils import get_all_active_proxies_by_deployment_env
            all_info = getattr(apigee, "get_all_info", lambda: None)() or {}
            pairs = get_all_active_proxies_by_deployment_env(all_info, deploy_env)
        except Exception:
            pairs = []

        if not pairs:
            print(f"[catalog] SDK discovery empty for deploy env '{deploy_env}'. Falling back to Splunk…")
            proxies = _list_active_proxies_from_splunk(env_key, spl_host, s.splunk_user, s.splunk_password, s.splunk_verify_tls)
            for p in proxies:
                rev = _latest_revision_from_sdk(apigee, p)
                if rev: pairs.append((p, rev))

    if not pairs:
        print(f"[catalog] No active proxies resolved for env '{env_key}'.")
        return []

    # Build rows
    rows = []
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

# ----------------------- Metrics (unchanged) -----------------------

def _index_by_month(rows):
    out = {}
    for r in rows:
        m = r.get("month")
        if m: out[_phoenix_month(m)] = {k: r[k] for k in r if k != "month"}
    return out

def fetch_apigee_monthlies(splunk_host, splunk_user, splunk_password, verify_tls: bool = True) -> list[dict]:
    index = os.getenv("APIGEE_SPLUNK_INDEX", "2000004162_api_e3_idx1")
    onboarded = _index_by_month(_run_splunk(splunk_host, splunk_user, splunk_password, SPL_ONBOARDED_TMPL.format(index=index), verify_tls))
    tps       = _index_by_month(_run_splunk(splunk_host, splunk_user, splunk_password, SPL_TPS_TMPL.format(index=index),       verify_tls))
    cons      = _index_by_month(_run_splunk(splunk_host, splunk_user, splunk_password, SPL_CONS_TMPL.format(index=index),      verify_tls))
    traffic   = _index_by_month(_run_splunk(splunk_host, splunk_user, splunk_password, SPL_TRAFFIC_TMPL.format(index=index),   verify_tls))
    months = sorted(set(onboarded)|set(tps)|set(cons)|set(traffic))
    out = []
    for m in months:
        row = {"month": m}
        row.update(onboarded.get(m, {}))
        row.update(tps.get(m, {}))
        row.update(cons.get(m, {}))
        row.update(traffic.get(m, {}))
        for k in ("onboarded_apis","peak_tps","new_consumers","active_consumers","requests","bytes_in","bytes_out"):
            if k in row and row[k] not in (None,""):
                try: row[k] = int(float(row[k]))
                except: pass
        if "avg_tps" in row and row["avg_tps"] not in (None,""):
            try: row["avg_tps"] = float(row["avg_tps"])
            except: pass
        out.append(row)
    return out
