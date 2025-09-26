from urllib.parse import urlparse
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import time
import requests

# Map "e1/e2/e3" -> env objects (E1_ENV/E2_ENV/E3_ENV)
from .utils.apigee_constants import ENV_OBJ_DICT

# Apigee helpers from your utils (SDK-dependent)
from .utils.apigee_utils import (
    initialize_apigee_obj,
    get_all_active_proxies_by_deployment_env,
    fetch_apigee_xml_data,
    get_policy_analysis_dict,
    get_virtual_host_analysis_dict,
)

# ----------------------- small helpers -----------------------

def _security_mechanism(policy_summary: dict, ssl_flags: dict) -> str:
    if policy_summary.get("oauthv2"): return "oauth2"
    if policy_summary.get("verify_api_key"): return "apikey"
    if policy_summary.get("hmac"): return "hmac"
    if any(ssl_flags.get(k) for k in ("clientAuthRequired","twoWaySSL","mtls")): return "mtls"
    if any([policy_summary.get("oauthv2"), policy_summary.get("verify_api_key"), policy_summary.get("hmac")]):
        return "unknown"
    return "none"

def _first_target_host(targets):
    for t in targets or []:
        u = t.get("url")
        if u:
            try:
                return urlparse(u).hostname or "N/A"
            except Exception:
                return "N/A"
    return "N/A"

def _phoenix_month(val: str) -> str:
    try:
        from datetime import datetime as _dt
        dt = _dt.strptime(val, "%Y-%m-%d")
    except Exception:
        from datetime import datetime as _dt
        dt = _dt.fromtimestamp(float(val), tz=timezone.utc)
    phx = dt.astimezone(ZoneInfo("America/Phoenix"))
    return f"{phx.year:04d}-{phx.month:02d}-01"

# ----------------------- resilient discovery -----------------------

def _maybe_get_all_info(apigee):
    """
    Try common SDK layouts to fetch 'all_info' (environments + proxies + revisions).
    """
    candidates = (
        "mgmt", "management", "admin", "org", "mgmt_api", ""  # "" means try apigee itself
    )
    for attr in candidates:
        obj = getattr(apigee, attr, None) if attr else apigee
        if obj and hasattr(obj, "get_all_info"):
            try:
                return obj.get_all_info()
            except Exception:
                pass
    return None

def _safe_active_pairs(apigee, env_key: str):
    """
    Return [(proxy, revision), ...] deployed in env_key.
    1) Prefer your utility that parses 'all_info' if we can get it from the SDK.
    2) Else, probe the proxy API to synthesize the list.
    """
    # 1) Try the fast path if SDK exposes get_all_info()
    all_info = _maybe_get_all_info(apigee)
    if all_info:
        try:
            return get_all_active_proxies_by_deployment_env(all_info, env_key)
        except Exception:
            pass

    # 2) Probe the proxy API with several common method names
    pairs = []
    proxy_api = getattr(apigee, "proxy", None)
    if not proxy_api:
        return pairs  # give up; caller will handle empty list

    # list proxies
    proxies = None
    for name in ("list_proxies", "get_proxies", "list"):
        if hasattr(proxy_api, name):
            try:
                proxies = getattr(proxy_api, name)()
                break
            except Exception:
                pass
    if not proxies:
        return pairs

    # for each proxy, try to find deployed revisions in this env
    for p in proxies:
        revs = None
        for name in ("get_revisions", "list_revisions", "revisions"):
            if hasattr(proxy_api, name):
                try:
                    revs = getattr(proxy_api, name)(p)
                    break
                except Exception:
                    pass
        if not revs:
            continue

        for r in revs:
            # check deployment state for this env
            deployed = False
            # common shapes we try:
            candidates = [
                ("get_proxy_deployments", (p, r)),
                ("get_deployments", (p,)),  # may return per-env structure
                ("is_deployed", (p, r, env_key)),
            ]
            for meth, args in candidates:
                if hasattr(proxy_api, meth):
                    try:
                        resp = getattr(proxy_api, meth)(*args)
                        # heuristics: if it's a bool from is_deployed
                        if isinstance(resp, bool):
                            deployed = resp
                        else:
                            # look for env_key in the response
                            s = str(resp).lower()
                            deployed = env_key.lower() in s and ("deploy" in s or "state" in s or "revision" in s)
                        break
                    except Exception:
                        pass
            if deployed:
                pairs.append((p, str(r)))
    return pairs

# ----------------------- CATALOG (Apigee Mgmt API) -----------------------

def load_apigee_catalog(planet: str, org: str, env_key: str) -> list[dict]:
    """
    planet: your literal (e.g., 'R0'/'R1'/'R2')
    org:    org name valid for that env
    env_key: 'e1' | 'e2' | 'e3' (looked up in ENV_OBJ_DICT)
    """
    env_obj = ENV_OBJ_DICT.get(env_key)
    if env_obj is None:
        raise ValueError(f"[catalog] Unknown APIGEE_ENV '{env_key}'. Available: {list(ENV_OBJ_DICT.keys())}")

    apigee = initialize_apigee_obj(planet, org, env_obj)

    # ← this used to be: apigee.mgmt.get_all_info() ...
    pairs = _safe_active_pairs(apigee, env_key)
    if not pairs:
        print(f"[catalog] No active proxies found for env '{env_key}'.")
        return []

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

# ----------------------- METRICS (Splunk REST) -----------------------

SPL_ONBOARDED = """
index=2000004162_api_e3_idx1 sourcetype=api_proxy earliest=-13mon
| eval apiproxy=coalesce(apiproxy, apiProxy_proxyName)
| stats earliest(_time) as first_seen by apiproxy
| eval month=strftime(first_seen,"%Y-%m-01")
| stats count as onboarded_apis by month
| sort 0 month
"""

SPL_TPS = """
index=2000004162_api_e3_idx1 sourcetype=api_proxy earliest=-13mon
| bin _time span=1s
| stats count as rps by _time
| eval month=strftime(_time,"%Y-%m-01")
| stats max(rps) as peak_tps avg(rps) as avg_tps by month
| sort 0 month
"""

SPL_CONSUMERS = """
index=2000004162_api_e3_idx1 sourcetype=api_proxy earliest=-13mon
| eval month=strftime(_time,"%Y-%m-01")
| eval consumer=coalesce('apigee.developer.app.name','apigee.client_id')
| eventstats earliest(_time) as first_seen by consumer
| eval is_new=if(strftime(first_seen,"%Y-%m-01")==month,1,0)
| stats sum(is_new) as new_consumers dc(consumer) as active_consumers by month
| sort 0 month
"""

SPL_TRAFFIC = """
index=2000004162_api_e3_idx1 sourcetype=api_proxy earliest=-13mon
| eval bytes_in=tonumber('request.header.contentLength'), bytes_out=tonumber('target.received.content.length')
| timechart span=1mon count as requests sum(bytes_in) as bytes_in sum(bytes_out) as bytes_out
"""

def _run_splunk(host, user, pwd, query: str, verify_tls: bool = True):
    base = f"{host}/services"
    r = requests.post(
        f"{base}/search/jobs",
        data={"search": f"search {query}", "output_mode": "json"},
        auth=(user, pwd),
        timeout=30,
        verify=verify_tls,
    )
    r.raise_for_status()
    sid = r.json()["sid"]

    for _ in range(300):
        j = requests.get(
            f"{base}/search/jobs/{sid}",
            params={"output_mode": "json"},
            auth=(user, pwd),
            timeout=30,
            verify=verify_tls,
        )
        j.raise_for_status()
        if j.json()["entry"][0]["content"].get("isDone"):
            break
        time.sleep(1)

    res = requests.get(
        f"{base}/search/jobs/{sid}/results",
        params={"output_mode": "json", "count": 50000},
        auth=(user, pwd),
        timeout=60,
        verify=verify_tls,
    )
    res.raise_for_status()
    return res.json().get("results", [])

def _index_by_month(rows):
    out = {}
    for r in rows:
        m = r.get("month")
        if m:
            out[_phoenix_month(m)] = {k: r[k] for k in r if k != "month"}
    return out

def fetch_apigee_monthlies(splunk_host, splunk_user, splunk_password, verify_tls: bool = True) -> list[dict]:
    onboarded = _index_by_month(_run_splunk(splunk_host, splunk_user, splunk_password, SPL_ONBOARDED, verify_tls))
    tps       = _index_by_month(_run_splunk(splunk_host, splunk_user, splunk_password, SPL_TPS,       verify_tls))
    cons      = _index_by_month(_run_splunk(splunk_host, splunk_user, splunk_password, SPL_CONSUMERS, verify_tls))
    traffic   = _index_by_month(_run_splunk(splunk_host, splunk_user, splunk_password, SPL_TRAFFIC,   verify_tls))
    months = sorted(set(onboarded) | set(tps) | set(cons) | set(traffic))

    out = []
    for m in months:
        row = {"month": m}
        row.update(onboarded.get(m, {}))
        row.update(tps.get(m, {}))
        row.update(cons.get(m, {}))
        row.update(traffic.get(m, {}))

        for k in ("onboarded_apis","peak_tps","new_consumers","active_consumers","requests","bytes_in","bytes_out"):
            if k in row and row[k] not in (None, ""):
                try: row[k] = int(float(row[k]))
                except Exception: pass
        if "avg_tps" in row and row["avg_tps"] not in (None,""):
            try: row["avg_tps"] = float(row["avg_tps"])
            except Exception: pass

        out.append(row)
    return out
