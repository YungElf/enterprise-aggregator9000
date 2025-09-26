from urllib.parse import urlparse
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import requests, time


from .utils.apigee_utils import (
    initialize_apigee_obj,
    get_all_active_proxies_by_deployment_env,
    fetch_apigee_xml_data,
    get_policy_analysis_dict,
    get_virtual_host_analysis_dict,
)

# ====================== CATALOG (Apigee Mgmt API) ======================

def _security_mechanism(policy_summary: dict, ssl_flags: dict) -> str:
    if policy_summary.get("oauthv2"): return "oauth2"
    if policy_summary.get("verify_api_key"): return "apikey"
    if policy_summary.get("hmac"): return "hmac"
    if any(ssl_flags.get(k) for k in ("clientAuthRequired","twoWaySSL","mtls")): return "mtls"
    return "none" if not any([policy_summary.get("oauthv2"),
                               policy_summary.get("verify_api_key"),
                               policy_summary.get("hmac")]) else "unknown"

def _first_target_host(targets):
    for t in targets or []:
        u = t.get("url")
        if u:
            try:
                return urlparse(u).hostname or "N/A"
            except Exception:
                return "N/A"
    return "N/A"

def load_apigee_catalog(planet: str, org: str, env: str) -> list[dict]:
    apigee = initialize_apigee_obj(planet, org, env)
    all_info = apigee.mgmt.get_all_info()
    pairs = get_all_active_proxies_by_deployment_env(all_info, env)  # [(proxy, rev)]
    rows = []
    for proxy, rev in pairs:
        parsed = fetch_apigee_xml_data(apigee, proxy, rev)  # {"policies","virtual_hosts","targets", ...}
        pol = get_policy_analysis_dict(parsed["policies"])
        ssl = get_virtual_host_analysis_dict(parsed["virtual_hosts"])
        row = {
            "apiproxy": proxy,
            "base_path": parsed.get("base_path") or parsed.get("BasePath") or parsed.get("proxy_base_path"),
            "target_host": _first_target_host(parsed.get("targets")),
            "security_mechanism": _security_mechanism(pol, ssl),
            "virtual_hosts": list(parsed.get("virtual_hosts") or []),
            "ssl_profile_flags": ssl,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        rows.append(row)
    return rows

# ========================= METRICS (Splunk) ============================

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

def _phoenix_month(val: str) -> str:
    try:
        dt = datetime.strptime(val, "%Y-%m-%d")
    except Exception:
        dt = datetime.fromtimestamp(float(val), tz=timezone.utc)
    phx = dt.astimezone(ZoneInfo("America/Phoenix"))
    return f"{phx.year:04d}-{phx.month:02d}-01"

def _run_splunk(host, user, pwd, query: str, verify_tls: bool = True):
    base = f"{host}/services"
    r = requests.post(f"{base}/search/jobs",
                      data={"search": f"search {query}", "output_mode":"json"},
                      auth=(user, pwd), timeout=30, verify=verify_tls)
    r.raise_for_status()
    sid = r.json()["sid"]
    for _ in range(300):
        j = requests.get(f"{base}/search/jobs/{sid}", params={"output_mode":"json"},
                         auth=(user, pwd), timeout=30, verify=verify_tls)
        j.raise_for_status()
        if j.json()["entry"][0]["content"].get("isDone"):
            break
        time.sleep(1)
    res = requests.get(f"{base}/search/jobs/{sid}/results",
                       params={"output_mode":"json","count":50000},
                       auth=(user, pwd), timeout=60, verify=verify_tls)
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
    months = sorted(set(onboarded)|set(tps)|set(cons)|set(traffic))
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
