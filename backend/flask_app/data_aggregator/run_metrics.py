from .config import load_settings
from .db import get_conn, upsert_enterprise_api_volume_metrics
from .apigee_loaders import fetch_apigee_monthlies
from .utils.apigee_constants import SPLUNK_API_BY_ENV  # mapping per env


def _resolve_splunk_host(splunk_host: str, env_key: str) -> str:
    host = (splunk_host or "").strip()
    if host:
        return host
    cfg = SPLUNK_API_BY_ENV.get(env_key)
    if not cfg:
        raise RuntimeError(f"No SPLUNK_HOST in .env and no SPLUNK_API_BY_ENV mapping for env '{env_key}'.")
    if isinstance(cfg, str):
        return cfg  # already a full URL
    scheme = cfg.get("scheme", "https")
    hostname = cfg["host"]
    port = cfg.get("port", 8089)
    return f"{scheme}://{hostname}:{port}"


def _map_monthlies_to_enterprise(rows: list[dict], gateway_name: str, env_key: str) -> list[dict]:
    # We do not have explicit start/end in monthly rows; use first day to last day of that month.
    out = []
    for r in rows:
        m = r.get("month")  # YYYY-MM-01
        if not m:
            continue
        # Compute end-date as last day by trick: next month first day minus 1
        yyyy, mm, _ = [int(x) for x in m.split("-")]
        if mm == 12:
            end_y, end_m = yyyy + 1, 1
        else:
            end_y, end_m = yyyy, mm + 1
        start_date = f"{yyyy:04d}-{mm:02d}-01"
        from datetime import date, timedelta
        end_date = (date(end_y, end_m, 1) - timedelta(days=1)).strftime("%Y-%m-%d")
        out.append({
            "gateway_name": gateway_name,
            "proxy_name": None,  # unknown at monthly aggregate level
            "central_id": None,
            "proxy_uri": None,
            "start_date": start_date,
            "end_date": end_date,
            "volume": r.get("requests"),
            "success_200_count": r.get("success_200_count") or None,
            "failure_401_count": r.get("failure_401_count") or None,
            "failure_400_count": r.get("failure_400_count") or None,
            "failure_500_count": r.get("failure_500_count") or None,
            "failure_503_count": r.get("failure_503_count") or None,
            "failure_504_count": r.get("failure_504_count") or None,
            "failure_429_count": r.get("failure_429_count") or None,
        })
    return out


def main():
    s = load_settings()
    host = _resolve_splunk_host(s.splunk_host, s.apigee_env)
    rows = fetch_apigee_monthlies(host, s.splunk_user, s.splunk_password, s.splunk_verify_tls)
    mapped = _map_monthlies_to_enterprise(rows, gateway_name="Apigee", env_key=s.apigee_env)
    with get_conn(s.pg_url) as conn:
        upsert_enterprise_api_volume_metrics(conn, mapped)
    print(f"[metrics] upserted {len(mapped)} enterprise_api_volume_metrics rows (host: {host})")
    return len(mapped)


if __name__ == "__main__":
    main()
