from .config import load_settings
from .db import get_conn, upsert_apigee_metrics
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

def main():
    s = load_settings()
    host = _resolve_splunk_host(s.splunk_host, s.apigee_env)
    rows = fetch_apigee_monthlies(host, s.splunk_user, s.splunk_password, s.splunk_verify_tls)
    with get_conn() as conn:
        upsert_apigee_metrics(conn, rows)
    print(f"[metrics] upserted {len(rows)} monthly rows (host: {host})")
    return len(rows)

if __name__ == "__main__":
    main()
