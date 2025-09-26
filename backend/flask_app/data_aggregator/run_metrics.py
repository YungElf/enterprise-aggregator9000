from .config import load_settings
from .db import get_conn, upsert_apigee_metrics
from .apigee_loaders import fetch_apigee_monthlies

def main():
    s = load_settings()
    rows = fetch_apigee_monthlies(s.splunk_host, s.splunk_user, s.splunk_password, s.splunk_verify_tls)
    with get_conn(s.pg_url) as conn:
        upsert_apigee_metrics(conn, rows)
    print(f"[metrics] upserted {len(rows)} monthly rows")
    return len(rows)

if __name__ == "__main__":
    main()
