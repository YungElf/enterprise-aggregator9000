from .config import load_settings
from .db import get_conn, upsert_apigee_config_data
from .apigee_loaders import load_apigee_catalog

def main():
    s = load_settings()
    rows = load_apigee_catalog(s.apigee_planet, s.apigee_org, s.apigee_env)
    with get_conn(s.pg_url) as conn:
        upsert_apigee_config_data(conn, rows)
    print(f"[catalog] upserted {len(rows)} rows")
    return len(rows)

if __name__ == "__main__":
    main()
