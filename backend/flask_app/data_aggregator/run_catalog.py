from .config import load_settings
from .db import get_conn, upsert_enterprise_api_apigee_metadata
from .apigee_loaders import load_apigee_catalog


def _map_to_enterprise_metadata(rows: list[dict], org: str, env: str) -> list[dict]:
    out = []
    for r in rows:
        out.append({
            "org_name": org,
            "env_name": env,
            "central_id": r.get("central_id"),
            "proxy_name": r.get("apiproxy") or r.get("proxy_name"),
            "proxy_base_path": r.get("base_path") or r.get("proxy_base_path"),
            "proxy_resource_path": r.get("resource_path") or r.get("proxy_resource_path"),
            "security_mechanism": r.get("security_mechanism"),
            "backend_target_path": r.get("target_host") or r.get("backend_target_path"),
            "rate_limit": r.get("rate_limit"),
            "io_timeout": r.get("io_timeout"),
            "connect_timeout": r.get("connect_timeout"),
            "developer_name": r.get("developer_name"),
            "developer_app_name": r.get("developer_app_name"),
        })
    return out


def main():
    s = load_settings()
    rows = load_apigee_catalog(s.apigee_planet, s.apigee_org, s.apigee_env)
    mapped = _map_to_enterprise_metadata(rows, s.apigee_org, s.apigee_env)
    with get_conn(s.pg_url) as conn:
        upsert_enterprise_api_apigee_metadata(conn, mapped)
    print(f"[catalog] upserted {len(mapped)} rows into enterprise_api_apigee_metadata")
    return len(mapped)


if __name__ == "__main__":
    main()
