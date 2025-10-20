# pg8000-only DB helpers + upserts
import os, re, json
from contextlib import contextmanager
from urllib.parse import urlparse, unquote
from pg8000 import dbapi as pg


def _conn_params(url: str = None):
    if url is None:
        url = os.getenv("AGG_PG_URL")
    if url:
        url = re.sub(r"^\s*postgresql\+[^:]+://", "postgresql://", url)
        u = urlparse(url)
        return dict(
            user=unquote(u.username or ""),
            password=unquote(u.password or ""),
            host=u.hostname or "localhost",
            port=int(u.port or 5432),
            database=(u.path or "/").lstrip("/"),
        )
    # fall back to discrete env vars
    name = os.getenv("DB_NAME")
    user = os.getenv("DB_USER")
    pwd  = os.getenv("DB_PASSWORD") or os.getenv("DB_SECRET")
    host = os.getenv("DB_HOST")
    port = int(os.getenv("DB_PORT", "5432"))
    if not (name and user and pwd and host):
        raise RuntimeError("No Postgres config. Set AGG_PG_URL or DB_* env vars.")
    host = re.sub(r"^\w+://", "", host)
    return dict(user=user, password=pwd, host=host, port=port, database=name)


@contextmanager

def get_conn(pg_url: str = None):
    params = _conn_params(pg_url)
    conn = pg.connect(**params)
    try:
        yield conn
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()


# ================== Legacy tables (kept for compatibility) ==================

def upsert_apigee_config_data(conn, rows: list[dict]):
    cur = conn.cursor()
    cur.execute("""
    create table if not exists apigee_config_data(
      apiproxy text primary key,
      base_path text,
      target_host text,
      security_mechanism text,
      virtual_hosts jsonb,
      ssl_profile_flags jsonb,
      consumer_count int,
      developer_apps jsonb,
      updated_at timestamptz not null default now()
    )""")
    if not rows:
        cur.close(); return
    data = []
    for r in rows:
        data.append((
            r.get("apiproxy"),
            r.get("base_path"),
            r.get("target_host"),
            r.get("security_mechanism"),
            json.dumps(r.get("virtual_hosts") or []),
            json.dumps(r.get("ssl_profile_flags") or {}),
            r.get("updated_at"),
        ))
    cur.executemany("""
    insert into apigee_config_data
      (apiproxy, base_path, target_host, security_mechanism, virtual_hosts, ssl_profile_flags, updated_at)
    values (%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s)
    on conflict (apiproxy) do update set
      base_path=excluded.base_path,
      target_host=excluded.target_host,
      security_mechanism=excluded.security_mechanism,
      virtual_hosts=excluded.virtual_hosts,
      ssl_profile_flags=excluded.ssl_profile_flags,
      updated_at=excluded.updated_at
    """, data)
    cur.close()


def upsert_apigee_metrics(conn, rows: list[dict]):
    cur = conn.cursor()
    cur.execute("""
    create table if not exists apigee_metrics(
      month date primary key,
      onboarded_apis int,
      peak_tps int,
      avg_tps numeric(10,2),
      new_consumers int,
      active_consumers int,
      requests bigint,
      bytes_in bigint,
      bytes_out bigint
    )""")
    if not rows:
        cur.close(); return
    data = []
    for r in rows:
        data.append((
            r.get("month"),
            r.get("onboarded_apis"),
            r.get("peak_tps"),
            r.get("avg_tps"),
            r.get("new_consumers"),
            r.get("active_consumers"),
            r.get("requests"),
            r.get("bytes_in"),
            r.get("bytes_out"),
        ))
    cur.executemany("""
    insert into apigee_metrics
      (month,onboarded_apis,peak_tps,avg_tps,new_consumers,active_consumers,requests,bytes_in,bytes_out)
    values (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    on conflict (month) do update set
      onboarded_apis=excluded.onboarded_apis,
      peak_tps=excluded.peak_tps,
      avg_tps=excluded.avg_tps,
      new_consumers=excluded.new_consumers,
      active_consumers=excluded.active_consumers,
      requests=excluded.requests,
      bytes_in=excluded.bytes_in,
      bytes_out=excluded.bytes_out
    """, data)
    cur.close()


# ================== New enterprise tables ==================

def upsert_enterprise_api_apigee_metadata(conn, rows: list[dict]):
    cur = conn.cursor()
    cur.execute("""
    create table if not exists enterprise_api_apigee_metadata(
      id bigserial primary key,
      org_name text not null,
      env_name text not null,
      central_id text,
      proxy_name text not null,
      proxy_base_path text,
      proxy_resource_path text,
      security_mechanism text,
      backend_target_path text,
      rate_limit text,
      io_timeout int,
      connect_timeout int,
      developer_name text,
      developer_app_name text,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      unique (org_name, env_name, proxy_name)
    )""")
    if not rows:
        cur.close(); return
    data = []
    for r in rows:
        data.append((
            r.get("org_name"),
            r.get("env_name"),
            r.get("central_id"),
            r.get("proxy_name"),
            r.get("proxy_base_path"),
            r.get("proxy_resource_path"),
            r.get("security_mechanism"),
            r.get("backend_target_path"),
            r.get("rate_limit"),
            r.get("io_timeout"),
            r.get("connect_timeout"),
            r.get("developer_name"),
            r.get("developer_app_name"),
        ))
    cur.executemany("""
    insert into enterprise_api_apigee_metadata (
      org_name, env_name, central_id, proxy_name, proxy_base_path, proxy_resource_path,
      security_mechanism, backend_target_path, rate_limit, io_timeout, connect_timeout,
      developer_name, developer_app_name
    ) values (
      %s,%s,%s,%s,%s,%s,
      %s,%s,%s,%s,%s,
      %s,%s
    ) on conflict (org_name, env_name, proxy_name) do update set
      central_id=excluded.central_id,
      proxy_base_path=excluded.proxy_base_path,
      proxy_resource_path=excluded.proxy_resource_path,
      security_mechanism=excluded.security_mechanism,
      backend_target_path=excluded.backend_target_path,
      rate_limit=excluded.rate_limit,
      io_timeout=excluded.io_timeout,
      connect_timeout=excluded.connect_timeout,
      developer_name=excluded.developer_name,
      developer_app_name=excluded.developer_app_name,
      updated_at=now()
    """, data)
    cur.close()


def upsert_enterprise_api_volume_metrics(conn, rows: list[dict]):
    cur = conn.cursor()
    cur.execute("""
    create table if not exists enterprise_api_volume_metrics(
      id bigserial primary key,
      gateway_name text not null,
      proxy_name text,
      central_id text,
      proxy_uri text,
      start_date date not null,
      end_date date not null,
      volume bigint,
      success_200_count bigint,
      failure_401_count bigint,
      failure_400_count bigint,
      failure_500_count bigint,
      failure_503_count bigint,
      failure_504_count bigint,
      failure_429_count bigint,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      unique (gateway_name, proxy_name, central_id, start_date, end_date)
    )""")
    if not rows:
        cur.close(); return
    data = []
    for r in rows:
        data.append((
            r.get("gateway_name"),
            r.get("proxy_name"),
            r.get("central_id"),
            r.get("proxy_uri"),
            r.get("start_date"),
            r.get("end_date"),
            r.get("volume"),
            r.get("success_200_count"),
            r.get("failure_401_count"),
            r.get("failure_400_count"),
            r.get("failure_500_count"),
            r.get("failure_503_count"),
            r.get("failure_504_count"),
            r.get("failure_429_count"),
        ))
    cur.executemany("""
    insert into enterprise_api_volume_metrics (
      gateway_name, proxy_name, central_id, proxy_uri, start_date, end_date,
      volume, success_200_count, failure_401_count, failure_400_count, failure_500_count,
      failure_503_count, failure_504_count, failure_429_count
    ) values (
      %s,%s,%s,%s,%s,%s,
      %s,%s,%s,%s,%s,
      %s,%s,%s
    ) on conflict (gateway_name, proxy_name, central_id, start_date, end_date) do update set
      proxy_uri=excluded.proxy_uri,
      volume=excluded.volume,
      success_200_count=excluded.success_200_count,
      failure_401_count=excluded.failure_401_count,
      failure_400_count=excluded.failure_400_count,
      failure_500_count=excluded.failure_500_count,
      failure_503_count=excluded.failure_503_count,
      failure_504_count=excluded.failure_504_count,
      failure_429_count=excluded.failure_429_count,
      updated_at=now()
    """, data)
    cur.close()
