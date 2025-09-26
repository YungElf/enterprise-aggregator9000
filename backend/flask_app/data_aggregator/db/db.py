from contextlib import contextmanager
import os
import re
from sqlalchemy import create_engine, text
import psycopg2
from psycopg2.extras import RealDictCursor

def _pg_url_from_env() -> str | None:
    url = os.getenv("AGG_PG_URL")
    if url:
        return url
    name = os.getenv("DB_NAME")
    user = os.getenv("DB_USER")
    pwd  = os.getenv("DB_PASSWORD") or os.getenv("DB_SECRET") 
    host = os.getenv("DB_HOST")
    port = os.getenv("DB_PORT", "5432")
    if not (name and user and pwd and host):
        return None
    host = re.sub(r"^\w+://", "", host)
    return f"postgresql+psycopg://{user}:{pwd}@{host}:{port}/{name}"


_engine_cache = {}

def get_engine(pg_url: str | None = None):
    pg_url = pg_url or _pg_url_from_env()
    if not pg_url:
        raise RuntimeError("No Postgres configuration. Set AGG_PG_URL or DB_* env vars.")
    eng = _engine_cache.get(pg_url)
    if not eng:
        eng = create_engine(pg_url, pool_pre_ping=True, future=True)
        _engine_cache[pg_url] = eng
    return eng

@contextmanager
def get_conn(pg_url: str | None = None):
    eng = get_engine(pg_url)
    with eng.begin() as conn:   # begins a txn and commits/rolls back automatically
        yield conn

def get_db_connection():
    """
    Legacy helper returning a raw psycopg2 connection.
    Uses DB_* env vars; falls back to parsing AGG_PG_URL.
    """
    
    name = os.getenv("DB_NAME")
    user = os.getenv("DB_USER")
    pwd  = os.getenv("DB_PASSWORD") or os.getenv("DB_SECRET")
    host = os.getenv("DB_HOST")
    port = os.getenv("DB_PORT", "5432")
    if name and user and pwd and host:
        host = re.sub(r"^\w+://", "", host)
        return psycopg2.connect(dbname=name, user=user, password=pwd, host=host, port=port, cursor_factory=RealDictCursor)

    
    pg_url = os.getenv("AGG_PG_URL")
    if not pg_url:
        raise RuntimeError("No Postgres configuration. Set AGG_PG_URL or DB_* env vars.")
    
    dsn = re.sub(r"^\s*postgresql\+psycopg://", "postgresql://", pg_url)
    return psycopg2.connect(dsn, cursor_factory=RealDictCursor)

def upsert_apigee_config_data(conn, rows: list[dict]):
    conn.execute(text("""
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
    )"""))
    if not rows:
        return
    sql = text("""
    insert into apigee_config_data
      (apiproxy, base_path, target_host, security_mechanism,
       virtual_hosts, ssl_profile_flags, updated_at)
    values
      (:apiproxy, :base_path, :target_host, :security_mechanism,
       cast(:virtual_hosts as jsonb), cast(:ssl_profile_flags as jsonb), :updated_at)
    on conflict (apiproxy) do update set
      base_path=excluded.base_path,
      target_host=excluded.target_host,
      security_mechanism=excluded.security_mechanism,
      virtual_hosts=excluded.virtual_hosts,
      ssl_profile_flags=excluded.ssl_profile_flags,
      updated_at=excluded.updated_at
    """)
    conn.execute(sql, rows)

def upsert_apigee_metrics(conn, rows: list[dict]):
    conn.execute(text("""
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
    )"""))
    if not rows:
        return
    sql = text("""
    insert into apigee_metrics
      (month,onboarded_apis,peak_tps,avg_tps,new_consumers,active_consumers,requests,bytes_in,bytes_out)
    values
      (:month,:onboarded_apis,:peak_tps,:avg_tps,:new_consumers,:active_consumers,:requests,:bytes_in,:bytes_out)
    on conflict (month) do update set
      onboarded_apis=excluded.onboarded_apis,
      peak_tps=excluded.peak_tps,
      avg_tps=excluded.avg_tps,
      new_consumers=excluded.new_consumers,
      active_consumers=excluded.active_consumers,
      requests=excluded.requests,
      bytes_in=excluded.bytes_in,
      bytes_out=excluded.bytes_out
    """)
    conn.execute(sql, rows)
