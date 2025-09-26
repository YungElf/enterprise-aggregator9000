# pg8000-only DB helpers + upserts
import os, re, json
from contextlib import contextmanager
from urllib.parse import urlparse, unquote
from pg8000 import dbapi as pg

def _conn_params():
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
def get_conn():
    params = _conn_params()
    conn = pg.connect(**params)
    try:
        yield conn
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()

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
