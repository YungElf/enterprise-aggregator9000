create table if not exists apigee_config_data (
  apiproxy            text primary key,
  base_path           text,
  target_host         text,
  security_mechanism  text,
  virtual_hosts       jsonb,
  ssl_profile_flags   jsonb,
  consumer_count      int,
  developer_apps      jsonb,
  updated_at          timestamptz not null default now()
);
