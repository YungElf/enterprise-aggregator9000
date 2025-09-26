create table if not exists apigee_metrics (
  month              date primary key,
  onboarded_apis     int,
  peak_tps           int,
  avg_tps            numeric(10,2),
  new_consumers      int,
  active_consumers   int,
  requests           bigint,
  bytes_in           bigint,
  bytes_out          bigint
);
