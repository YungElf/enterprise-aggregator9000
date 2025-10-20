
# Aggregator → Explorer Nightly Feeds — Context Pack (Drop‑in)

> Use this file as “everything you need to know” for teammates, vendors, or other AI tools. It’s intentionally self‑contained and safe (no secrets). Replace placeholders marked LIKE_THIS before use.

---

## 0) TL;DR

We’re extending the **Aggregator** to produce **nightly, file‑only exports** for **Explorer** (the internal API discovery/analytics UI). Sources:

- **GRT** (Gateway Reporting Tool): API **metadata** (inventory/ownership).
- **ELF** (Enterprise Logging Framework): API **transactions** (gateway logs).
- **Platform Health**: gateway **SLIs** (availability, 5xx rate, latency), ideally from **ELF Health export**; fallback **Splunk saved search**.

Deliverables (per UTC date `YYYY-MM-DD`):
```
exports/YYYY-MM-DD/
  grt_config_YYYY-MM-DD_full.ndjson.gz    + .manifest.json
  elf_txn_YYYY-MM-DD_full.ndjson.gz       + .manifest.json
  elf_health_YYYY-MM-DD_full.ndjson.gz    + .manifest.json
```
Everything is **PII-neutral** and **no database** is required for MVP.

---

## 1) Objectives & Scope

- **Objective:** Give Explorer a minimal, stable contract (files + manifests) so their dashboards can light up quickly.
- **Scope (MVP):** nightly full exports for **GRT config**, **ELF transactions**, **Platform Health**.
- **Out of scope (MVP):** realtime streaming; long-term storage; SLO math; DB schemas; PII transforms.

**Why file‑only?** Simple to validate, easy to ingest, and trivial to switch sources later without breaking Explorer.

---

## 2) Glossary

- **Aggregator**: Our internal service + scripts that consolidate API metadata and telemetry from multiple sources.
- **Explorer**: Internal UI/data service that surfaces API inventory and metrics for stakeholders.
- **GRT**: Gateway Reporting Tool (source of API metadata such as owners, proxies, lifecycle).
- **ELF**: Enterprise Logging Framework (centralized gateway logging/telemetry platform).
- **EAG/EWP/Apigee**: API gateways (EAG/EWP primary; Apigee may appear in metadata).
- **Splunk**: Log analytics platform (fallback data source for Platform Health if ELF export not available).

---

## 3) Data Feeds & Minimal Schemas

### 3.1 GRT Config (nightly full)
One line per API asset.
```json
{
  "api_key": "string",
  "api_name": "string",
  "proxy_name": "string",
  "env": "prod|test|dev",
  "gateway": "EAG|EWP|Apigee|…",
  "business_unit": "string|null",
  "owner_email": "string|null",
  "lifecycle_stage": "dev|test|prod|retired|null",
  "pii_flag": true|false|null,
  "service_name": "string|null",
  "version": "string|null",
  "tags": ["string"],
  "src_updated_at": "ISO-8601",
  "_source": "GRT"
}
```

### 3.2 ELF Transactions (nightly, full day)
Raw transaction events (Explorer will aggregate).
```json
{
  "event_ts": "ISO-8601",
  "env": "prod|test|dev",
  "gateway": "EAG|EWP",
  "region": "string|null",
  "proxy_name": "string|null",
  "api_key": "string|null",
  "http_method": "GET|POST|…",
  "path_template": "string|null",
  "status_code": 200,
  "latency_total_ms": 123,
  "_source": "ELF"
}
```

### 3.3 Platform Health (nightly full; hourly/minute buckets inside file OK)
```json
{
  "bucket_ts": "ISO-8601",
  "env": "prod|test|dev",
  "gateway": "EAG|EWP",
  "region": "string|null",
  "component": "router|mp|oauth|…",
  "reqs": 12345,
  "errors": 123,
  "error_rate": 0.0099,
  "p95_ms": 120,
  "p99_ms": 220,
  "availability_pct": 99.98,
  "_source": "ELF|Splunk"
}
```

---

## 4) File Contract & Integrity

Per feed, per date:
- **Data file**: `*.ndjson.gz` (one JSON object per line; gzip compressed).
- **Manifest**: `*.manifest.json` with:
```json
{
  "date": "YYYY-MM-DD",
  "recordCount": 123456,
  "sha256": "hex-of-compressed-file",
  "schemaVersion": "1.0.0",
  "source": "GRT|ELF|Splunk|ELF (NOT CONFIGURED)|UNKNOWN",
  "generator": "aggregator-nightly-collector",
  "generatedAt": "ISO-8601 UTC"
}
```
Manifests let downstreams verify integrity and completeness.

---

## 5) Scheduling & Retention

- **Schedule:** Nightly at 03:00 UTC (configurable).
- **Range:** Yesterday’s full UTC day.
- **Retention (MVP):** Last 7–30 days in the export location (TBD by storage owner).

---

## 6) Integration Points

- **Explorer**: reads files directly or via their ingest job. We expose a stable path/prefix.
- **Later**: If Explorer wants GraphQL/REST instead of files, we can surface read-only endpoints over the same normalized schemas.

---

## 7) Environment & Configuration (.env Template)

```
# --- Output ---
OUT_DIR=./exports
LOG_LEVEL=INFO

# --- Proxy (if required by corporate network) ---
PROXY_USER=YOUR_ADS_USERNAME
PROXY_PASS=YOUR_PROXY_PASSWORD_OR_TOKEN
PROXY_HOST=proxy.aexp.com
PROXY_PORT=8080
HTTP_PROXY=http://$PROXY_USER:$PROXY_PASS@$PROXY_HOST:$PROXY_PORT
HTTPS_PROXY=http://$PROXY_USER:$PROXY_PASS@$PROXY_HOST:$PROXY_PORT
NO_PROXY=.aexp.com,localhost,127.0.0.1

# --- GRT (KNOWN) ---
GRT_BASE_URL=https://grt.api.aexp.com
GRT_BEARER_TOKEN=REDACTED_TOKEN

# --- ELF (UNKNOWN UNTIL CONFIRMED) ---
ELF_BASE_URL=https://elf.api.aexp.com
ELF_TXN_PATH=/v1/exports/eag/transactions         # NEEDS CONFIRMATION
ELF_HEALTH_PATH=/v1/exports/eag/health            # NEEDS CONFIRMATION
ELF_BEARER_TOKEN=REDACTED_TOKEN
# Optional mTLS
ELF_CLIENT_CERT=/path/to/client.crt
ELF_CLIENT_KEY=/path/to/client.key
ELF_CA_BUNDLE=/path/to/ca-bundle.crt

# --- Splunk fallback for Platform Health ---
SPLUNK_BASE=https://splunk.internal:8089          # NEEDS CONFIRMATION
SPLUNK_TOKEN=REDACTED_TOKEN
SPLUNK_SAVED_SEARCH_HEALTH=elf_platform_health_daily  # NEEDS CONFIRMATION
```

---

## 8) Network & Runner Notes

- **Enterprise GitHub runner** is **in-network** and behind corp proxy.
- For **SFTP/FTP** steps, ensure `NO_PROXY` includes the target host or run on a runner that can directly reach it.
- For **ELF/HTTPS** calls, `requests` should honor `HTTP(S)_PROXY` automatically (or build proxies explicitly).

---

## 9) Source Discovery (What We Need From Teams)

### From **ELF/Observability**
- `ELF_BASE_URL` + **daily export** paths:
  - **Transactions**: `ELF_TXN_PATH` (pattern + date parameter: `?date=YYYY-MM-DD` or `/YYYY-MM-DD`).
  - **Platform Health**: `ELF_HEALTH_PATH` (same).
- **Auth**: bearer scope name; mTLS (client cert/key + CA) if required.
- **Format**: `NDJSON` vs `JSON` (gzipped?).
- **Sample**: 20–50 lines of each export for normalizer validation.
- **Proxy**: confirm if internal proxy must be used/bypassed (`NO_PROXY`).

### From **Explorer**
- Confirm **which fields** they will use for MVP:
  - Transactions: `calls, error_rate, p95_ms` (they can derive from raw events).
  - Health: `availability_pct, error_rate, p95_ms/p99_ms`.
- Confirm **ingest path/pattern** and how they’ll **verify manifests**.

### From **Splunk** (if ELF Health export not available)
- `SPLUNK_BASE`, `SPLUNK_TOKEN`, `SPLUNK_SAVED_SEARCH_HEALTH` returning the fields in §3.3.  
- Time window: yesterday 00:00:00Z–23:59:59Z.

---

## 10) Repo Placement & Code Layout (inside Aggregator)

```
collectors/nightly_file_export/
  README.md
  requirements.txt
  .env.example
  scripts/
    run_now.sh
    verify_exports.sh
  collector/
    __init__.py
    main.py                 # --jobs all|grt|txn|health --date YYYY-MM-DD --out ./exports
    logging_setup.py
    filesystem.py           # atomic write, gzip, manifest(sha256)
    http_client.py          # proxies + optional bearer/mTLS
    normalizers/
      grt_normalizer.py
      elf_txn_normalizer.py
      elf_health_normalizer.py
    sources/
      grt_rest.py
      elf_export.py         # placeholders call ELF endpoints once provided
      splunk_saved_search.py
    runners/
      run_grt_config.py
      run_elf_txn.py
      run_elf_health.py
```

---

## 11) Example Flows

### 11.1 GRT (REST)
1. GET `${GRT_BASE_URL}/v1/apis?date=YYYY-MM-DD` (placeholder path; adjust to actual).
2. Normalize each record to §3.1.
3. Write `grt_config_DATE_full.ndjson.gz` + manifest.

### 11.2 ELF Transactions
1. GET `${ELF_BASE_URL}${ELF_TXN_PATH}?date=YYYY-MM-DD` (or path segment).
2. Input may be **NDJSON**, **JSON array**, or **gzipped** NDJSON → auto-detect.
3. Normalize to §3.2; write file + manifest.

### 11.3 Platform Health (ELF preferred; Splunk fallback)
- **Preferred**: GET `${ELF_BASE_URL}${ELF_HEALTH_PATH}?date=YYYY-MM-DD` → normalize (§3.3).
- **Fallback**: POST `${SPLUNK_BASE}/services/search/jobs/export` with `search savedsearch:${SPLUNK_SAVED_SEARCH_HEALTH} earliest_time=DATET00:00:00Z latest_time=DATET23:59:59Z output_mode=json` → normalize (§3.3).

---

## 12) Test Plan (Dry‑run OK)

- With only `.env.example` populated (no real endpoints), running:
  ```bash
  python -m collector.main --jobs all --date 2025-10-11
  ```
  creates the folder structure and empty NDJSON + manifests (`recordCount: 0`), proving the contract.
- Once endpoints are provided, the same command produces populated files; manifests should show non‑zero `recordCount`.

---

## 13) Risks & Mitigations

- **No ELF export available** → Use **Splunk saved search** for health; transactions can also fall back to Splunk if desperately needed.
- **Proxy blocks** → Configure `HTTP(S)_PROXY`/`NO_PROXY`; or run on a runner with direct reachability.
- **Schema drift** → Treat extra fields as pass‑through; keep minimal set stable in outputs.
- **Large volumes** → Stream NDJSON; avoid loading full day into memory.

---

## 14) Troubleshooting Cheat Sheet

- **SFTP upload fails**: verify port 22 reachability, add `NO_PROXY` for host, ensure SSH key format & known_hosts (`ssh-keyscan`).  
- **FTPS stalls**: PASV range blocked; use SFTP or open PASV ports.  
- **ELF call times out**: corporate proxy path; set proxies or `NO_PROXY`.  
- **403/401**: bearer token scope or mTLS missing.  
- **Gzip vs NDJSON**: auto‑detect; if unknown `Content-Type`, try gzip decode then line‑split.

---

## 15) Ready‑to‑Send Messages

**To ELF/Observability (Transactions + Health):**
```
Hi ELF team — I’m delivering nightly files to Explorer from Aggregator.
Please share the daily export endpoints for yesterday (UTC):

1) Transactions (EAG/EWP):
   - Base + path (e.g., /v1/exports/eag/transactions)
   - Date filter (?date=YYYY-MM-DD or path)
   - Auth (bearer scope, mTLS cert/CA), proxy requirements
   - Format (NDJSON vs JSON; gzip?)
   - 20–50 line sample

2) Platform Health:
   - Same items as above. If no export, please share the Splunk saved search name for daily health rollups.

Thanks! — Alex
```

**To Explorer:**
```
We’ll publish nightly files with minimal fields (txn + health + config). 
Confirm the columns you’ll consume for MVP and your preferred ingest path/prefix.
```

---

## 16) Future Phases (Not MVP)

- Optional DB for historical queries (same schemas).
- Per‑API aggregated facts (`calls`, `p95`, `error_rate`) as separate views.
- Streaming or intra‑day cadence if needed.
- Cost/SLO overlays and ownership rollups.

---

## 17) Explicit Unknowns (to resolve before “real data”)

- Actual ELF export endpoints and auth model.  
- Whether Platform Health is exposed via ELF or only Splunk today.  
- Explorer’s exact field subset and ingest path/prefix.

---

**End of Context Pack** — replace placeholders and ship.
