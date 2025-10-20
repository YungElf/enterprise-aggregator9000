from dataclasses import dataclass
from pathlib import Path
import os
from dotenv import load_dotenv

def _load_env_once():
    here = Path(__file__).resolve()
    backend_dir = here.parent.parent.parent   # .../backend
    root_dir = backend_dir.parent             # repo root
    for p in (root_dir / ".env", backend_dir / ".env"):
        if p.is_file():
            load_dotenv(dotenv_path=str(p), override=False)
            os.environ.setdefault("__ENV_LOADED_FROM__", str(p))
            return
    load_dotenv()  # fallback: current CWD

_load_env_once()

@dataclass(frozen=True)
class Settings:
    tz: str
    pg_url: str
    splunk_host: str    # may be ""
    splunk_user: str
    splunk_password: str
    splunk_verify_tls: bool
    apigee_planet: str
    apigee_org: str
    apigee_env: str

def _req(name: str) -> str:
    v = os.getenv(name)
    if not v:
        where = os.getenv("__ENV_LOADED_FROM__", "CWD/.env")
        raise RuntimeError(f"Missing env var: {name} (loaded from {where})")
    return v

def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in {"1","true","t","yes","y"}

def load_settings() -> Settings:
    return Settings(
        tz=os.getenv("AGG_TZ", "America/Phoenix"),
        pg_url=_req("AGG_PG_URL"),
        splunk_host=os.getenv("SPLUNK_HOST", ""),  # OPTIONAL now
        splunk_user=_req("SPLUNK_USERNAME"),
        splunk_password=_req("SPLUNK_PASSWORD"),
        splunk_verify_tls=_bool("SPLUNK_VERIFY_TLS", True),
        apigee_planet=_req("APIGEE_PLANET"),       # e.g., R0/R1/R2
        apigee_org=_req("APIGEE_ORG"),
        apigee_env=os.getenv("APIGEE_ENV", "e3"),  # must be key in ENV_OBJ_DICT
    )
