from dataclasses import dataclass
import os
from dotenv import load_dotenv

load_dotenv()  

@dataclass(frozen=True)
class Settings:
    tz: str
    pg_url: str
    splunk_host: str
    splunk_user: str
    splunk_password: str
    splunk_verify_tls: bool
    apigee_planet: str
    apigee_org: str
    apigee_env: str

def _req(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise RuntimeError(f"Missing env var: {name}")
    return v

def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1","true","t","yes","y")

def load_settings() -> Settings:
    return Settings(
        tz=os.getenv("AGG_TZ", "America/Phoenix"),
        pg_url=_req("AGG_PG_URL"),
        splunk_host=_req("SPLUNK_HOST"),
        splunk_user=_req("SPLUNK_USERNAME"),
        splunk_password=_req("SPLUNK_PASSWORD"),
        splunk_verify_tls=_bool("SPLUNK_VERIFY_TLS", True),
        apigee_planet=_req("APIGEE_PLANET"),
        apigee_org=_req("APIGEE_ORG"),
        apigee_env=os.getenv("APIGEE_ENV", "e3"),
    )
