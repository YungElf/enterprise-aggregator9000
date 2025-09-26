import os

E0 = "e0"
E1 = "e1"
E2 = "e2"
E3 = "e3"
LOCAL_ENV = "e1"
GITHUB_API_URL = "https://github.aexp.com/api/v3"
VAULT_SECRETS_PATH = os.getenv("VAULT_SECRETS_PATH", "/opt/epaas/vault/secrets/secrets")
PVC_BASE_PATH = "/mnt/volume"
REMOTE_CACHE_DIR = "/mnt/volume/cache"
AMEX_ENG = "amex-eng"
REPORTS_REPO_NAME = "enpr-api-mgmt_gateway-reporting"
REPORTS_REPO_BRANCH = "reports"
REPORTS_FOLDER = "reports"
FILE_RETENTION_DAYS = 7

ELF_LOGGER_ENDPOINT = {
    "e0": "https://elfingest-dev.aexp.com",
    "e1": "https://elfingest-dev.aexp.com",
    "e2": "https://elfingest-qa.aexp.com",
    "e3": "https://elfingest.aexp.com",
}

LOCAL_CACHE_DIR = './cache'
STRF_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
