import logging
import requests
from requests.auth import HTTPBasicAuth

from flask_app.web.constants import SPLUNK_API_BY_ENV
from flask_app.web.utils.vault_utils import get_env_value

log = logging.getLogger()


def fetch_splunk_data(env: str, query: str):
    """
    Fetch data from Splunk API for the given environment.
    Uses host/port from SPLUNK_API_BY_ENV defined in apigee_constants.py.
    """
    # Pull env config (E1/E2/E3)
    env_cfg = SPLUNK_API_BY_ENV.get(env.upper())
    if not env_cfg:
        raise ValueError(f"No Splunk configuration found for environment {env}")

    host = env_cfg["host"]
    port = env_cfg["port"]

    url = f"https://{host}:{port}/services/search/jobs"

    username = get_env_value("SPLUNK_USERNAME")
    password = get_env_value("SPLUNK_PASSWORD")

    log.info(f"Connecting to Splunk at {host}:{port} for env {env}")

    try:
        response = requests.post(
            url,
            data={"search": query},
            auth=HTTPBasicAuth(username, password),
            verify=True,  # keep TLS validation
            timeout=60
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        log.error(f"Splunk request failed for {env} at {host}:{port}: {e}")
        raise
