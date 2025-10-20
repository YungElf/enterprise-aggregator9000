import os
from typing import Dict


def get_amex_proxies_verified() -> Dict[str, str]:
    """
    Build a requests-compatible proxies dict for Amex corporate tunneling.

    Env vars supported (first non-empty wins):
      - AMEX_PROXY_ADS or PROXY_ADS or HTTP_PROXY_USER
      - AMEX_PROXY_SECRET or PROXY_SECRET or HTTP_PROXY_PASS

    Example output:
      {
        "http":  "http://ADS_ID:SECRET@proxy.aexp.com:8080",
        "https": "http://ADS_ID:SECRET@proxy.aexp.com:8080",
      }
    """
    ads = os.getenv("AMEX_PROXY_ADS") or os.getenv("PROXY_ADS") or os.getenv("HTTP_PROXY_USER")
    secret = os.getenv("AMEX_PROXY_SECRET") or os.getenv("PROXY_SECRET") or os.getenv("HTTP_PROXY_PASS")
    if not (ads and secret):
        return {}
    auth = f"{ads}:{secret}"
    proxy = f"http://{auth}@proxy.aexp.com:8080"
    return {"http": proxy, "https": proxy}
