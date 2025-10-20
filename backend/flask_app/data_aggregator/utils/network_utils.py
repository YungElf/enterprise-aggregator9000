import os
from typing import Dict
from urllib.parse import quote


def get_amex_proxies_verified() -> Dict[str, str]:
    """
    Build a requests-compatible proxies dict for Amex corporate tunneling.

    Env vars supported (first non-empty wins):
      - AMEX_PROXY_ADS or PROXY_ADS or HTTP_PROXY_USER
      - AMEX_PROXY_SECRET or PROXY_SECRET or HTTP_PROXY_PASS
      - PROXY_HOST (default proxy.aexp.com)
      - PROXY_PORT (default 8080)
      - AMEX_TUNNEL_STYLE=true to swap schemes (http->https, https->http)
    """
    ads = os.getenv("AMEX_PROXY_ADS") or os.getenv("PROXY_ADS") or os.getenv("HTTP_PROXY_USER")
    secret = os.getenv("AMEX_PROXY_SECRET") or os.getenv("PROXY_SECRET") or os.getenv("HTTP_PROXY_PASS")
    if not (ads and secret):
        return {}
    host = os.getenv("PROXY_HOST", "proxy.aexp.com").strip()
    port = os.getenv("PROXY_PORT", "8080").strip()
    tunnel_style = os.getenv("AMEX_TUNNEL_STYLE", "").strip().lower() in ("1","true","t","yes","y")

    auth = f"{quote(ads, safe='')}:{quote(secret, safe='')}"
    if tunnel_style:
        # Some internal environments require swapped schemes
        return {
            "http":  f"https://{auth}@{host}:{port}",
            "https": f"http://{auth}@{host}:{port}",
        }
    # Default: http scheme for both
    proxy = f"http://{auth}@{host}:{port}"
    return {"http": proxy, "https": proxy}
