import logging
import re
import os
import inspect
from typing import Any, List

from apigee.apigee_api import ApigeeManagement

log = logging.getLogger()


# Minimal constants and helpers to support parsing
APIGEE_SECURITY_TYPES = ["oauthv2", "verify_api_key", "hmac", "ip_allow_list", "cors"]
APIGEE_OAUTH = "oauthv2"
VERIFY_API_KEY = "verify_api_key"
IP_ALLOW_LIST = "ip_allow_list"
APIGEE_CORS = "cors"
NONE = "none"

SECURITY_POLICY_BUCKETS = {
    "hmac": {
        "callout_urls": [],
        "shared_flow_bundles": ["hmac"],
    },
}

APIGEE_SSL_TYPES = ["mtls", "one_way_ssl"]
REPORT_CELL_TRUE = True
REPORT_CELL_FALSE = False

SSL_BUCKETS = {
    "mtls": {"hosts": ["secure-mtls", "mtls"]},
    "one_way_ssl": {"hosts": ["secure", "secure-prod", "secure-nonprod"]},
}


def safe_open_xml_list(obj, keys):
    cur = obj
    for k in keys:
        cur = cur.get(k) if isinstance(cur, dict) else None
        if cur is None:
            return []
    if isinstance(cur, list):
        return cur
    if isinstance(cur, dict) and "Step" in cur:
        return [cur]
    return []


def _normalize_planet(planet: str, selected_env) -> str:
    p = (str(planet or "")).strip().upper()
    if p in {"PROD", "PRODUCTION"}: return "R3"
    if p in {"TEST", "NONPROD", "NP"}: return "R2"
    if p in {"DEV"}: return "R1"
    env_name = str(getattr(selected_env, "name", "")).strip().upper()
    if p in {"", "DEFAULT"}:
        if env_name.endswith("E3"): return "R3"
        if env_name.endswith("E2"): return "R2"
        if env_name.endswith("E1"): return "R1"
    return planet


def initialize_apigee_obj(planet, org, selected_env):
    username = os.getenv("APIGEE_USERNAME")
    password = os.getenv("APIGEE_PASSWORD")

    planet = _normalize_planet(planet, selected_env)

    # Build kwargs based on ApigeeManagement __init__ signature
    try:
        sig = inspect.signature(ApigeeManagement.__init__)
        param_names = {p for p in sig.parameters.keys() if p != "self"}
    except Exception:
        param_names = set()

    value_by_key = {
        "environment": selected_env,
        "env": selected_env,
        "env_name": getattr(selected_env, "name", None) or selected_env,
        "planet": planet,
        "region": planet,
        "org": org,
        "organization": org,
        "org_name": org,
        "username": username,
        "user": username,
        "password": password,
        "pwd": password,
        "token": os.getenv("APIGEE_TOKEN"),
    }
    kwargs = {k: v for k, v in value_by_key.items() if k in param_names and v is not None}

    # Try kwargs-only init first to avoid wrong positional arity
    try:
        if kwargs:
            client = ApigeeManagement(**kwargs)
        else:
            client = ApigeeManagement()
        log.debug(f"ApigeeManagement initialized with kwargs: {sorted(kwargs.keys())}")
        return client
    except Exception as e:
        last_exc = e

    # Then try common positional permutations (with optional auth kwargs)
    auth_kwargs = {}
    if username is not None:
        auth_kwargs["username"] = username
    if password is not None:
        auth_kwargs["password"] = password

    attempts = (
        lambda: ApigeeManagement(selected_env, planet, org, **auth_kwargs),
        lambda: ApigeeManagement(planet, org, selected_env, **auth_kwargs),
        lambda: ApigeeManagement(selected_env, org, **auth_kwargs),
        lambda: ApigeeManagement(org, selected_env, **auth_kwargs),
        lambda: ApigeeManagement(org, **auth_kwargs),
        lambda: ApigeeManagement(**auth_kwargs),
        lambda: ApigeeManagement(),
    )
    for ctor in attempts:
        try:
            client = ctor()
            log.debug("ApigeeManagement initialized via positional attempt")
            return client
        except Exception as e:
            last_exc = e
            continue

    raise RuntimeError(f"Unable to initialize ApigeeManagement; last error: {last_exc}")


def get_all_active_proxies_by_deployment_env(all_info: dict, deployment_env: str) -> list[tuple[str, str]]:
    env_info = [x for x in all_info['environment'] if x['name'] == deployment_env][0]
    all_active_proxies = []

    for proxy in env_info['aPIProxy']:
        deployed_revisions = [rev['name'] for rev in proxy['revision'] if rev['state'] == 'deployed']
        for revision in deployed_revisions:
            all_active_proxies.append((proxy['name'], revision))

    if not all_active_proxies:
        log.warning(f"No proxies found in the selected environment: {deployment_env}")
        return []

    return all_active_proxies


def fetch_apigee_xml_data(apigee_obj, proxy_name: str, revision: str) -> tuple[dict, dict]:
    try:
        policies = apigee_obj.proxy.get_policies_summary_for_proxy_revision(proxy_name, revision)
        used_policies, virtual_hosts, xml_dicts = parse_apigee_xml_data(apigee_obj, policies, proxy_name, revision)
        target_details = find_proxy_target_details(apigee_obj, proxy_name, revision)
        output_json = {
            "policies": used_policies,
            "virtual_hosts": list(virtual_hosts),
            "targets": target_details
        }
    except Exception as e:
        log.error(f"Error with {proxy_name} - {revision}: {e}")
        output_json = {
            "policies": [],
            "virtual_hosts": [],
            "targets": []
        }
        xml_dicts = {}
    return output_json, xml_dicts


def parse_apigee_xml_data(apigee: ApigeeManagement, policies: list[dict], proxy: str,
                          revision: str) -> tuple[list[dict], set[Any], dict]:
    flow_policies = []
    used_policies = []
    virtual_hosts = []
    xml_dict = {}

    for api_proxy in apigee.proxy.get_proxy_endpoints(proxy, revision):
        xmldict = apigee.proxy.get_proxy_endpoint_details(proxy, revision, api_proxy)

        global_policies = [step['Step']['name'] for step in
                           safe_open_xml_list(xmldict.get('preFlow', {}), ['request', 'children']) if 'preFlow' in xmldict]
        flows = safe_open_xml_list(xmldict['flows'], []) if 'flows' in xmldict and xmldict['flows'] else []
        for flow in flows:
            if 'request' not in flow or not flow['request'] or 'children' not in flow['request']:
                continue
            steps = safe_open_xml_list(flow['request'], ['children'])
            flow_policies = [*flow_policies, *[step['Step']['name'] for step in steps]]
        for policy in policies:
            if policy['policy_file_name'] in global_policies:
                policy['application_level'] = 'global'
                used_policies.append(policy)
            if policy['policy_file_name'] in flow_policies:
                policy['application_level'] = 'flow'
                used_policies.append(policy)
        proxy_virtual_hosts = xmldict['connection']['virtualHost'] if 'connection' in xmldict and 'virtualHost' in \
                                                                      xmldict['connection'] else []
        virtual_hosts = [*virtual_hosts, *proxy_virtual_hosts]
        xml_dict[api_proxy] = xmldict

    return used_policies, set(virtual_hosts), xml_dict


def find_proxy_target_details(apigee: ApigeeManagement, proxy: str, revision: str) -> List[dict]:
    target_details = {}
    for target in apigee.proxy.get_proxy_targets(proxy, revision):
        raw_details = apigee.proxy.get_proxy_target_by_name(proxy, revision, target)
        target_details[target] = {
            "url": raw_details['connection']['uRL'] if 'uRL' in raw_details['connection'] else 'N/A',
            "ssl_info": raw_details['connection']['sSLInfo'] if 'sSLInfo' in raw_details['connection'] else None,
        }
    return target_details


def identify_rate_limit(policies):
    for policy in policies:
        if policy['policy_type'] == 'SpikeArrest' and policy['rate_limit']:
            return policy['rate_limit']
    return None


def identify_threat_protections(policies):
    policy_types = [policy['policy_type'] for policy in policies]
    output = [REPORT_CELL_TRUE if protection in policy_types else REPORT_CELL_FALSE for protection in
              list({"threat_protection": "threat_protection"}.values())]
    return output


def get_virtual_host_analysis_dict(virtual_host_data) -> List[str]:
    host_types = sort_virtual_hosts(virtual_host_data)
    ssl_bool_list = [REPORT_CELL_TRUE if ssl_type in host_types else REPORT_CELL_FALSE for ssl_type in sorted(list(APIGEE_SSL_TYPES))]
    return ssl_bool_list


def get_policy_analysis_dict(policy_data) -> List[str]:
    used_security_types = identity_security_policies(policy_data)
    rate_limit = identify_rate_limit(policy_data)
    threat_protections = identify_threat_protections(policy_data)

    security_bool_list = [REPORT_CELL_TRUE if security_type in used_security_types else REPORT_CELL_FALSE for security_type in
                          sorted(list(APIGEE_SECURITY_TYPES))]

    return [*security_bool_list, rate_limit, *threat_protections]


def all_policies_disabled(policies):
    return all(str(policy['enabled']).lower() == 'false' for policy in policies)


def format_callout_url(policy):
    callout_url = policy['callout_url']
    callout_url = re.sub(r'127\.0\.0\.1:(\d*)\/', 'localhost/', str(callout_url))
    callout_url = re.sub('localhost:(\d*)\/', 'localhost/', str(callout_url))
    policy['callout_url'] = callout_url


def identity_security_policies(policies):
    used_security_types = []
    for policy in policies:
        format_callout_url(policy)
        if policy['enabled'] == 'false':
            continue
        if policy.get('cors_policy') and str(policy['cors_policy']).lower() != "none":
            used_security_types.append(APIGEE_CORS)
        for security_type in APIGEE_SECURITY_TYPES:
            if security_type == NONE:
                continue
            elif (security_type == APIGEE_OAUTH and check_for_oauth2(policy)) or \
                    (security_type == VERIFY_API_KEY and policy.get('api_key') and policy['api_key'].lower() != "none") \
                    or security_type == IP_ALLOW_LIST and policy.get('ip_allow_list') not in (None, []):
                used_security_types.append(security_type)
            else:
                check_for_security_type(**SECURITY_POLICY_BUCKETS.get(security_type, {"callout_urls": [], "shared_flow_bundles": []}), policy=policy,
                                        security_type=security_type, used_security_types=used_security_types)
    return list(set(used_security_types))


def sort_virtual_hosts(virtual_hosts):
    host_types = set()
    all_hosts_in_buckets = {host for ssl_type in SSL_BUCKETS for host in SSL_BUCKETS[ssl_type]['hosts']}
    for virtual_host in virtual_hosts:
        for ssl_type in SSL_BUCKETS:
            if virtual_host in SSL_BUCKETS[ssl_type]['hosts']:
                host_types.add(ssl_type)
                break
        if virtual_host not in all_hosts_in_buckets:
            log.debug(f"{virtual_host} not found in buckets")
    return host_types


def check_uri_prefixes(callout_url, callout_urls):
    for url in callout_urls:
        if callout_url and str(callout_url).startswith(url):
            return True
    return False


def check_for_security_type(callout_urls: list[str], shared_flow_bundles: list[str], policy, security_type: str,
                            used_security_types: list[str]):
    if policy.get('shared_flow_bundle') in shared_flow_bundles or check_uri_prefixes(policy.get('callout_url'), callout_urls):
        used_security_types.append(security_type)


def check_for_oauth2(policy):
    if not policy.get('policy_name'):
        return False
    return '_oauth2_' in policy['policy_name'].lower() and policy.get('callout_url') == 'None' and not policy.get('api_key')
