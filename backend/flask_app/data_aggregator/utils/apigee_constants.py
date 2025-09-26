from apigee.constants import E1_ENV, E2_ENV, E3_ENV

possible_security_policy_types = ['ServiceCallout', 'FlowCallout', 'JavaCallout', 'VerifyAPIKey', 'OAuthV2',
                                  'BasicAuthentication', 'AccessControl']
APIGEE = 'apigee'
APIGEE_OAUTH = 'Apigee OAuth'
APIGEE_CLIENT_HMAC = 'HMAC'
MESSAGE_SIGNING = 'Message Signing'
JWT_C2B = 'JTW C2B'
JWT_B2B = 'JWT B2B'
JWT_A2A = 'JWT A2A'
LAYER_7 = 'Layer 7'
VERIFY_API_KEY = 'Verify Api Key'
NEXT_GEN_OAUTH = 'Next Gen Oauth'
CAZM = 'CAZM'
IP_ALLOW_LIST = 'IP Allow List'
MISC_SECURITY = 'Misc Security'
BASIC_AUTHENTICATION = 'Basic Authentication'
APIGEE_CORS = 'Cors'
NONE = 'Unauthenticated'
APIGEE_RATE_LIMIT = 'Rate Limit'
JSON_THREAT_PROTECTION = 'JSON Threat Protection'
XML_THREAT_PROTECTION = 'XML Threat Protection'
REGEX_THREAT_PROTECTION = 'Regex Threat Protection'

ONE_WAY_INTRANET = 'One Way Intranet'
TWO_WAY_INTRANET = 'Two Way Intranet'
ONE_WAY_INTERNET = 'One Way Internet'
TWO_WAY_INTERNET = 'Two Way Internet'
VHOSTS = 'Virtual Hosts'
HOSTS = 'Hosts'

APIGEE_B2B_ORGS = {
    'e1': ['amexe1'],
    'e2': ['amexe2', 'sandbox'],
    'e3': ['amex_prod', 'sandbox']
}

REPORT_CELL_TRUE = "T"
REPORT_CELL_FALSE = "F"

APIGEE_TARGET_URL = 'Target URL'
TWO_WAY_SSL_TO_APIGEE_TARGET = 'Target Two Way SSL'
OUTBOUND = 'Outbound'

SECURITY_POLICY_BUCKETS = {
    APIGEE_OAUTH: {
        'callout_urls': [
            'https://localhost/apiplatform/oauth/token'
        ],
        'shared_flow_bundles': []
    },
    APIGEE_CLIENT_HMAC: {
        'callout_urls': [
            'https://localhost/apiplatform/validatetoken/v1/hmac',
            'https://localhost/apiplatform/validatetoken/v2/hmac'
        ],
        'shared_flow_bundles': [
            'APIPlatform_ValidateHmac_SharedFlow_200004162_V1'
        ]
    },
    MESSAGE_SIGNING: {
        'callout_urls': [
            'https://localhost/apiplatform/v1/soapsignature/sign',
            'https://amexmktcampaigns.my.salesforce.com/services/Soap/u/30.0',
            'https://login.salesforce.com/services/Soap/u/30.0'

        ],
        'shared_flow_bundles': [
            'API_Sharedflow_SignMessage_V1'
        ]
    },
    JWT_C2B: {
        'callout_urls': [
            'https://localhost/idaas/validatetoken/v2/jwt',
            'https://localhost/iddass/validatetoken/v1',
        ],
        'shared_flow_bundles': [
            'APIPlatform_IDCJWTCallC2B_Sharedflow_200004162_v1'
        ]
    },
    JWT_B2B: {
        'callout_urls': [
            'https://localhost/idaas/validatetoken/v1/business/jwt',
            'https://localhost/security/digital/v1/okta_jwt/validation',
            'https://idcb2bjwt-green-qa.aexp.com/apiplatform/v1/idc_auth/b2b/jwt_token/validation'
        ],
        'shared_flow_bundles': [
            'APIPlatform_IDCJWTCallB2B_Sharedflow_200004162_v1'
        ]
    },
    JWT_A2A: {
        'callout_urls': [
            'https://localhost/security/digital/v1/validate_jwt'
        ],
        'shared_flow_bundles': [
            'APIPlatform_IDCJWTCallA2A_Sharedflow_200004162_v1'
        ]
    },
    LAYER_7: {
        'callout_urls': [
            'https://localhost/apiplatform/v3/oauth/validate_token',
            'https://localhost/apiplatform/v1/mactoken',
            'https://localhost/v1/oauth/validate_token',
            'https://localhost/apiplatform/v2/oauth/validate_token',
            'https://localhost/ace/v1/oauth/validate/token/mac',
            'https://localhost/v2/oauth/validate_token'
        ],
        'shared_flow_bundles': []
    },
    VERIFY_API_KEY: {
        'callout_urls': [],
        'shared_flow_bundles': []
    },
    NEXT_GEN_OAUTH: {
        'callout_urls': [
            'https://localhost/oauth/v1/token/cc/validate',
            'https://localhost/apiplatform/v6/oauth/validate_token',
            'https://localhost/apiplatform/v8/oauth/validate_token',
            'https://localhost/oauth/v2/token/cc/validate'
        ],
        'shared_flow_bundles': []
    },
    CAZM: {
        'callout_urls': [
            'https://localhost/apiplatform/cazm/v1/token/xml'
        ],
        'shared_flow_bundles': []
    },
    IP_ALLOW_LIST: {
        'callout_urls': [],
        'shared_flow_bundles': []
    },
    MISC_SECURITY: {
        'callout_urls': [
            'https://api.loungebuddy.com/validate',
            'https://localhost/apiplatform/v1/reserve/oauth/token/validation/mac',
            'https://localhost/apiplatform/v1/smsession/users/session/validation',
            'https://developer.api.intuit.com/.well-known/openid_configuration/'
        ],
        'shared_flow_bundles': [
            'APICommonComponent_FlowCallout_PreFlowAuthorization',
            'DPGMigration_Preflow_Authorization_Timestamp'
        ]
    },
    BASIC_AUTHENTICATION: {
        'callout_urls': [
        ],
        'shared_flow_bundles': [
            'API_FlowCallout_VerifyBasicAuth_V1'
        ]
    },
    APIGEE_CORS: {
        'callout_urls': [
        ],
        'shared_flow_bundles': []
    }
}

SSL_BUCKETS = {
    ONE_WAY_INTRANET: {
        'hosts': {
            'gwInternalApiC2',
            'gwInternalApi',
            'gwGDHAAPIntranet',
            'gwIntranet',
            'intranet',
            'gwIntranetSFL',
            'gwIntranetHTTP',
            'gwInternetStservices',
            'gwIntranetBeta',
            'gwGDHAAAIntranet',
            'gwInternalApiSFL',
            'gwInternalApi2T',
            'gwIntranetIDC',
            'gwIntranetSB',
            'gwsharedpocApi',
            'gwInternalApiC1',
            'gwEngineering',
            'FeatureTest',
            'gwInternalPWS',
            'gwInternalPWSTemp',
            'gwTestVHostLB',
            'gwInternalApiArena',
            'gwInternalApiArC1',
            'gwInternalApiSB',
            'gwInternalApiSbC4',
            'gwInternalApiC4',
            'gwIntranetArena'
        }
    },
    TWO_WAY_INTRANET: {
        'hosts': {
            'intranet2S',
            'gwIntranet2S',
            'gwIntranet2Sservicesout',
            'gwIntranet2Spservices2',
            'gwIntranet2Spservices',
            'gwIntranet2SFL',
            'gwInternalApi2S',
            'gwIntranetSB2S',
            'gwIntranetHTTPS',
            'gw2STesting',
            'gwIntranetCertAAS',
            'gwInternetArena2S'
        }
    },
    ONE_WAY_INTERNET: {
        'hosts': {
            'internet',
            'gwInternet',
            'gwApiInternet',
            'gwGDHAInternet',
            'gwInternetSFL',
            'gwInternetIDC',
            'gwInternetBeta',
            'gwInternetVir',
            'gwInternetSB',
            'gwInternetArena',
            'gwInternetEng'
        }
    },
    TWO_WAY_INTERNET: {
        'hosts': {
            'gwInternet2Sob',
            'gwInternet2S',
            'gwInternet2S01',
            'gwApiInternet2S',
            'gwInternet2Sgatewayservices',
            'gwInternet2Sma',
            'gwInternet2S_Safekey2.0',
            'gwInternet2S_Safekey2.0_stl',
            'gwInternet2Sservicesin',
            'gwInternet2Sservices2',
            'gwInternet2Sservices',
            'gwInternet2SservicesAddCiphers',
            'gwInternet2SservicesCAList',
            'gwInternet2Ssb',
            'gwInternetProducts',
            'gwInternetSB2S',
            'gwInternetSbOpenAmex',
            'gwInternet2S_ds_Safekey'
        }
    }
}

SPLUNK_API_BY_ENV = {
    'E1': {
        'host': 'hvidlemtwa86.phx.aexp.com',
        'port': 12011
    },
    'E2': {
        'host': 'splunkgroup5sh-e2-vip.phx.aexp.com',
        'port': 12011
    },
    'E3': {
        'host': 'insightssplunkapi.aexp.com',
        'port': 8089
    }
}

APIGEE_SECURITY_TYPES = set(SECURITY_POLICY_BUCKETS.keys())
APIGEE_SSL_TYPES = set(SSL_BUCKETS.keys())

APIGEE_REPORT_COLUMNS = f'Org,Env,Proxy,Central ID,Revision,URI,Methods,{",".join(sorted(list(APIGEE_SECURITY_TYPES)))},' \
                        f'{APIGEE_RATE_LIMIT},{JSON_THREAT_PROTECTION},{REGEX_THREAT_PROTECTION},{XML_THREAT_PROTECTION},' \
                        f'{",".join(sorted(list(APIGEE_SSL_TYPES)))},{APIGEE_TARGET_URL},{TWO_WAY_SSL_TO_APIGEE_TARGET},' \
                        f'{OUTBOUND},{VHOSTS},{HOSTS}'.split(',')

ENV_OBJ_DICT = {"e1": E1_ENV, "e2": E2_ENV, "e3": E3_ENV}

APIGEE_PROTECTION_DICT = {
    REGEX_THREAT_PROTECTION: 'RegularExpressionProtection',
    JSON_THREAT_PROTECTION: 'JSONThreatProtection',
    XML_THREAT_PROTECTION: 'XMLThreatProtection'
}
