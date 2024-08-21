import argparse
import os
import datetime
import re
from datetime import datetime, timedelta
import logging
import traceback
import intersight.api.cond_api
import tabulate

import intersight
import intersight.api
import intersight.api.fabric_api
import intersight.api.organization_api
import intersight.model
import intersight.model.organization_organization_relationship
import intersight.signing

Parser = argparse.ArgumentParser(description='KeyCheck Intersight credentials')

FORMAT = '%(asctime)-15s [%(levelname)s] [%(filename)s:%(lineno)s] %(message)s'
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger('openapi')

def format_time(dt):
    s = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')
    return f"{s[:-3]}Z"

def print_results_to_table(obj, ignored_fields=[]):
    headers = []
    if 'intersight' in str(type(obj[0])):
        headers = [ k for k in obj[0].to_dict().keys() if k not in ignored_fields ]
    else:
        headers = [ k for k in obj[0].keys() if k not in ignored_fields ]

    entries = []
    for entry in obj:
        row = []
        for h in headers:
            row.append(entry.get(h))
        entries.append(row)
    
    print(tabulate(entries, headers=headers, tablefmt='orgtbl'))

def config_credentials():
    Parser.add_argument('--url', default='https://eu-central-1.intersight.com',
                        help='Use eu-central-1.intersight.com for IMM keys and intersight.com for non IMM keys')
    Parser.add_argument('--ignore-tls', action='store_true',
                        help='Set to ignore TLS server-side certificate verification')
    
    Parser.add_argument('--https-proxy', default=os.getenv('https_proxy'),
                        help='Set https proxy (usually not needed)')
    Parser.add_argument('--api-key-id', default=os.getenv('INTERSIGHT_API_KEY_ID'),
                        help='Set the API key ID if not saved or found in environment variable.')
    Parser.add_argument('--api-key-file', default=os.getenv('INTERSIGHT_API_PRIVATE_KEY', '~/Downloads/SecretKey.txt'),
                        help='Set the path for the api key file if not found inside environment variable')
    
    args = Parser.parse_args()

    if args.api_key_id and args.api_key_file:
        with open(args.api_key_file, 'r') as file:
            private_key = file.read()
        regex = re.compile(r"\s*-----BEGIN (.*)-----\s+")
        match = regex.match(private_key)
        if not match:
            raise ValueError("API key file does not have a valid PEM pre boundary")
        pem_header = match.group(1)

        # HTTP signature scheme
        if pem_header == 'RSA PRIVATE KEY':
            signing_scheme = intersight.signing.SCHEME_RSA_SHA256
            signing_algorithm = intersight.signing.ALGORITHM_RSASSA_PKCS1v15
        elif pem_header == 'EC PRIVATE KEY':
            signing_scheme = intersight.signing.SCHEME_HS2019
            signing_algorithm = intersight.signing.ALGORITHM_ECDSA_MODE_FIPS_186_3
        else:
            raise Exception("Unsupported key: {0}".format(pem_header))
        
        configuration = intersight.Configuration(
            host = args.url,
            signing_info=intersight.HttpSigningConfiguration(
                key_id=args.api_key_id,
                private_key_path=args.api_key_file,
                signing_scheme=signing_scheme,
                signing_algorithm=signing_algorithm,
                hash_algorithm=intersight.signing.HASH_SHA256,
                signed_headers=[intersight.signing.HEADER_REQUEST_TARGET,
                                intersight.signing.HEADER_CREATED,
                                intersight.signing.HEADER_EXPIRES,
                                intersight.signing.HEADER_HOST,
                                intersight.signing.HEADER_DATE,
                                intersight.signing.HEADER_DIGEST,
                                'Content-Type',
                                'User-Agent'],
                                signature_max_validity=timedelta(minutes=5)
            )
        )
    else:
        raise Exception("Must provide API key information")

    if args.ignore_tls:
        configuration.verify_ssl = False

    configuration.proxy = args.https_proxy
    api_client = intersight.ApiClient(configuration)
    api_client.set_default_header('referer', args.url)
    api_client.set_default_header('x-requested-with', 'XMLHttpRequest')
    api_client.set_default_header('Content-Type', 'application/json')

    return api_client

def get_organization(organization_name = 'default'):
    api_instance = intersight.api.organization_api.OrganizationApi(api_client)
    odata = {"filter":f"Name eq {organization_name}"}
    organizations = api_instance.get_organization_organization_list(**odata)
    if organizations.results and len(organizations.results) > 0:
        moid = organizations.results[0].moid
    else:
        print("No organization was found with given name")
        sys.exit(1)
    #return intersight.model.organization_organization_relationship.OrganizationOrganizationRelationship(class_id="mo.MoRef", object_type="organization.Organization", moid=moid)
    return organizations



if __name__ == "__main__":
    api_client = config_credentials()

    orga = get_organization()

    print(f"Using organizational unit: {orga.results[0].name}")

    try:
        api_instance = intersight.api.cond_api.CondApi(api_client)

        search_period = datetime.now() - timedelta(hours=4)
        query_filter = f"Severity eq Critical and LastTransitionTime gt {format_time(search_period)}"
        query_select = "LastTransitionTime,Description"

        alarm_query = api_instance.get_cond_alarm_list(filter=query_filter, select=query_select)

        if alarm_query.results:
            print_results_to_table(alarm_query.results, ignored_fields=['class_id', 'object_type'])
        else:
            print('No alarms found')

    except intersight.OpenApiException as e:
        logger.error("Exception when calling API: %s\n" % e)
        traceback.print_exc()
