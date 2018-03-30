# Copyright 2018 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import boto3
import yaml
from ldap import LdapLookup


def session_factory(config):
    return boto3.Session(
        region_name=config['region'],
        profile_name=config.get('profile'))

def set_config_defaults(config):
    config.setdefault('region', 'us-east-1')
    config.setdefault('ses_region', config.get('region'))
    config.setdefault('memory', 1024)
    config.setdefault('runtime', 'python2.7')
    config.setdefault('timeout', 300)
    config.setdefault('subnets', None)
    config.setdefault('security_groups', None)
    config.setdefault('contact_tags', [])
    config.setdefault('ldap_uri', None)
    config.setdefault('ldap_bind_dn', None)
    config.setdefault('ldap_bind_user', None)
    config.setdefault('ldap_bind_password', None)

def get_config(parser_config):
    with open(parser_config) as fh:
        config = yaml.load(fh.read(), Loader=yaml.SafeLoader)
        set_config_defaults(config)
    return config

def get_logger(debug=False):
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=log_format)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    if debug:
        logging.getLogger('botocore').setLevel(logging.DEBUG)
        debug_logger = logging.getLogger('c7n-slacker')
        debug_logger.setLevel(logging.DEBUG)
        return debug_logger
    else:
        return logging.getLogger('c7n-slacker')

def start():
    parser_config = 'config.yml'
    config = get_config(parser_config)

    aws_session = session_factory(config)
    logger = get_logger(debug=False)

    ldap_resource = LdapLookup(config, aws_session, logger)

    results = ldap_resource.search_ldap()

    print results["mail"][0]

    # print results

if __name__ == '__main__':
    try:
        start()
    except Exception as e:
        import traceback, pdb, sys
        print traceback.print_exc()
        pdb.post_mortem(sys.exc_info()[-1])