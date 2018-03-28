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

import datetime
import logging
import math
import random
import time
from ldap3 import Connection
from ldap3.core.exceptions import LDAPSocketOpenError

import boto3
import ldap3
import click
from concurrent.futures import ProcessPoolExecutor, as_completed
from dateutil.parser import parse as parse_date
import jsonschema
import yaml
import base64
from botocore.exceptions import ClientError

from c7n import schema
from c7n.credentials import assumed_session, SessionFactory
from c7n.registry import PluginRegistry
from c7n.reports import csvout as s3_resource_parser
from c7n.resources import load_resources
from c7n.utils import chunks, dumps, get_retry, local_session

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

def start():
    parser_config = 'config.yml'
    config = get_config(parser_config)

    aws_session = session_factory(config)

    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=logging.DEBUG, format=log_format)
    logging.getLogger('botocore').setLevel(logging.WARNING)

    ldap_resource = LdapLookup(config, aws_session)

    results = ldap_resource.search_ldap()

    print results

class LdapLookup():

    def __init__(self, config, session):
        self.config      = config
        self.session     = session
        self.connection = self.get_ldap_session(
            config.get('ldap_uri'),
            config.get('ldap_bind_user', None)
        )
        self.base_dn   = config.get('ldap_bind_dn')
        self.email_key = config.get('ldap_email_key', 'mail')
        self.uid_key   = config.get('ldap_uid_attribute_name', 'sAMAccountName')

    def search_ldap(self,):
        ldap_filter = '(%s=%s)' % (self.uid_key, self.uid)
        self.connection.search(self.base_dn, ldap_filter)
        if len(self.connection.entries) == 0:
            self.log.warning("user not found. base_dn: %s filter: %s", self.base_dn)
            return {}
        if len(self.connection.entries) > 1:
            print self.connection.entries
            self.log.warning("too many results for search")
            return {}
        return self.connection.entries[0]

    def get_ldap_session(self, ldap_uri, ldap_bind_user):
        try:
            if self.config.get('ldap_bind_password', None):
                kms = self.session.client('kms')
                self.config['ldap_bind_password'] = kms.decrypt(
                    CiphertextBlob=base64.b64decode(self.config['ldap_bind_password']))[
                    'Plaintext']
        except (TypeError, base64.binascii.Error) as e:
            self.logger.warning(
                "Error: %s Unable to base64 decode ldap_bind_password, will assume plaintext." % (e)
            )
        except ClientError as e:
            if e.response['Error']['Code'] != 'InvalidCiphertextException':
                raise
            self.logger.warning(
                "Error: %s Unable to decrypt ldap_bind_password with kms, will assume plaintext." % (e)
            )
        return self.get_connection(ldap_uri, ldap_bind_user, self.config['ldap_bind_password'])

    def get_connection(self, ldap_uri, ldap_bind_user, ldap_bind_password):
        try:
            return Connection(
                ldap_uri, user=ldap_bind_user, password=ldap_bind_password,
                auto_bind=True,
                receive_timeout=30,
                auto_referrals=False,
            )
        except LDAPSocketOpenError:
            self.log.error('Not able to establish a connection with LDAP.')

if __name__ == '__main__':
    try:
        start()
    except Exception as e:
        import traceback, pdb, sys
        print traceback.print_exc()
        pdb.post_mortem(sys.exc_info()[-1])