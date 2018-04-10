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

import click
from sqs_handler import SQSHandler

CONFIG_SCHEMA = {
    'type': 'object',
    'additionalProperties': False,
    'required': ['queue_url', 'role', 'from_address'],
    'properties': {
        'queue_url': {'type': 'string'},
        'contact_tags': {'type': 'array', 'items': {'type': 'string'}},

        # Mailer Infrastructure Config
        'role': {'type': 'string'},
        'cache_engine': {'type': 'string'},
        'smtp_server': {'type': 'string'},
        'smtp_port': {'type': 'integer'},
        'smtp_ssl': {'type': 'boolean'},
        'smtp_username': {'type': 'string'},
        'smtp_password': {'type': 'string'},
        'ldap_email_key': {'type': 'string'},
        'ldap_uid_tags': {'type': 'array', 'items': {'type': 'string'}},
        'debug': {'type': 'boolean'},
        'ldap_uid_regex': {'type': 'string'},
        'ldap_uri': {'type': 'string'},
        'ldap_bind_dn': {'type': 'string'},
        'ldap_bind_user': {'type': 'string'},
        'ldap_uid_attribute': {'type': 'string'},
        'ldap_manager_attribute': {'type': 'string'},
        'ldap_email_attribute': {'type': 'string'},
        'ldap_bind_password_in_kms': {'type': 'boolean'},
        'ldap_bind_password': {'type': 'string'},
        'cross_accounts': {'type': 'object'},
        'ses_region': {'type': 'string'},
        'redis_host': {'type': 'string'},
        'redis_port': {'type': 'integer'},

        # SDK Config
        'profile': {'type': 'string'},
        'http_proxy': {'type': 'string'},
        'https_proxy': {'type': 'string'},

        # Mapping account / emails
        'account_emails': {'type': 'object'}
    }
}

@click.group()
def cli():
    """Custodian Slacker"""


@cli.command(name='slacker')
@click.option('-c', '--config', required=True, help="Config file")
def start(config):

    slacker_handler = SQSHandler(config)

    messages = slacker_handler.process_sqs()

    results = slacker_handler.search_ldap(messages)

if __name__ == '__main__':
    try:
        start()
    except Exception as e:
        import traceback, pdb, sys
        print traceback.print_exc()
        pdb.post_mortem(sys.exc_info()[-1])