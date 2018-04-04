# Copyright 2017 Capital One Services, LLC
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
import base64
import boto3
import click
import jsonschema
import yaml

from slackclient import SlackClient
from c7n import sqsexec
from c7n.utils import get_retry


log = logging.getLogger('c7n.slack')

<<<<<<< HEAD
retry = get_retry(('Throttling',), log_retries=True)


# Create class for consumer
=======
CONFIG_SCHEMA = {
    'type': 'object',
    'additionalProperties': False,
    'required': ['slacker'],
    'properties': {
        'slacker': {
            'type': 'object',
            'additionalProperties': False,
            'required': ['type', 'client_id', 'client_secret'],
            'properties': {
                'type': {'enum': ['slack']},
                'client_id': {'type': 'string'},
                'client_secret': {'type': 'string'}
            }
        }
    }
}

retry = get_retry(('Throttling',), log_retries=True)


def get_token(client_id, client_secret):
    sc = SlackClient("")

    # Request the auth tokens from Slack
    auth_response = sc.api_call(
        "oauth.access",
        client_id=client_id,
        client_secret=client_secret
    )
    print auth_response['access_token']

@click.group()
def cli():
    """Custodian Slacker"""


@cli.command(name='slacker')
@click.option('-c', '--config', required=True, help="Config file")
@click.option('--concurrency', default=5)
@click.option('--verbose/--no-verbose', default=False)
>>>>>>> 1a0882f83492eb2ae14957e80f2494a5345f6625
def consumer(config, concurrency, verbose=False):
    """"""
    logging.basicConfig(level=(verbose and logging.DEBUG or logging.INFO))
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.DEBUG)

    with open(config) as fh:
        config = yaml.safe_load(fh.read())
    jsonschema.validate(config, CONFIG_SCHEMA)

<<<<<<< HEAD
    print config.get("slacker").get("encrypted_token")

    sc = SlackClient(config.get("slacker").get("encrypted_token"))
    print sc.api_call("chat.postMessage",
                        channel="c7n-slacker-bot",
                        text="Hello from Python! :tada:")
=======
    print config.get("slacker")
    get_token(config.get("slacker").get("client_id"), config.get("slacker").get("client_secret"))


>>>>>>> 1a0882f83492eb2ae14957e80f2494a5345f6625
    #
    # region_name = config.get('region', 'us-east-1')
    #
    # # decrypt KMS password
    # log.debug('decrypting kms password')
    # if config.get('kms_decrypt_password', True) and config['indexer'].get('password'):
    #     kms = boto3.Session(region_name=region_name).client('kms')
    #     config['indexer']['password'] = kms.decrypt(
    #         CiphertextBlob=base64.b64decode(config['indexer']['password']))['Plaintext']
    #
    # sqs_consumer = SQSConsumer(url=url, config=config, concurrency=concurrency)
    #
    # log.debug('processing messages from sqs')
    # sqs_consumer.process()


if __name__ == '__main__':
    try:
        cli()
    except Exception as e:
        log.error(e)
        import traceback, pdb, sys
        traceback.print_exc()
        pdb.post_mortem(sys.exc_info()[-1])