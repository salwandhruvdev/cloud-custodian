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

retry = get_retry(('Throttling',), log_retries=True)


# Create class for consumer
def consumer(config, concurrency, verbose=False):
    """"""
    logging.basicConfig(level=(verbose and logging.DEBUG or logging.INFO))
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.DEBUG)

    with open(config) as fh:
        config = yaml.safe_load(fh.read())
    jsonschema.validate(config, CONFIG_SCHEMA)

    print config.get("slacker").get("encrypted_token")

    sc = SlackClient(config.get("slacker").get("encrypted_token"))
    print sc.api_call("chat.postMessage",
                        channel="c7n-slacker-bot",
                        text="Hello from Python! :tada:")
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