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