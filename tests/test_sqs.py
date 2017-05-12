# Copyright 2016 Capital One Services, LLC
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

from common import BaseTest


class TestSqsAction(BaseTest):

    def test_sqs_delete(self):
        session_factory = self.replay_flight_data(
            'test_sqs_delete')
        client = session_factory().client('sqs')
        p = self.load_policy({
            'name': 'sqs-delete',
            'resource': 'sqs',
            'filters': [{'QueueArn': 'arn:aws:sqs:us-west-2:644160558196:test-sqs'},
                        {'KmsMasterKeyId': 'alias/aws/sqs'}],
            'actions': [
                {'type': 'delete'}]},
            session_factory=session_factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_sqs_set_encryption(self):
        session_factory = self.replay_flight_data(
            'test_sqs_set_encryption')
        client = session_factory().client('sqs')
        p = self.load_policy({
            'name': 'sqs-delete',
            'resource': 'sqs',
            'filters': [{'QueueArn': 'arn:aws:sqs:us-west-2:644160558196:test-sqs'}],
            'actions': [
                {'type': 'set-encryption',
                 'key': 'c7n-test'}]},
            session_factory=session_factory)
        resources = p.run()
        check_master_key = client.get_queue_attributes(
            QueueUrl=
            'https://sqs.us-west-2.amazonaws.com/644160558196/test-sqs',
            AttributeNames=['All'])['Attributes']['KmsMasterKeyId']
        self.assertEqual(check_master_key, '44d25a5c-7efa-44ed-8436-c9821qe872m3')
