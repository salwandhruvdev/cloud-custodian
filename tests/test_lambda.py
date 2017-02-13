# Copyright 2016-2017 Capital One Services, LLC
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


class LambdaTest(BaseTest):

    def test_delete(self):
        factory = self.replay_flight_data('test_aws_lambda_delete')
        p = self.load_policy({
            'name': 'lambda-events',
            'resource': 'lambda',
            'filters': [
                {'FunctionName': 'superduper'}],
            'actions': [{'type': 'delete'}]
            }, session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['FunctionName'], 'superduper')
        client = factory().client('lambda')
        self.assertEqual(client.list_functions()['Functions'], [])

    def test_event_source(self):
        factory = self.replay_flight_data('test_aws_lambda_source')
        p = self.load_policy({
            'name': 'lambda-events',
            'resource': 'lambda',
            'filters': [
                {'type': 'event-source',
                 'key': '',
                 'value': 'not-null'}]},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 2)
        self.assertEqual(
            {r['c7n.EventSources'][0] for r in resources},
            set(['iot.amazonaws.com']))

    def test_sg_filter(self):
        factory = self.replay_flight_data('test_aws_lambda_sg')

        p = self.load_policy({
            'name': 'sg-lambda',
            'resource': 'lambda',
            'filters': [
                {'FunctionName': 'mys3'},
                {'type': 'security-group',
                 'key': 'GroupName',
                 'value': 'default'}
                ]}, session_factory=factory)
        resources = p.run()
        self.assertEqual(resources[0]['FunctionName'], 'mys3')
        self.assertEqual(
            resources[0]['c7n.matched-security-groups'],
            ['sg-f9cc4d9f'])
