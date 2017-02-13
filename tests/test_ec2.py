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
import unittest

from jsonschema.exceptions import ValidationError

from c7n.filters import FilterValidationError
from c7n.resources import ec2
from c7n.resources.ec2 import actions, QueryFilter
from c7n import tags, utils

from common import BaseTest


class TestTagAugmentation(BaseTest):

    def test_tag_augment_empty(self):
        session_factory = self.replay_flight_data(
            'test_ec2_augment_tag_empty')
        # recording was modified to be sans tags
        ec2 = session_factory().client('ec2')
        policy = self.load_policy({
            'name': 'ec2-tags',
            'resource': 'ec2'},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 0)

    def test_tag_augment(self):
        session_factory = self.replay_flight_data(
            'test_ec2_augment_tags')
        # recording was modified to be sans tags
        ec2 = session_factory().client('ec2')
        policy = self.load_policy({
            'name': 'ec2-tags',
            'resource': 'ec2',
            'filters': [
                {'tag:Env': 'Production'}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)


class TestMetricFilter(BaseTest):

    def test_metric_filter(self):
        session_factory = self.replay_flight_data(
            'test_ec2_metric')
        ec2 = session_factory().client('ec2')
        policy = self.load_policy({
            'name': 'ec2-utilization',
            'resource': 'ec2',
            'filters': [
                {'type': 'metrics',
                 'name': 'CPUUtilization',
                 'days': 3,
                 'value': 1.5}
            ]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)


class TestHealthEventsFilter(BaseTest):
    def test_ec2_health_events_filter(self):
        session_factory = self.replay_flight_data(
            'test_ec2_health_events_filter')
        policy = self.load_policy({
            'name': 'ec2-health-events-filter',
            'resource': 'ec2',
            'filters': [
                {'type': 'health-event'}
            ]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 0)


class TestTagTrim(BaseTest):

    def test_ec2_tag_trim(self):
        self.patch(tags.TagTrim, 'max_tag_count', 10)
        session_factory = self.replay_flight_data(
            'test_ec2_tag_trim')
        ec2 = session_factory().client('ec2')
        start_tags = {
            t['Key']: t['Value'] for t in
            ec2.describe_tags(
                Filters=[{'Name': 'resource-id',
                          'Values': ['i-fdb01920']}])['Tags']}
        policy = self.load_policy({
            'name': 'ec2-tag-trim',
            'resource': 'ec2',
            'filters': [
                {'type': 'tag-count', 'count': 10}],
            'actions': [
                {'type': 'tag-trim',
                 'space': 1,
                 'preserve': [
                     'Name',
                     'Env',
                     'Account',
                     'Platform',
                     'Classification',
                     'Planet'
                     ]}
                ]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)
        end_tags = {
            t['Key']: t['Value'] for t in
            ec2.describe_tags(
                Filters=[{'Name': 'resource-id',
                          'Values': ['i-fdb01920']}])['Tags']}

        self.assertEqual(len(start_tags)-1, len(end_tags))
        self.assertTrue('Containers' in start_tags)
        self.assertFalse('Containers' in end_tags)


class TestVolumeFilter(BaseTest):

    def test_ec2_attached_ebs_filter(self):
        session_factory = self.replay_flight_data(
            'test_ec2_attached_ebs_filter')
        policy = self.load_policy({
            'name': 'ec2-unencrypted-vol',
            'resource': 'ec2',
            'filters': [
                {'type': 'ebs',
                 'key': 'Encrypted',
                 'value': False}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)

    # DISABLED / Re-record flight data on public account
    def test_ec2_attached_volume_skip_block(self):
        session_factory = self.replay_flight_data(
            'test_ec2_attached_ebs_filter')
        policy = self.load_policy({
            'name': 'ec2-unencrypted-vol',
            'resource': 'ec2',
            'filters': [
                {'type': 'ebs',
                 'skip-devices': ['/dev/sda1', '/dev/xvda', '/dev/sdb1'],
                 'key': 'Encrypted',
                 'value': False}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 0)


class TestResizeInstance(BaseTest):

    def test_ec2_resize(self):
        # preconditions - three instances (2 m4.4xlarge, 1 m4.1xlarge)
        # one of the instances stopped
        session_factory = self.replay_flight_data('test_ec2_resize')
        policy = self.load_policy({
            'name': 'ec2-resize',
            'resource': 'ec2',
            'filters': [
                {'type': 'value',
                 'key': 'State.Name',
                 'value': ['running', 'stopped'],
                 'op': 'in'},
                {'type': 'value',
                 'key': 'InstanceType',
                 'value': ['m4.2xlarge', 'm4.4xlarge'],
                 'op': 'in'},
                ],
            'actions': [
                {'type': 'resize',
                 'restart': True,
                 'default': 'm4.large',
                 'type-map': {
                     'm4.4xlarge': 'm4.2xlarge'}}]
            }, session_factory=session_factory)

        resources = policy.run()
        self.assertEqual(len(resources), 3)

        stopped, running = [], []
        for i in resources:
            if i['State']['Name'] == 'running':
                running.append(i['InstanceId'])
            if i['State']['Name'] == 'stopped':
                stopped.append(i['InstanceId'])

        instances = utils.query_instances(
            session_factory(),
            InstanceIds=[r['InstanceId'] for r in resources])

        cur_stopped, cur_running = [], []
        for i in instances:
            if i['State']['Name'] == 'running':
                cur_running.append(i['InstanceId'])
            if i['State']['Name'] == 'stopped':
                cur_stopped.append(i['InstanceId'])

        cur_running.sort()
        running.sort()

        self.assertEqual(cur_stopped, stopped)
        self.assertEqual(cur_running, running)
        instance_types = [i['InstanceType'] for i in instances]
        instance_types.sort()
        self.assertEqual(
            instance_types,
            list(sorted(['m4.large', 'm4.2xlarge', 'm4.2xlarge'])))


class TestStateTransitionAgeFilter(BaseTest):

    def test_ec2_state_transition_age(self):
        session_factory = self.replay_flight_data(
            'test_ec2_state_transition_age_filter'
        )
        policy = self.load_policy({
            'name': 'ec2-state-transition-age',
            'resource': 'ec2',
            'filters': [
                {'State.Name': 'running'},
                {'type': 'state-age',
                 'days': 30}]},
            session_factory=session_factory)
        resources = policy.run()
        #compare stateTransition reason to expected
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['StateTransitionReason'], 'User initiated (2015-11-25 10:11:55 GMT)')


class TestImageAgeFilter(BaseTest):

    def test_ec2_image_age(self):
        session_factory = self.replay_flight_data(
            'test_ec2_image_age_filter')
        policy = self.load_policy({
            'name': 'ec2-image-age',
            'resource': 'ec2',
            'filters': [
                {'State.Name': 'running'},
                {'type': 'image-age',
                 'days': 30}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)


class TestImageFilter(BaseTest):

    def test_ec2_image(self):
        session_factory = self.replay_flight_data(
            'test_ec2_image_filter')
        policy = self.load_policy({
            'name': 'ec2-image',
            'resource': 'ec2',
            'filters': [
                {'type': 'image', 'key': 'Public', 'value': True}
                ]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['InstanceId'], 'i-039628786cabe8c16')


class TestInstanceAge(BaseTest):

    # placebo doesn't record tz information
    def test_ec2_instance_age(self):
        session_factory = self.replay_flight_data(
            'test_ec2_instance_age_filter')
        policy = self.load_policy({
            'name': 'ec2-instance-age',
            'resource': 'ec2',
            'filters': [
                {'State.Name': 'running'},
                {'type': 'instance-age',
                 'days': 0}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)


class TestTag(BaseTest):

    def test_ec2_tag(self):
        session_factory = self.replay_flight_data(
            'test_ec2_mark')
        policy = self.load_policy({
            'name': 'ec2-test-mark',
            'resource': 'ec2',
            'filters': [
                {'State.Name': 'running'}],
            'actions': [
                {'type': 'tag',
                 'key': 'Testing',
                 'value': 'Testing123'}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)

    def test_ec2_tag_errors(self):
        # Specifying both 'key' and 'tag' is an error
        policy = {
            'name': 'ec2-tag-error',
            'resource': 'ec2',
            'actions': [{
                'type': 'tag',
                'key': 'Testing',
                'tag': 'foo',
                'value': 'TestingError'
            }]
        }
        self.assertRaises(FilterValidationError, self.load_policy, policy)

        # Invalid op for 'mark-for-op' action
        policy = {
            'name': 'ec2-tag-error',
            'resource': 'ec2',
            'actions': [{
                'type': 'mark-for-op',
                'op': 'fake',
            }]
        }
        self.assertRaises(FilterValidationError, self.load_policy, policy)
        
    def test_ec2_untag(self):
        session_factory = self.replay_flight_data(
            'test_ec2_untag')
        policy = self.load_policy({
            'name': 'ec2-test-unmark',
            'resource': 'ec2',
            'filters': [
                {'tag:Testing': 'not-null'}],
            'actions': [
                {'type': 'remove-tag',
                 'tags': ['Testing']}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)

    def test_ec2_normalize_tag(self):
        session_factory = self.replay_flight_data(
            'test_ec2_normalize_tag')

        policy = self.load_policy({
            'name': 'ec2-test-normalize-tag-lower',
            'resource': 'ec2',
            'filters': [
                {'tag:Testing-lower': 'not-null'}],
            'actions': [
                {'type': 'normalize-tag',
                 'key': 'Testing-lower',
                 'action': 'lower'}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)

        policy = self.load_policy({
            'name': 'ec2-test-normalize-tag-upper',
            'resource': 'ec2',
            'filters': [
                {'tag:Testing-upper': 'not-null'}],
            'actions': [
                {'type': 'normalize-tag',
                 'key': 'Testing-upper',
                 'action': 'upper'}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)

        policy = self.load_policy({
            'name': 'ec2-test-normalize-tag-title',
            'resource': 'ec2',
            'filters': [
                {'tag:Testing-title': 'not-null'}],
            'actions': [
                {'type': 'normalize-tag',
                 'key': 'Testing-title',
                 'action': 'title'}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)

        policy = self.load_policy({
            'name': 'ec2-test-normalize-tag-strip',
            'resource': 'ec2',
            'filters': [
                {'tag:Testing-strip': 'not-null'}],
            'actions': [
                {'type': 'normalize-tag',
                 'key': 'Testing-strip',
                 'action': 'strip',
                 'value': 'blah'}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)

    def test_ec2_rename_tag(self):
        session_factory = self.replay_flight_data(
            'test_ec2_rename_tag')

        policy = self.load_policy({
            'name': 'ec2-rename-start',
            'resource': 'ec2',
            'filters': [
                {'tag:Testing': 'present'}
                ]}, session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 3)

        policy = self.load_policy({
            'name': 'ec2-rename-tag',
            'resource': 'ec2',
            'actions': [{
                'type': 'rename-tag',
                'old_key': 'Testing',
                'new_key': 'Testing1'}]}, session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 3)

        policy = self.load_policy({
            'name': 'ec2-rename-end',
            'resource': 'ec2',
            'filters': [
                {'tag:Testing1': 'present'}
                ]}, session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 3)


class TestStop(BaseTest):

    def test_ec2_stop(self):
        session_factory = self.replay_flight_data(
            'test_ec2_stop')
        policy = self.load_policy({
            'name': 'ec2-test-stop',
            'resource': 'ec2',
            'filters': [
                {'tag:Testing': 'not-null'}],
            'actions': [
                {'type': 'stop'}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)


class TestStart(BaseTest):

    def test_ec2_start(self):
        session_factory = self.replay_flight_data(
            'test_ec2_start')
        policy = self.load_policy({
            'name': 'ec2-test-start',
            'resource': 'ec2',
            'filters': [],
            'actions': [
                {'type': 'start'}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 2)


class TestOr(BaseTest):

    def test_ec2_or_condition(self):
        session_factory = self.replay_flight_data(
            'test_ec2_stop')
        policy = self.load_policy({
            'name': 'ec2-test-snapshot',
            'resource': 'ec2',
            'filters': [
                {"or": [
                    {"tag:Name": "CompileLambda"},
                    {"tag:Name": "Spinnaker"}]}]
        }, session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 2)
        self.assertEqual(
            sorted([r['InstanceId'] for r in resources]),
            [u'i-13413bd7', u'i-1aebf7c0'])


class TestSnapshot(BaseTest):

    def test_ec2_snapshot_no_copy_tags(self):
        session_factory = self.replay_flight_data(
            'test_ec2_snapshot')
        policy = self.load_policy({
            'name': 'ec2-test-snapshot',
            'resource': 'ec2',
            'filters': [
                {'tag:Name': 'CompileLambda'}],
            'actions': [
                {'type': 'snapshot'}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)

    def test_ec2_snapshot_copy_tags(self):
        session_factory = self.replay_flight_data(
            'test_ec2_snapshot')
        policy = self.load_policy({
            'name': 'ec2-test-snapshot',
            'resource': 'ec2',
            'filters': [
                {'tag:Name': 'CompileLambda'}],
            'actions': [
                {'type': 'snapshot', 'copy-tags': ['ASV' 'Testing123']}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)


class TestEC2QueryFilter(unittest.TestCase):

    def test_parse(self):
        self.assertEqual(QueryFilter.parse([]), [])
        x = QueryFilter.parse(
            [{'instance-state-name': 'running'}])
        self.assertEqual(
            x[0].query(),
            {'Name': 'instance-state-name', 'Values': ['running']})

        self.assertTrue(
            isinstance(
                QueryFilter.parse(
                    [{'tag:ASV': 'REALTIMEMSG'}])[0],
                QueryFilter))

        self.assertRaises(
            ValueError,
            QueryFilter.parse,
            [{'tag:ASV': None}])


class TestTerminate(BaseTest):

    def test_ec2_terminate(self):
        # Test conditions: single running instance, with delete protection
        session_factory = self.replay_flight_data('test_ec2_terminate')
        p = self.load_policy({
            'name': 'ec2-term',
            'resource': 'ec2',
            'filters': [{'InstanceId': 'i-017cf4e2a33b853fe'}],
            'actions': [
                {'type': 'terminate',
                 'force': True}]},
           session_factory=session_factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        instances = utils.query_instances(
            session_factory(), InstanceIds=['i-017cf4e2a33b853fe'])
        self.assertEqual(instances[0]['State']['Name'], 'shutting-down')


class TestDefaultVpc(BaseTest):

    def test_ec2_default_vpc(self):
        session_factory = self.replay_flight_data('test_ec2_default_vpc')
        p = self.load_policy(
            {'name': 'ec2-default-filters',
             'resource': 'ec2',
             'filters': [
                 {'type': 'default-vpc'}]},
            config={'region': 'us-west-2'},
            session_factory=session_factory)

        resources = p.run()

        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['InstanceId'], 'i-0bfe468063b02d018')


class TestActions(unittest.TestCase):

    def test_action_construction(self):

        self.assertIsInstance(
            actions.factory('mark', None),
            tags.Tag)

        self.assertIsInstance(
            actions.factory('stop', None),
            ec2.Stop)

        self.assertIsInstance(
            actions.factory('terminate', None),
            ec2.Terminate)


class TestModifySecurityGroupsActionSchema(BaseTest):
    def test_remove_dependencies(self):
        policy = {
            'name': 'remove-with-no-isolation-or-add',
            'resource': 'ec2',
            'actions': [
                {'type': 'modify-security-groups', 'remove': 'matched'}
            ]
        }
        self.assertRaises(
            ValidationError, self.load_policy, data=policy, validate=True)

    def test_invalid_remove_params(self):
        # basestring invalid
        policy = {
            'name': 'remove-with-incorrect-param-string',
            'resource': 'ec2',
            'actions': [
                {'type': 'modify-security-groups', 'remove': 'none'}
            ]
        }
        self.assertRaises(
            ValidationError, self.load_policy, data=policy, validate=True)

        # list - one valid, one invalid
        policy = {
            'name': 'remove-with-incorrect-param-list',
            'resource': 'ec2',
            'actions': [
                {'type': 'modify-security-groups', 'remove': [
                    'invalid-sg', 'sg-abcd1234']}
            ]
        }
        self.assertRaises(
            ValidationError, self.load_policy, policy, validate=True)

    def test_invalid_add_params(self):
        # basestring invalid
        policy = {
            'name': 'add-with-incorrect-param-string',
            'resource': 'ec2',
            'actions': [
                {'type': 'modify-security-groups', 'add': 'none'},
                {'type': 'modify-security-groups', 'add': [
                    'invalid-sg', 'sg-abcd1234']}
            ]
        }
        self.assertRaises(
            ValidationError, self.load_policy, data=policy, validate=True)

    def test_invalid_isolation_group_params(self):
        policy = {
            'name': 'isolation-group-with-incorrect-param-string',
            'resource': 'ec2',
            'actions': [
                {'type': 'modify-security-groups', 'isolation-group': 'none'}
            ]
        }
        self.assertRaises(
            ValidationError, self.load_policy, data=policy, validate=True)

        # list - one valid, one invalid
        policy = {
            'name': 'isolation-group-with-incorrect-param-list',
            'resource': 'ec2',
            'actions': [
                {'type': 'modify-security-groups',
                 'isolation-group': ['invalid-sg', 'sg-abcd1234']}
            ]
        }
        self.assertRaises(
            ValidationError, self.load_policy, data=policy, validate=True)


class TestModifySecurityGroupAction(BaseTest):
    def test_security_group_type(self):
        # Test conditions:
        #   - running two instances; one with TestProductionInstanceProfile
        #     and one with none
        #   - security group named TEST-PROD-ONLY-SG exists in VPC and is
        #     attached to both test instances
        session_factory = self.replay_flight_data(
            'test_ec2_security_group_filter')

        # Catch on anything that uses the *PROD-ONLY* security groups but isn't in a prod role
        policy = self.load_policy({
            'name': 'restrict-sensitive-sg',
            'resource': 'ec2',
            'filters': [
                {'or': [
                    {'and': [
                        {'type': 'value', 'key': 'IamInstanceProfile.Arn',
                         'value': '(?!.*TestProductionInstanceProfile)(.*)',
                         'op': 'regex'},
                        {'type': 'value', 'key': 'IamInstanceProfile.Arn',
                         'value': 'not-null'}
                    ]},
                    {'type': 'value', 'key': 'IamInstanceProfile',
                     'value': 'absent'}
                ]},
                {'type': 'security-group', 'key': 'GroupName',
                 'value': '(.*PROD-ONLY.*)', 'op': 'regex'},

            ]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['InstanceId'], 'i-0dd3919bc5bac1ea8')

    def test_security_group_modify_groups_action(self):
        # Test conditions:
        #   - running two instances; one with TestProductionInstanceProfile
        #     and one with none
        #   - security group named TEST-PROD-ONLY-SG exists in VPC and is
        #     attached to both test instances
        session_factory = self.replay_flight_data(
            'test_ec2_modify_groups_action')
        client = session_factory().client('ec2')

        default_sg_id = client.describe_security_groups(
            GroupNames=[
                'default',
            ]
        )['SecurityGroups'][0]['GroupId']


        # Catch on anything that uses the *PROD-ONLY* security groups but isn't in a prod role
        policy = self.load_policy({
            'name': 'remove-sensitive-sg',
            'resource': 'ec2',
            'filters': [
                {'or': [
                    {'and': [
                        {'type': 'value', 'key': 'IamInstanceProfile.Arn',
                         'value': '(?!.*TestProductionInstanceProfile)(.*)',
                         'op': 'regex'},
                        {'type': 'value', 'key': 'IamInstanceProfile.Arn',
                         'value': 'not-null'}
                    ]},
                    {'type': 'value', 'key': 'IamInstanceProfile',
                     'value': 'absent'}
                ]},
                {'type': 'security-group', 'key': 'GroupName',
                 'value': '(.*PROD-ONLY.*)', 'op': 'regex'}],
            'actions': [
                {'type': 'modify-security-groups', 'remove': 'matched',
                 'isolation-group': default_sg_id}]
            },
            session_factory=session_factory)
        before_action_resources = policy.run()
        after_action_resources = policy.run()
        self.assertEqual(len(before_action_resources), 1)
        self.assertEqual(
            before_action_resources[0]['InstanceId'], 'i-0dd3919bc5bac1ea8')
        self.assertEqual(len(after_action_resources), 0)

    def test_invalid_modify_groups_schema(self):
        policy = {
            'name': 'invalid-modify-security-groups-action',
            'resource': 'ec2',
            'filters': [],
            'actions': [
                {'type': 'modify-security-groups', 'change': 'matched'}
            ]
        }
        self.assertRaises(
            ValidationError, self.load_policy, policy, validate=True)

    def test_ec2_add_security_groups(self):
        # Test conditions:
        #   - running one instance with TestProductionInstanceProfile
        #   - security group named TEST-PROD-ONLY-SG exists in VPC and
        #     is attached to test instance
        #   - security group with id sg-8a4b64f7 exists in VPC and is selected
        #     in a policy to be attached
        session_factory = self.replay_flight_data(
            'test_ec2_add_security_groups')
        policy = self.load_policy({
            'name': 'add-sg-to-prod-instances',
            'resource': 'ec2',
            'filters': [
                {'type': 'value', 'key': 'IamInstanceProfile.Arn',
                 'value': '(.*TestProductionInstanceProfile)', 'op': 'regex'}
            ],
            'actions': [
                {'type': 'modify-security-groups', 'add': 'sg-8a4b64f7'}
            ]
        },
        session_factory=session_factory)

        first_resources = policy.run()
        self.assertEqual(len(
            first_resources[0]['NetworkInterfaces'][0]['Groups']), 1)
        second_resources = policy.run()
        self.assertEqual(len(
            second_resources[0]['NetworkInterfaces'][0]['Groups']), 2)

