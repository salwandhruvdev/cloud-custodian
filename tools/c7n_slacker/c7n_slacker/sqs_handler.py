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
import base64
import json
from email.utils import parseaddr

import yaml
import boto3
import os

import zlib

from botocore.exceptions import ClientError
from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPSocketOpenError
from c7n import sqsexec

class SQSHandler(object):

    def __init__(self, config, logger):
        self.config = config
        self.session = self.session_factory(self.config)
        self.logger = logger
        self.base_dn   = self.config.get('ldap_bind_dn')
        self.email_key = self.config.get('ldap_email_key', 'mail')
        self.uid_key   = self.config.get('ldap_uid_attribute_name', 'sAMAccountName')
        self.manager_attr = self.config.get('ldap_manager_attribute', 'manager')
        self.attributes = ['displayName', self.uid_key, self.email_key, self.manager_attr]

    def format_struct(evt):
        return json.dumps(evt, indent=2, ensure_ascii=False)

    def resource_format(self, r, r_type):
        if r_type == 'ec2':
            tag_map = {t['Key']: t['Value'] for t in r.get('Tags', ())}
            return "%s %s %s %s %s %s" % (
                r['InstanceId'],
                r.get('VpcId', 'NO VPC!'),
                r['InstanceType'],
                r.get('LaunchTime'),
                tag_map.get('Name', ''),
                r.get('PrivateIpAddress'))
        elif r_type == 'ami':
            return "%s %s %s" % (
                r['Name'], r['ImageId'], r['CreationDate'])
        elif r_type == 's3':
            return "%s" % (r['Name'])
        elif r_type == 'ebs':
            return "%s %s %s %s" % (
                r['VolumeId'],
                r['Size'],
                r['State'],
                r['CreateTime'])
        elif r_type == 'rds':
            return "%s %s %s %s" % (
                r['DBInstanceIdentifier'],
                "%s-%s" % (
                    r['Engine'], r['EngineVersion']),
                r['DBInstanceClass'],
                r['AllocatedStorage'])
        elif r_type == 'asg':
            tag_map = {t['Key']: t['Value'] for t in r.get('Tags', ())}
            return "%s %s %s" % (
                r['AutoScalingGroupName'],
                tag_map.get('Name', ''),
                "instances: %d" % (len(r.get('Instances', []))))
        elif r_type == 'elb':
            tag_map = {t['Key']: t['Value'] for t in r.get('Tags', ())}
            if 'ProhibitedPolicies' in r:
                return "%s %s %s %s" % (
                    r['LoadBalancerName'],
                    "instances: %d" % len(r['Instances']),
                    "zones: %d" % len(r['AvailabilityZones']),
                    "prohibited_policies: %s" % ','.join(
                        r['ProhibitedPolicies']))
            return "%s %s %s" % (
                r['LoadBalancerName'],
                "instances: %d" % len(r['Instances']),
                "zones: %d" % len(r['AvailabilityZones']))
        elif r_type == 'redshift':
            return "%s %s %s" % (
                r['ClusterIdentifier'],
                'nodes:%d' % len(r['ClusterNodes']),
                'encrypted:%s' % r['Encrypted'])
        elif r_type == 'emr':
            return "%s status:%s" % (
                r['Id'],
                r['Status']['State'])
        elif r_type == 'cfn':
            return "%s" % (
                r['StackName'])
        elif r_type == 'launch-config':
            return "%s" % (
                r['LaunchConfigurationName'])
        elif r_type == 'security-group':
            name = r.get('GroupName', '')
            for t in r.get('Tags', ()):
                if t['Key'] == 'Name':
                    name = t['Value']
            return "%s %s %s inrules: %d outrules: %d" % (
                name,
                r['GroupId'],
                r.get('VpcId', 'na'),
                len(r.get('IpPermissions', ())),
                len(r.get('IpPermissionsEgress', ())))
        elif r_type == 'log-group':
            if 'lastWrite' in r:
                return "name: %s last_write: %s" % (
                    r['logGroupName'],
                    r['lastWrite'])
            return "name: %s" % (r['logGroupName'])
        elif r_type == 'cache-cluster':
            return "name: %s created: %s status: %s" % (
                r['CacheClusterId'],
                r['CacheClusterCreateTime'],
                r['CacheClusterStatus'])
        elif r_type == 'cache-snapshot':
            return "name: %s cluster: %s source: %s" % (
                r['SnapshotName'],
                r['CacheClusterId'],
                r['SnapshotSource'])
        elif r_type == 'redshift-snapshot':
            return "name: %s db: %s" % (
                r['SnapshotIdentifier'],
                r['DBName'])
        elif r_type == 'ebs-snapshot':
            return "name: %s date: %s" % (
                r['SnapshotId'],
                r['StartTime'])
        elif r_type == 'subnet':
            return "%s %s %s %s %s %s" % (
                r['SubnetId'],
                r['VpcId'],
                r['AvailabilityZone'],
                r['State'],
                r['CidrBlock'],
                r['AvailableIpAddressCount'])
        elif r_type == 'account':
            return " %s %s" % (
                r['account_id'],
                r['account_name'])
        elif r_type == 'cloudtrail':
            return " %s %s" % (
                r['account_id'],
                r['account_name'])
        elif r_type == 'vpc':
            return "%s " % (
                r['VpcId'])
        elif r_type == 'iam-group':
            return " %s %s %s" % (
                r['GroupName'],
                r['Arn'],
                r['CreateDate'])
        elif r_type == 'rds-snapshot':
            return " %s %s %s" % (
                r['DBSnapshotIdentifier'],
                r['DBInstanceIdentifier'],
                r['SnapshotCreateTime'])
        elif r_type == 'iam-user':
            return " %s " % (
                r['UserName'])
        elif r_type == 'iam-role':
            return " %s %s " % (
                r['RoleName'],
                r['CreateDate'])
        elif r_type == 'iam-policy':
            return " %s " % (
                r['PolicyName'])
        elif r_type == 'iam-profile':
            return " %s " % (
                r['InstanceProfileId'])
        elif r_type == 'dynamodb-table':
            return "name: %s created: %s status: %s" % (
                r['TableName'],
                r['CreationDateTime'],
                r['TableStatus'])
        elif r_type == "sqs":
            return "QueueUrl: %s QueueARN: %s " % (
                r['QueueUrl'],
                r['QueueArn'])
        else:
            return "%s" % r

    def process_sqs(self):

        messages = []

        sqs_fetch = sqsexec.MessageIterator(client=self.session.client('sqs'), queue_url=self.config.get('queue_url'), timeout=0)
        self.logger.info('processing queue messages')

        for m in sqs_fetch:
            message = m['Body']
            try:
                self.logger.debug('Valid JSON')
                msg_json = json.loads(zlib.decompress(base64.b64decode(message)))
                self.logger.info("Acct: %s,  msg: %s, resource type: %s, count: %d, policy: %s, recipients: %s, action_desc: %s, violation_desc: %s" % (
                    msg_json.get('account', 'na'),
                    m['MessageId'],
                    msg_json['policy']['resource'],
                    len(msg_json['resources']),
                    msg_json['policy']['name'],
                    ', '.join(msg_json['action']['to']),
                    msg_json['action']['action_desc'],
                    msg_json['action']['violation_desc']))
                messages.append(msg_json)

                # sqs_fetch.ack(m)

            except ValueError:
                self.logger.warning("Invalid JSON")
                pass

        return messages

    def session_factory(self, config):

        if config.get('region') is None:
            set_region = os.environ['AWS_DEFAULT_REGION']
        else:
            set_region = config.get('region')

        if config.get('profile') is None:
            set_profile = os.environ['AWS_DEFAULT_PROFILE']
        else:
            set_profile = config.get('profile')

        return boto3.Session(
            region_name=set_region,
            profile_name=set_profile)

    def get_resource_owner_values(self, sqs_message):
        if 'Tags' in sqs_message:
            tags = {tag['Key']: tag['Value'] for tag in sqs_message['Tags']}
        else:
            self.logger.debug("No tags found on resource. Skipping")
            return None, None

        if tags:
            for contact_tag in self.config.get('contact_tags'):
                for tag in tags:
                    if tag == contact_tag:
                        self.logger.debug("resource owner match: %s - %s", contact_tag, tags[contact_tag])
                        return tags[contact_tag], contact_tag
        else:
            self.logger.debug("No tags found.")
            return None, None

    def target_is_email(self, target):
        if parseaddr(target)[1] and '@' in target and '.' in target:
            return True
        else:
            return False

    def search_ldap(self, messages):
        message_delimiter = 0
        resource_delimiter = 0
        connection = self.get_ldap_session()
        resource_list = {}
        target_list = {}
        if messages is None:
            self.logger.info("No messages left to process. Exiting SQS handler.")
            return
        for m in messages:
            for r in m['resources']:
                if 'resource-owner' in m['action']['to']:
                    try:
                        resource_owner_value, matched_tag = self.get_resource_owner_values(r)
                    except Exception as e:
                        self.logger.warning("Error fetching resource owner value: %s" % e)
                    if r is None or resource_owner_value is None:
                        self.logger.debug("Resource details not found. Continuing....")
                        continue
                    else:
                        resource_string = self.resource_format(r, m['policy']['resource'])
                        self.logger.debug("resource string: %s", resource_string)
                        resource_handler = {resource_delimiter: {'resource_string': resource_string}}
                        if (self.target_is_email(resource_owner_value)) is True:
                            self.logger.debug("%s %s: %s" % (resource_string, matched_tag, resource_owner_value))
                            self.logger.debug("Email address found. Passing back to handler.")
                            resource_handler[resource_delimiter].update({'resource_owner_value': resource_owner_value})
                        elif (resource_owner_value.find("arn:aws:sns") != -1):
                                self.logger.debug("Contact method is SNS topic. Skipping.")
                                continue
                        else:
                            self.logger.debug("ID number found. Doing LDAP lookup.")
                            ldap_filter = '(%s=%s)' % (self.uid_key, resource_owner_value)
                            connection.search(self.base_dn, ldap_filter, attributes=self.attributes)
                            if len(connection.entries) == 0:
                                self.logger.warning("user not found. base_dn: %s filter: %s", self.base_dn, ldap_filter)
                                continue
                            elif len(connection.entries) > 1:
                                self.logger.warning("too many results for search")
                                continue
                            self.logger.debug("%s %s: %s" % (self.resource_format(r, m['policy']['resource']), matched_tag, connection.entries[0]['mail']))
                            self.logger.debug("LDAP lookup complete. Passing back to handler.")
                            resource_handler.update({
                                resource_delimiter: {'resource_owner_value': connection.entries[0]['mail']}})

                        resource_handler[resource_delimiter].update(
                            {'resource_type': m['policy']['resource']})
                        resource_handler[resource_delimiter].update(
                            {'action_desc': m['action']['action_desc']})
                        resource_handler[resource_delimiter].update(
                            {'violation_desc': m['action']['violation_desc']})

                        resource_list.update(resource_handler)

                        resource_delimiter += 1

            target_list.update(resource_list)
            message_delimiter += 1

        return target_list

    def get_ldap_session(self):
        try:
            if self.config.get('ldap_bind_password', None):
                ldap_bind_password = self.session.client('kms').decrypt(
                    CiphertextBlob=base64.b64decode(self.config.get('ldap_bind_password')))[
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
        return self.get_connection(self.config.get('ldap_uri'), self.config.get('ldap_bind_user'), ldap_bind_password)

    def get_connection(self, ldap_uri, ldap_bind_user, ldap_bind_password):
        try:
            server = Server(ldap_uri, use_ssl=True)
            return Connection(
                server, user=ldap_bind_user, password=ldap_bind_password,
                auto_bind=True,
                receive_timeout=30,
                auto_referrals=False,
            )
        except LDAPSocketOpenError:
            self.logger.error('Not able to establish a connection with LDAP.')
