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
from __future__ import absolute_import, division, print_function, unicode_literals

from botocore.exceptions import ClientError

import json
from c7n.filters import CrossAccountAccessFilter
from c7n.manager import resources
from c7n.query import QueryResourceManager
from c7n.actions import ActionRegistry, BaseAction
from c7n.filters import FilterRegistry
from c7n.utils import (
    chunks, local_session, set_annotation, type_schema, dumps)
from concurrent.futures import as_completed

filters = FilterRegistry('ecr.filters')
actions = ActionRegistry('ecr.actions')


@resources.register('ecr')
class ECR(QueryResourceManager):

    class resource_type(object):
        service = 'ecr'
        enum_spec = ('describe_repositories', 'repositories', None)
        name = "repositoryName"
        id = "repositoryArn"
        dimension = None

    filter_registry = filters
    action_registry = actions


@filters.register('cross-account')
class ECRCrossAccountAccessFilter(CrossAccountAccessFilter):
    """Filters all EC2 Container Registries (ECR) with cross-account access

    :example:

        .. code-block: yaml

            policies:
              - name: ecr-cross-account
                resource: ecr
                filters:
                  - type: cross-account
                    whitelist_from:
                      expr: "accounts.*.accountNumber"
                      url: *accounts_url
    """
    permissions = ('ecr:GetRepositoryPolicy',)

    def process(self, resources, event=None):

        def _augment(r):
            client = local_session(self.manager.session_factory).client('ecr')
            try:
                r['Policy'] = client.get_repository_policy(
                    repositoryName=r['repositoryName'])['policyText']
            except ClientError as e:
                if e.response['Error']['Code'] == 'RepositoryPolicyNotFoundException':
                    return None
                raise
            return r

        self.log.debug("fetching policy for %d repos" % len(resources))
        with self.executor_factory(max_workers=3) as w:
            resources = list(filter(None, w.map(_augment, resources)))

        return super(ECRCrossAccountAccessFilter, self).process(resources, event)


@actions.register('remove-statements')
class RemovePolicyStatement(BaseAction):
    """Action to remove policy statements from ECR

    :example:

        .. code-block: yaml

            policies:
              - name: ecr-remove-cross-accounts
                resource: s3
                filters:
                  - type: cross-account
                actions:
                  - type: remove-statements
                    statement_ids: matched
    """

    schema = type_schema(
        'remove-statements',
        required=['statement_ids'],
        statement_ids={'oneOf': [
            {'enum': ['matched']},
            {'type': 'array', 'items': {'type': 'string'}}]})
    permissions = ("ecr:SetRepositoryPolicy",)

    def process(self, resources):
        with self.executor_factory(max_workers=3) as w:
            futures = {}
            results = []
            for resource in resources:
                futures[w.submit(self.process_registries, resource)] = resource
            for f in as_completed(futures):
                if f.exception():
                    self.log.error('error modifying registry:%s\n%s',
                                   resource['repositoryName'], f.exception())
                elif f.result():
                    results.append(resource)
            return results

    def process_registries(self, resource):
        p = resource.get('Policy')
        # print(p)
        if p is None:
            return
        else:
            p = json.loads(p)

        found = []
        statement_ids = self.data.get('statement_ids')
        statements = p.get('Statement', [])
        resource_statements = resource.get(
            CrossAccountAccessFilter.annotation_key, ())

        for s in list(statements):
            if statement_ids == 'matched':
                if s in resource_statements:
                    found.append(s)
                    statements.remove(s)
            elif s['Sid'] in self.data['statement_ids']:
                found.append(s)
                statements.remove(s)
        if not found:
            return
        #
        client = local_session(self.manager.session_factory).client('ecr')
        if not statements:
            client.delete_repository_policy(repositoryName=resource['repositoryName'])
        else:
            client.set_repository_policy(repositoryName=resource['repositoryName'], policyText=json.dumps(p))
        return {'Name': resource['repositoryName'], 'State': 'PolicyRemoved', 'Statements': found}
