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

from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPSocketOpenError

import base64
from botocore.exceptions import ClientError

class LdapLookup():

    def __init__(self, config, session, logger):
        self.config      = config
        self.session     = session
        self.log         = logger
        self.connection = self.get_ldap_session(
            config.get('ldap_uri'),
            config.get('ldap_bind_user', None)
        )
        self.base_dn   = config.get('ldap_bind_dn')
        self.email_key = config.get('ldap_email_key', 'mail')
        self.uid_key   = config.get('ldap_uid_attribute_name', 'sAMAccountName')
        self.manager_attr = config.get('ldap_manager_attribute', 'manager')
<<<<<<< HEAD
        self.uid       = 'ijm065' # read from SQS
        self.attributes = ['displayName', self.uid_key, self.email_key, self.manager_attr]

=======
        self.attributes = ['displayName', self.uid_key, self.email_key, self.manager_attr]


>>>>>>> 1a0882f83492eb2ae14957e80f2494a5345f6625
    def search_ldap(self,):
        ldap_filter = '(%s=%s)' % (self.uid_key, self.uid)
        self.log.debug('Initiating LDAP search...')
        self.connection.search(self.base_dn, ldap_filter, attributes=self.attributes)
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
            server = Server(ldap_uri, use_ssl=True)
            return Connection(
                server, user=ldap_bind_user, password=ldap_bind_password,
                auto_bind=True,
                receive_timeout=30,
                auto_referrals=False,
            )
        except LDAPSocketOpenError:
<<<<<<< HEAD
            self.log.error('Not able to establish a connection with LDAP.')
=======
            self.log.error('Not able to establish a connection with LDAP.')
>>>>>>> 1a0882f83492eb2ae14957e80f2494a5345f6625
