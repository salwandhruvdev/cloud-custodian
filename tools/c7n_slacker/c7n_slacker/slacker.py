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

"""
Thoughts:
 - Token as part of schema, encrypted token
 - Purpose of this file
  - Create an interface to create a Slack Client(This can be done in __init__)
  - Retrieve per user IM slack details details on the basis of LDAP lookup
  - Send message to the User's IM

"""


from slackclient import SlackClient


class SlackBot(object):

    def __init__(self, token):
        self.client = SlackClient(token)

    def retrieve_user_im(self, user_email):
        response = self.client.api_call(
                    "users.lookupByEmail", email=user_email)
        return response

    def send_slack_msg(self, channel):
        response = self.client.api_call(
            "chat.postMessage", channel=channel, text="Hello from Python! :tada:")
        return response

