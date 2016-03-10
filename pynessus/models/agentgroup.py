"""
Copyright 2014 Quentin Kaiser

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from nessusobject import NessusObject


class AgentGroup(NessusObject):
    """
    A Nessus scanning agent group.

    Attributes:
        id(int): identification
        name(str): agent group's name
        owner_id(str):
        owner(str):
        shared(int):
        user_permissions(int):
        creation_date(int):
        last_modification_date(int):

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, server):
        """Constructor"""
        super(AgentGroup, self).__init__(server)
        self._id = None
        self._name = None
        self._owner_id = None
        self._owner = None
        self._shared = None
        self._user_permissions = None
        self._creation_date = None
        self._last_modification_date = None
        self._scanner_id = None

    def add_agent(self, agent_id):
        response = self._server._api_request(
            "PUT",
            "/scanners/%d/agent-groups/%d/agents/%d" % (self._scanner_id, self.id, agent_id),
            ""
        )
        if response is None:
            return True
        else:
            return False

    def create(self):
        response = self._server._api_request(
            "POST",
            "/scanners/%d/agent-groups" % self.scanner_id,
            {"name": self.name}
        )
        if response is not None:
            self._id = response["id"]
            return True
        else:
            return False


    def update(self):
        response = self._server._api_request(
            "PUT",
            "/scanners/%d/agent-groups/%d" % (self._scanner_id, self.id),
            {"name": self.name}
        )
        if response is None:
            return True
        else:
            return False

    def delete(self):
        response = self._server._api_request(
            "DELETE",
            "/scanners/%d/agent-groups/%d" % (self.scanner_id, self.id),
            ""
        )
        if response is None:
            return True
        else:
            return False


    def remove_agent(self, agent_id):
        response = self._server._api_request(
            "DELETE",
            "/scanners/%d/agent-groups/%d/agents/%d" % (self.scanner_id, self.id, agent_id),
            ""
        )
        if response is None:
            return True
        else:
            return False

    def details(self):
        response = self._server._api_request(
            "GET",
            "/scanners/%d/agent-groups/%d" % (self.scanner_id, self.id),
            ""
        )
        if response is not None:
            self._id = response["id"]
            self._name = response["name"]
            self._owner_id = response["owner_id"]
            self._owner = response["owner"]
            self._shared = response["shared"]
            self._user_permissions = response["user_permissions"]
            self._creation_date = response["creation_date"]
            self._creation_date = response["last_modification_date"]
            return True
        else:
            return False

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = int(value)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = str(value)

    @property
    def owner_id(self):
        return self._owner_id

    @owner_id.setter
    def owner_id(self, value):
        self._owner_id = str(value)

    @property
    def owner(self):
        return self._owner

    @owner.setter
    def owner(self, value):
        self._owner = str(value)

    @property
    def shared(self):
        return self._shared

    @shared.setter
    def shared(self, value):
        self._shared = int(value)

    @property
    def user_permissions(self):
        return self._user_permissions

    @user_permissions.setter
    def user_permissions(self, value):
        self._user_permissions = int(value)

    @property
    def creation_date(self):
        return self._creation_date

    @creation_date.setter
    def creation_date(self, value):
        self._creation_date = int(value)

    @property
    def last_modification_date(self):
        return self._last_modification_date

    @last_modification_date.setter
    def last_modification_date(self, value):
        self._last_modification_date = int(value)

    @property
    def scanner_id(self):
        return self._scanner_id

    @scanner_id.setter
    def scanner_id(self, value):
        self._scanner_id = int(value)

