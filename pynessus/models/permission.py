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


class Permission(NessusObject):
    """
    A Nessus permission.

    Attributes:
        id(int): identification
        name(str) :
        owner(int):
        type(str):
        permissions(int):

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, server):
        """Constructor"""
        super(Permission, self).__init__(server)
        self._owner = None
        self._type = None
        self._permissions = None
        self._id = None
        self._name = None

    def load(self, object_type, object_id):
        """

        :return:
        """
        if self._server.server_version[0] == "6":
            response = self._server._api_request("GET", "/permissions/%s/%d" % (object_type, object_id))
            if response is not None:
                self._id = response["id"]
                self._name = response["name"]
                self._owner = response["owner"]
                self._type = response["type"]
                self._permissions = response["permissions"]
                return True
        else:
            raise Exception("Agents are not supported by Nessus version < 6.x .")

    def update(self, object_type, object_id):
        """

        :return:
        """
        if self._server.server_version[0] == "6":
            response = self._server._api_request(
                "PUT",
                "/permissions/%s/%d" % (object_type, object_id),
                str(self._permissions)
            )
            if response is None:
                return True
        else:
            raise Exception("Agents are not supported by Nessus version < 6.x .")

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
    def owner(self):
        return self._owner

    @owner.setter
    def owner(self, value):
        self._owner = int(value)

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = str(value)

    @property
    def permissions(self):
        return self._permissions

    @permissions.setter
    def permissions(self, value):
        self._permissions = int(value)