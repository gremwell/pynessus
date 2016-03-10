
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


class Session(NessusObject):
    """
    A Nessus Folder instance.

    Attributes:

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, server):
        """Constructor"""
        super(Session, self).__init__(server)
        self._id = None
        self._username = None
        self._email = None
        self._name = None
        self._type = None
        self._permissions = 0
        self._lastlogin = 0
        self._container_id = 0
        self._groups = []

    def create(self, user):
        params = {
            "username" : user.username,
            "password" : user.password
        }
        response = self._server._api_request("POST", "/session", params)
        if response is not None:
            self._server.headers["X-Cookie: token=%s" % (response["token"])]
            return True
        else:
            return False

    def edit(self):
        params = {
            "name": self.name,
            "email": self.email
        }
        return True if self._server._api_request("PUT", "/session", params) is None else False

    def get(self):
        response = self._server._api_request("GET", "/session", "")
        if response is not None:
            self.id = response["id"]
            self.username = response["username"]
            self.email = response["email"]
            self.name = response["name"]
            self.type = response["type"]
            self.permissions = response["permissions"]
            self.lastlogin = response["lastlogin"]
            self.container_id = response["container_id"]
            self.groups = response["groups"]

    def destroy(self):
        return True if self._server._api_request("DELETE", "/session", "") is None else False

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = str(value)

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        self._username = str(value)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = str(value)

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value):
        self._email = str(value)

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

    @property
    def lastlogin(self):
        return self._lastlogin

    @lastlogin.setter
    def lastlogin(self, value):
        self._lastlogin = int(value)

    @property
    def container_id(self):
        return self._container_id

    @container_id.setter
    def container_id(self, value):
        self._container_id = int(value)

    @property
    def groups(self):
        return self._groups

    @groups.setter
    def groups(self, value):
        self._groups = value