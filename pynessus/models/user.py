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


class User(NessusObject):
    """
    A Nessus User instance.

    Attributes:

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, server, username=None, password=None):
        """
        Constructor
        Params:
            username(string): username
            password(string): password
        """
        super(User, self).__init__(server)
        self._name = None
        self._username = username
        self._password = password
        self._usertype = None
        self._admin = False
        self._token = None
        self._last_login = 0
        self._permissions = 32
        self._type = "local"

    def create(self):
        """
        Create a user.
        Params:
        Returns:
        """
        params = {
            "username": self.username,
            "permissions": self.permissions,
            "type": self.type,
            "password": self.password
        }
        response = self._server._api_request("POST", "/users", params)
        if response is not None:
            self.name = response["name"]
            self.permissions = response["permissions"]
            self.id = response["id"]
            return True
        else:
            return False

    def edit(self):
        """
        Edit a user.
        Params:
        Returns:
        """
        params = {
            "username": self.username,
            "permissions": self.permissions,
            "type": self.type,
            "password": self.password
        }
        response = self._server._api_request("PUT", "/users/%d" % self.id, params)
        if response is not None:
            self.name = response["name"]
            self.permissions = response["permissions"]
            self.id = response["id"]
            return True
        else:
            return False

    def delete(self):
        """
        Delete a user.
        Params:
        Returns:
        """
        response = self._server._api_request("DELETE", "/users/%d" % self.id, "")
        if response is None:
            return True
        else:
            return False

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, username):
        self._username = username

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        #TODO: implement the change password call
        self._password = password

    @property
    def admin(self):
        return self._admin

    @admin.setter
    def admin(self, admin):
        self._admin = admin

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, token):
        self._token = token

    @property
    def last_login(self):
        return self._last_login

    @last_login.setter
    def last_login(self, last_login):
        self._last_login = last_login

    @property
    def permissions(self):
        return self._permissions

    @permissions.setter
    def permissions(self, permissions):
        self._permissions = permissions

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, _type):
        self._type = _type