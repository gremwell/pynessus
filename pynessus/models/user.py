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


class User(object):
    """
    A Nessus User instance.

    Attributes:

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, username=None, password=None):
        """
        Constructor
        Params:
            username(string): username
            password(string): password
        """
        self._id = -1
        self._name = None
        self._username = username
        self._password = password
        self._usertype = None
        self._admin = False
        self._token = None
        self._last_login = 0
        self._permissions = 32
        self._type = "local"

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, _id):
        self._id = _id

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