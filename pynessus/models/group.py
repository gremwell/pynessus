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
from user import User


class Group(NessusObject):
    """
    A Nessus group.

    Attributes:
        id(int): identification
        name(str): group's name
    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, server):
        """Constructor"""
        super(Group, self).__init__(server)
        self._name = None
        self._users = None

    @staticmethod
    def list():
        """
        Returns the group list.
        Params:
        Returns:
        """
        return

    def create(self):
        """
        Create a group.
        Params:
        Returns:
        """
        return

    def edit(self):
        """
        Edit a group
        Params:
        Returns:
        """
        return

    def delete(self):
        """
        Delete a group.
        Params:
        Returns:
        """
        return

    def add_user(self, user):
        if type(user) is User:
            return
        else:
            raise Exception("Invalid user format.")

    def delete_user(self, user):
        if type(user) is User:
            return
        else:
            raise Exception("Invalid user format.")

    @property
    def users(self):
        """
        Return the group user list.
        Params:
        Returns:
        """
        return self._users

    @users.setter
    def users(self, value):
        if type(value) == list:
            self._users = value
        else:
            raise Exception("Invalid format.")