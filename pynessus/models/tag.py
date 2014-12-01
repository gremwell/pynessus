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

class Tag(NessusObject):
    """
    A Nessus Tag instance.

    Attributes:

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, server):
        """Constructor"""
        super(Tag, self).__init__(server)
        self._default_tag = 1
        self._type = None
        self._name = None
        self._custom = False
        self._unread_count = 0

    def create(self):
        """
        Create a tag.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                "name": self.name
            }
            response = self._server._api_request("POST", "/tag/create", params)
            if response is not None:
                self.id = response["id"]
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            params = {
                "name": self.name
            }
            response = self._server._api_request("POST", "/folders", params)
            if response is not None:
                self.id = response["id"]
                return True
            else:
                return False
        else:
            return False

    def edit(self):
        """
        Edit a tag.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                "tag_id": self.id,
                "name": self.name
            }
            response = self._server._api_request("POST", "/tag/edit", params)
            if response is not None:
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            params = {
                "name": self.name
            }
            response = self._server._api_request("PUT", "/folders/%d" % self.id, params)
            if response is None:
                return True
            else:
                return False
        else:
            return False

    def delete(self):
        """
        Delete a tag.
        Params:
        Returns:
        """
        if self._server.server_version[0] == "5":
            params = {
                "tag_id": self.id
            }
            response = self._server._api_request("POST", "/tag/delete", params)
            if response is not None:
                return True
            else:
                return False
        elif self._server.server_version[0] == "6":
            response = self._server._api_request("DELETE", "/folders/%d" % self.id, "")
            if response is None:
                return True
            else:
                return False
        else:
            return False

    @property
    def default_tag(self):
        return self._default_tag

    @default_tag.setter
    def default_tag(self, default_tag):
        self._default_tag = default_tag

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, _type):
        self._type = _type

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def custom(self):
        return self._custom

    @custom.setter
    def custom(self, custom):
        self._custom = custom

    @property
    def unread_count(self):
        return self._unread_count

    @unread_count.setter
    def unread_count(self, unread_count):
        self._unread_count = unread_count
