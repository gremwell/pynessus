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


class NessusObject(object):

    def __init__(self, server):
        self._id = None
        self._permissions = None
        self._server = server

    def request(self, method, path, params):
        return self._server._api_request(method, path, params)

    def save(self):
        if self._id is None:
            return getattr(self, "create")()
        else:
            return getattr(self, "edit")()

    def delete(self):
        if self._id is not None:
            return getattr(self._server, "delete_%s" % self.__class__.__name__.lower())(self)

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, _id):
        self._id = _id

    @property
    def permissions(self):
        return self._permissions

    @permissions.setter
    def permissions(self, value):
        self._permissions = value