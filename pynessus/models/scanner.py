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

class Scanner(NessusObject):
    """
    A Nessus Scan Template instance.

    Attributes:

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, server):
        """Constructor"""
        super(Scanner, self).__init__(server)
        self._id = None
        self._uuid = None
        self._name = None
        self._type = None
        self._status = None
        self._scan_count = 0
        self._engine_version = None
        self._platform = None
        self._loaded_plugin_set = None
        self._registration_code = None
        self._owner = None

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = int(value)

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, value):
        self._uuid = str(value)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = str(value)

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = str(value)

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = str(value)

    @property
    def scan_count(self):
        return self._scan_count

    @scan_count.setter
    def scan_count(self, value):
        self._scan_count = int(value)

    @property
    def engine_version(self):
        return self._engine_version

    @engine_version.setter
    def engine_version(self, value):
        self._engine_version = str(value)

    @property
    def platform(self):
        return self._platform

    @platform.setter
    def platform(self, value):
        self._platform = str(value)

    @property
    def loaded_plugin_set(self):
        return self._loaded_plugin_set

    @loaded_plugin_set.setter
    def loaded_plugin_set(self, value):
        self._loaded_plugin_set = str(value)

    @property
    def registration_code(self):
        return self._registration_code

    @registration_code.setter
    def registration_code(self, value):
        self._registration_code = str(value)

    @property
    def owner(self):
        return self._owner

    @owner.setter
    def owner(self, value):
        self._owner = str(value)