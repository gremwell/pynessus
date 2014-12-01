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


class Plugin(NessusObject):
    """
    A Nessus Plugin.

    Attributes:
        name(string): plugin's name
        family_name(string): plugin's family name
        attributes(array): plugin's attributes
    """

    def __init__(self, server):
        """Constructor"""
        super(Plugin, self).__init__(server)
        self._name = None
        self._family_name = None
        self._attributes = []

    def details(self):
        """
        Returns the details for a given plugin.
        Params:
        Returns:
        """
        return

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = str(value)

    @property
    def family_name(self):
        return self._family_name

    @family_name.setter
    def family_name(self, value):
        self._family_name = str(value)

    @property
    def attributes(self):
        return self._attributes

    @attributes.setter
    def attributes(self, value):
        if type(value) == list:
            self._attributes = value
        else:
            raise Exception("Invalid format.")


class PluginFamily(NessusObject):
    """
    A Nessus Plugin Family.

    Attributes:
        name(string): plugin's name
        family_name(string): plugin's family name
        attributes(array): plugin's attributes
    """

    def __init__(self, server):
        """Constructor"""
        super(PluginFamily, self).__init__(server)
        self._id = -1
        self._name = None
        self._plugin_count = 0
        self._status = "enabled"
        self._plugins = []

    @staticmethod
    def list():
        """
        Return plugin family list.
        Params:
        Returns:
        """
        return

    def details(self):
        """
        Returns the list of plugins in a family.
        Params:
        Returns:
        """
        return

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
    def plugin_count(self):
        return self._plugin_count

    @plugin_count.setter
    def plugin_count(self, value):
        self._plugin_count = int(value)

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = str(value)

    @property
    def plugins(self):
        return self._plugins

    @plugins.setter
    def plugins(self, value):
        if type(value) == list:
            self._plugins = value
        else:
            raise Exception("Invalid format.")