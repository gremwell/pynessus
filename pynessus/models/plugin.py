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

    def load_details(self):
        """
        Returns the details for a given plugin.
        Params:
        Returns:
        """
        response = self._server._api_request("GET", "/plugins/plugin/%d" % self.id, "")
        if response is not None:
            self.id = response["id"]
            self.name = response["name"]
            self.family_name = response["family_name"]
            self.attributes = response["attributes"]
        return True

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
        if type(value) == list or value is None:
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

    def load_plugins(self):
        """

        :return:
        """
        response = self._server._api_request("GET", "/plugins/families/%d" % self.id, "")
        if "plugins" in response and response["plugins"] is not None:
            for plugin in response["plugins"]:
                p = self._server.Plugin()
                p.id = plugin["id"]
                p.name = plugin["name"]
                p.load_details()
                self._plugins.append(p)
        return True

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
        if type(value) == list or value is None:
            self._plugins = value
        else:
            raise Exception("Invalid format.")


def enum(**enums):
    return type('Enum', (), enums)


class Severity:
    """

    """
    RECAST_CRITICAL = "recast_critical"
    RECAST_HIGH = "recast_high"
    RECAST_MEDIUM = "recast_medium"
    RECAST_LOW = "recast_low"
    RECAST_INFO = "recast_info"
    EXCLUDE = "exclude"


class PluginRule(NessusObject):
    """
    A Nessus Plugin Rule.

    Attributes:
        id(int):
        plugin_id(int):
        date(str):
        host(str):
        type(str):
        owner(str):
        owner_id(int):
    """

    def __init__(self, server):
        """Constructor"""
        super(PluginRule, self).__init__(server)
        self._id = -1
        self._plugin_id = -1
        self._date = None
        self._host = None
        self._type = None
        self._owner = None
        self._owner_id = -1

    def create(self):
        """

        :return:
        """
        response = self._server._api_request(
            "POST",
            "/plugin-rules",
            {
                "plugin_id": self.plugin_id,
                "type": self.type,
                "host": self.host,
                "date": self.date
            }
        )
        return True if response is None else False

    def edit(self):
        """

        :return:
        """
        response = self._server._api_request(
            "PUT",
            "/plugin-rules/%d" % self.id,
            {
                "plugin_id": self.plugin_id,
                "type": self.type,
                "host": self.host,
                "date": self.date
            }
        )
        return True if response is None else False

    def delete(self):
        """

        :return:
        """
        response = self._server._api_request(
            "DELETE",
            "/plugin-rules/%d" % self.id,
            ""
        )
        return True if response is None else False

    def details(self):
        """

        :return:
        """
        response = self._server._api_request(
            "GET",
            "/plugin-rules/%d" % self.id,
            ""
        )
        if response is not None:
            self.id = response["id"]
            self.plugin_id = response["plugin_id"]
            self.date = response["date"]
            self.host = response["host"]
            self.type = response["type"]
            self.owner = response["owner"]
            self.owner_id = response["owner_id"]
            return True
        else:
            return False

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        if type(value) in [int] or value is None:
            self._id = value
        else:
            raise Exception("")

    @property
    def plugin_id(self):
        return self._plugin_id

    @plugin_id.setter
    def plugin_id(self, value):
        if type(value) in [int] or value is None:
            self._plugin_id = value
        else:
            raise Exception("")

    @property
    def date(self):
        return self._date

    @date.setter
    def date(self, value):
        if type(value) in [str, unicode] or value is None:
            self._date = value
        else:
            raise Exception("")

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, value):
        if type(value) in [str, unicode] or value is None:
            self._host = value
        else:
            raise Exception("")

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if type(value) in [str, unicode] or value is None:
            self._type = value
        else:
            raise Exception("")

    @property
    def owner(self):
        return self._owner

    @owner.setter
    def owner(self, value):
        if type(value) in [str, unicode] or value is None:
            self._owner = value
        else:
            raise Exception("")

    @property
    def owner_id(self):
        return self._owner_id

    @owner_id.setter
    def owner_id(self, value):
        if type(value) in [int] or value is None:
            self._owner_id = value
        else:
            raise Exception("")