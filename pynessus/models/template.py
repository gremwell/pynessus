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

class Template(NessusObject):
    """
    A Nessus Scan Template instance.

    Attributes:

    _Google Python Style Guide:
    http://google-styleguide.googlecode.com/svn/trunk/pyguide.html
    """

    def __init__(self, server):
        """Constructor"""
        super(Template, self).__init__(server)
        self._description = None
        self._title = None
        self._name = None
        self._more_info = None
        self._subscription_only = False
        self._uuid = None
        self._cloud_only = False

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, value):
        self._title = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def more_info(self):
        return self._more_info

    @more_info.setter
    def more_info(self, value):
        self._more_info = value

    @property
    def subscription_only(self):
        return self._more_info

    @subscription_only.setter
    def subscription_only(self, value):
        self._subscription_only = value

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, value):
        self._uuid = value

    @property
    def cloud_only(self):
        return self._cloud_only

    @cloud_only.setter
    def cloud_only(self, value):
        self._cloud_only = value